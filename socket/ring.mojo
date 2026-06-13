# The completion engine: a safe operation table over UringQueue.
#
# Lifetime rule (learned the hard way — see .probe/SYNTAX.md): every
# byte of memory the kernel can read or write for an in-flight
# operation is OWNED BY THE OPERATION'S SLOT until its completion is
# reaped. Callers hand buffers in (send) and take buffers out (recv
# completions); they never share memory with the kernel. Mojo's ASAP
# destruction therefore cannot free anything the kernel still sees.
#
# user_data packing: slot index (32 bits) | generation (16) | kind (8).
# Generations make completions of recycled slots detectable; the
# engine raises on a stale generation instead of misrouting it.
#
# Usage shape (M0, single-shot ops):
#   var ring = Ring(256)
#   var op = ring.recv(fd, 4096)
#   _ = ring.wait(min_complete=1)
#   while True:
#       var c = ring.next_completion()
#       if not c: break
#       var done = c.value()
#       if done.kind == KIND_RECV and done.op == op: ... done.take_buffer()

from std.memory import UnsafePointer, memcpy

from socket._libc import (
    SOCKADDR_STORAGE_SIZE,
    errno_message,
    write_sockaddr,
    read_sockaddr,
)
from socket.addr import IpAddress, SocketAddr
from socket.bufring import BufRing
from socket.uring_sys import (
    ACCEPT_MULTISHOT,
    CQE_BUFFER_SHIFT,
    CQE_F_BUFFER,
    CQE_F_MORE,
    IOSQE_BUFFER_SELECT,
    IOSQE_IO_LINK,
    OP_ACCEPT,
    OP_ASYNC_CANCEL,
    OP_CLOSE,
    OP_CONNECT,
    OP_LINK_TIMEOUT,
    OP_NOP,
    OP_RECV,
    OP_SEND,
    OP_SHUTDOWN,
    OP_TIMEOUT,
    RECV_MULTISHOT,
    UringQueue,
)

comptime KIND_NOP = UInt8(0)
comptime KIND_ACCEPT = UInt8(1)
comptime KIND_CONNECT = UInt8(2)
comptime KIND_RECV = UInt8(3)
comptime KIND_SEND = UInt8(4)
comptime KIND_CLOSE = UInt8(5)
comptime KIND_SHUTDOWN = UInt8(6)
comptime KIND_ACCEPT_MULTI = UInt8(7)
comptime KIND_RECV_MULTI = UInt8(8)
comptime KIND_TIMEOUT = UInt8(9)
comptime KIND_CANCEL = UInt8(10)


@always_inline
def _kind_name(kind: UInt8) -> String:
    if kind == KIND_ACCEPT:
        return "accept"
    if kind == KIND_CONNECT:
        return "connect"
    if kind == KIND_RECV:
        return "recv"
    if kind == KIND_SEND:
        return "send"
    if kind == KIND_CLOSE:
        return "close"
    if kind == KIND_SHUTDOWN:
        return "shutdown"
    if kind == KIND_ACCEPT_MULTI:
        return "accept-multishot"
    if kind == KIND_RECV_MULTI:
        return "recv-multishot"
    if kind == KIND_TIMEOUT:
        return "timeout"
    if kind == KIND_CANCEL:
        return "cancel"
    return "nop"


struct OpId(Copyable, ImplicitlyCopyable, Movable):
    """Opaque handle for one submitted operation."""

    var raw: UInt64

    def __init__(out self, raw: UInt64):
        self.raw = raw

    def __eq__(self, other: OpId) -> Bool:
        return self.raw == other.raw

    def __ne__(self, other: OpId) -> Bool:
        return self.raw != other.raw


struct _OpSlot(Movable):
    # Generation of the CURRENT (or next) occupant; bumped on free.
    var gen: UInt16
    var kind: UInt8
    var active: Bool
    var fd: Int32
    # All kernel-visible memory for this op. For send: the payload.
    # For recv: the target buffer. For connect/accept: sockaddr storage
    # (accept also stores the 4-byte addrlen immediately after it).
    var buf: List[UInt8]

    def __init__(out self):
        self.gen = 0
        self.kind = KIND_NOP
        self.active = False
        self.fd = -1
        self.buf = List[UInt8]()


struct Completion(Movable):
    """One finished operation. `res` is the raw kernel result
    (negative errno on failure); `ok()` raises a mapped error.
    For recv/send the buffer is recovered with take_buffer()."""

    var op: OpId
    var kind: UInt8
    var fd: Int32  # the fd the op was submitted against
    var res: Int32
    var buf: List[UInt8]
    # multishot extras: kernel-picked buffer id (or -1) and whether
    # this op stays armed and will produce further completions
    var bid: Int
    var more: Bool

    def __init__(
        out self,
        op: OpId,
        kind: UInt8,
        fd: Int32,
        res: Int32,
        var buf: List[UInt8],
        bid: Int = -1,
        more: Bool = False,
    ):
        self.op = op
        self.kind = kind
        self.fd = fd
        self.res = res
        self.buf = buf^
        self.bid = bid
        self.more = more

    def ok(self) raises:
        if self.res < 0:
            raise Error(
                "socket.ring: "
                + _kind_name(self.kind)
                + " failed: "
                + errno_message(Int32(-self.res))
            )

    def take_buffer(mut self) -> List[UInt8]:
        """Moves the op's buffer out. For recv, the valid prefix is
        `res` bytes (the engine has already truncated it)."""
        var out = self.buf^
        self.buf = List[UInt8]()
        return out^

    def accepted_peer(self) raises -> SocketAddr:
        """For accept completions: the peer's address."""
        if self.kind != KIND_ACCEPT or len(self.buf) < SOCKADDR_STORAGE_SIZE:
            raise Error("socket.ring: not an accept completion")
        var parsed = read_sockaddr(self.buf.unsafe_ptr())
        var ip = IpAddress(parsed[0], parsed[1])
        return SocketAddr(ip, parsed[2])


struct Ring(Movable):
    """One io_uring engine: submit socket operations, reap typed
    completions. Single-threaded; create one Ring per thread."""

    var q: UringQueue
    var slots: List[_OpSlot]
    var free: List[UInt32]
    # Count of submitted-but-not-yet-reaped ops. An invariant/debug counter
    # (tests assert it returns to 0 on graceful drain); no control flow
    # depends on it.
    var inflight: Int
    var bufs: Optional[BufRing]

    def __init__(out self, entries: Int = 256) raises:
        self.q = UringQueue(entries)
        self.slots = List[_OpSlot]()
        self.free = List[UInt32]()
        self.inflight = 0
        self.bufs = None

    def setup_buffers(
        mut self, *, entries: Int = 256, buf_size: Int = 16384, bgid: UInt16 = 0
    ) raises:
        """Registers the provided-buffer pool multishot recv draws
        from. 16 KiB default matches the TLS record ceiling."""
        self.bufs = BufRing(self.q.fd, bgid, entries, buf_size)

    def buffer_view(
        mut self, bid: Int, length: Int
    ) raises -> Span[UInt8, MutAnyOrigin]:
        """Borrowed bytes of a multishot-recv completion's buffer.
        Valid until recycle_buffer(bid)."""
        if not self.bufs:
            raise Error("socket.ring: no buffer pool registered")
        # bid/length come straight from the kernel CQE; fail fast rather
        # than form an out-of-bounds Span if anything ever desyncs.
        if (
            bid < 0
            or bid >= self.bufs.value().entries
            or length < 0
            or length > self.bufs.value().buf_size
        ):
            raise Error("socket.ring: buffer_view bid/length out of range")
        var p: UnsafePointer[UInt8, MutAnyOrigin] = (
            self.bufs.value().backing.unsafe_ptr()
            + bid * self.bufs.value().buf_size
        )
        return Span(ptr=p, length=length)

    def recycle_buffer(mut self, bid: Int) raises:
        if not self.bufs:
            raise Error("socket.ring: no buffer pool registered")
        if bid < 0 or bid >= self.bufs.value().entries:
            raise Error("socket.ring: recycle_buffer bid out of range")
        self.bufs[].recycle(bid)

    # --- slot management --------------------------------------------------

    def _alloc(mut self, kind: UInt8, fd: Int32, var buf: List[UInt8]) -> Int:
        var idx: Int
        if len(self.free) > 0:
            idx = Int(self.free.pop())
        else:
            self.slots.append(_OpSlot())
            idx = len(self.slots) - 1
        self.slots[idx].kind = kind
        self.slots[idx].active = True
        self.slots[idx].fd = fd
        self.slots[idx].buf = buf^
        return idx

    @always_inline
    def _user_data(self, idx: Int, kind: UInt8) -> UInt64:
        return (
            UInt64(idx)
            | (UInt64(self.slots[idx].gen) << 32)
            | (UInt64(kind) << 48)
        )

    def _room(mut self) raises:
        # transparently flush a full SQ so callers can queue freely
        if self.q.sq_space() == 0:
            _ = self.q.enter(0)

    # --- operations ---------------------------------------------------------

    def nop(mut self) raises -> OpId:
        self._room()
        var idx = self._alloc(KIND_NOP, -1, List[UInt8]())
        var ud = self._user_data(idx, KIND_NOP)
        self.q.push_sqe(OP_NOP, -1, 0, 0, 0, 0, ud)
        self.inflight += 1
        return OpId(ud)

    def accept(mut self, listen_fd: Int32) raises -> OpId:
        """Queues one accept. The peer sockaddr lands in slot-owned
        storage and is read from the completion."""
        self._room()
        # sockaddr storage + 4-byte addrlen, both kernel-written
        var st = List[UInt8](length=SOCKADDR_STORAGE_SIZE + 4, fill=0)
        st[SOCKADDR_STORAGE_SIZE] = UInt8(SOCKADDR_STORAGE_SIZE)
        var addr_ptr = UInt64(Int(st.unsafe_ptr()))
        var len_ptr = UInt64(Int(st.unsafe_ptr() + SOCKADDR_STORAGE_SIZE))
        var idx = self._alloc(KIND_ACCEPT, listen_fd, st^)
        var ud = self._user_data(idx, KIND_ACCEPT)
        self.q.push_sqe(OP_ACCEPT, listen_fd, addr_ptr, 0, len_ptr, 0, ud)
        self.inflight += 1
        return OpId(ud)

    def connect(mut self, fd: Int32, addr: SocketAddr) raises -> OpId:
        self._room()
        var st = List[UInt8](length=SOCKADDR_STORAGE_SIZE, fill=0)
        var alen = write_sockaddr(
            st.unsafe_ptr(), addr.ip.is_v6, addr.ip.octets, addr.port
        )
        var addr_ptr = UInt64(Int(st.unsafe_ptr()))
        var idx = self._alloc(KIND_CONNECT, fd, st^)
        var ud = self._user_data(idx, KIND_CONNECT)
        self.q.push_sqe(OP_CONNECT, fd, addr_ptr, 0, UInt64(alen), 0, ud)
        self.inflight += 1
        return OpId(ud)

    def recv(mut self, fd: Int32, max_bytes: Int) raises -> OpId:
        self._room()
        # Uninitialized: the kernel fills it; a zero-fill would be thrown
        # away on the next syscall.
        var buf = List[UInt8](capacity=max_bytes)
        buf.resize(unsafe_uninit_length=max_bytes)
        var ptr = UInt64(Int(buf.unsafe_ptr()))
        var idx = self._alloc(KIND_RECV, fd, buf^)
        var ud = self._user_data(idx, KIND_RECV)
        self.q.push_sqe(OP_RECV, fd, ptr, UInt32(max_bytes), 0, 0, ud)
        self.inflight += 1
        return OpId(ud)

    def send(mut self, fd: Int32, var data: List[UInt8]) raises -> OpId:
        """Takes ownership of `data` until the completion is reaped."""
        self._room()
        var ptr = UInt64(Int(data.unsafe_ptr()))
        var n = len(data)
        var idx = self._alloc(KIND_SEND, fd, data^)
        var ud = self._user_data(idx, KIND_SEND)
        # MSG_NOSIGNAL: a dead peer must surface as -EPIPE, not SIGPIPE
        self.q.push_sqe(OP_SEND, fd, ptr, UInt32(n), 0, UInt32(0x4000), ud)
        self.inflight += 1
        return OpId(ud)

    def send_copy(mut self, fd: Int32, data: Span[UInt8, _]) raises -> OpId:
        var owned = List[UInt8](capacity=len(data))
        owned.extend(data)
        return self.send(fd, owned^)

    def close_fd(mut self, fd: Int32) raises -> OpId:
        self._room()
        var idx = self._alloc(KIND_CLOSE, fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_CLOSE)
        self.q.push_sqe(OP_CLOSE, fd, 0, 0, 0, 0, ud)
        self.inflight += 1
        return OpId(ud)

    def shutdown(mut self, fd: Int32, how: Int32) raises -> OpId:
        self._room()
        var idx = self._alloc(KIND_SHUTDOWN, fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_SHUTDOWN)
        self.q.push_sqe(OP_SHUTDOWN, fd, 0, UInt32(how), 0, 0, ud)
        self.inflight += 1
        return OpId(ud)

    def accept_multishot(mut self, listen_fd: Int32) raises -> OpId:
        """One armed SQE that produces a completion per incoming
        connection until it terminates (completion with more=False).
        Peer addresses are not collected on this path — fetch them via
        getpeername if a protocol needs them."""
        self._room()
        var idx = self._alloc(KIND_ACCEPT_MULTI, listen_fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_ACCEPT_MULTI)
        self.q.push_sqe(
            OP_ACCEPT, listen_fd, 0, 0, 0, 0, ud, ioprio=ACCEPT_MULTISHOT
        )
        self.inflight += 1
        return OpId(ud)

    def recv_multishot(mut self, fd: Int32) raises -> OpId:
        """One armed SQE that produces a buffer-carrying completion per
        arriving chunk, drawing from the registered pool. ANY completion
        with bid >= 0 — INCLUDING the terminal one (more == False) — owns
        a pool buffer: read it with buffer_view(bid, res) and you MUST
        recycle_buffer(bid) afterwards. A multishot can terminate WHILE
        committing a buffer (res > 0, more == False) when the pool drains
        or the CQ overflows; skipping recycle there leaks that buffer and
        starves the pool toward -ENOBUFS. res == 0 means peer EOF (no
        buffer, bid == -1); -ENOBUFS means the pool starved."""
        if not self.bufs:
            raise Error("socket.ring: setup_buffers() first")
        self._room()
        var idx = self._alloc(KIND_RECV_MULTI, fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_RECV_MULTI)
        self.q.push_sqe(
            OP_RECV,
            fd,
            0,
            0,
            0,
            0,
            ud,
            sqe_flags=IOSQE_BUFFER_SELECT,
            ioprio=RECV_MULTISHOT,
            buf_group=self.bufs.value().bgid,
        )
        self.inflight += 1
        return OpId(ud)

    def timeout(mut self, nanoseconds: Int64) raises -> OpId:
        """A standalone timer: completes with res == -ETIME (-62) when
        it fires, -ECANCELED if cancelled."""
        self._room()
        # __kernel_timespec { i64 sec, i64 nsec } — slot-owned
        var ts = List[UInt8](length=16, fill=0)
        ts.unsafe_ptr().bitcast[Int64]()[0] = nanoseconds // 1_000_000_000
        (ts.unsafe_ptr() + 8).bitcast[Int64]()[0] = nanoseconds % 1_000_000_000
        var ptr = UInt64(Int(ts.unsafe_ptr()))
        var idx = self._alloc(KIND_TIMEOUT, -1, ts^)
        var ud = self._user_data(idx, KIND_TIMEOUT)
        self.q.push_sqe(OP_TIMEOUT, -1, ptr, 1, 0, 0, ud)
        self.inflight += 1
        return OpId(ud)

    def recv_with_timeout(
        mut self, fd: Int32, max_bytes: Int, nanoseconds: Int64
    ) raises -> OpId:
        """Recv bounded by a linked deadline: the recv fails with
        -ECANCELED if no data arrives in time.

        NOTE: this queues TWO operations and posts TWO completions — the
        recv (KIND_RECV: bytes, or -ECANCELED on the deadline) AND its
        linked timeout (KIND_TIMEOUT: -ETIME if it fired, -ECANCELED if
        the recv finished first). Callers MUST reap BOTH completions to
        release both slots and bring inflight back down by 2; reaping
        only the returned KIND_RECV OpId leaks one slot and one inflight
        count."""
        self._room()
        if self.q.sq_space() < 2:
            _ = self.q.enter(0)
        # Data region [0, max_bytes) is kernel-written; the trailing
        # 16-byte timespec is written explicitly below — so allocate
        # uninitialized (no wasted zero-fill).
        var buf = List[UInt8](capacity=max_bytes + 16)
        buf.resize(unsafe_uninit_length=max_bytes + 16)
        # timespec rides in the same slot allocation, after the data
        # (the kernel copies it at prep time, so submit-lifetime is
        # enough — slot ownership gives us completion-lifetime anyway)
        var data_ptr = UInt64(Int(buf.unsafe_ptr()))
        var ts_ptr = UInt64(Int(buf.unsafe_ptr() + max_bytes))
        (buf.unsafe_ptr() + max_bytes).bitcast[Int64]()[0] = (
            nanoseconds // 1_000_000_000
        )
        (buf.unsafe_ptr() + max_bytes + 8).bitcast[Int64]()[0] = (
            nanoseconds % 1_000_000_000
        )
        var idx = self._alloc(KIND_RECV, fd, buf^)
        var ud = self._user_data(idx, KIND_RECV)
        self.q.push_sqe(
            OP_RECV,
            fd,
            data_ptr,
            UInt32(max_bytes),
            0,
            0,
            ud,
            sqe_flags=IOSQE_IO_LINK,
        )
        # The linked timeout posts its OWN KIND_TIMEOUT completion (-ETIME
        # if it fired, -ECANCELED if the recv completed first); it is
        # fully identified and must be reaped like any other completion.
        var tidx = self._alloc(KIND_TIMEOUT, -1, List[UInt8]())
        var tud = self._user_data(tidx, KIND_TIMEOUT)
        self.q.push_sqe(OP_LINK_TIMEOUT, -1, ts_ptr, 1, 0, 0, tud)
        self.inflight += 2
        return OpId(ud)

    def cancel(mut self, target: OpId) raises -> OpId:
        """Asks the kernel to cancel an in-flight op. The target then
        completes with -ECANCELED (or finishes first); this op's own
        completion is 0 on success, -ENOENT if nothing matched."""
        self._room()
        var idx = self._alloc(KIND_CANCEL, -1, List[UInt8]())
        var ud = self._user_data(idx, KIND_CANCEL)
        self.q.push_sqe(OP_ASYNC_CANCEL, -1, target.raw, 0, 0, 0, ud)
        self.inflight += 1
        return OpId(ud)

    # --- driving ------------------------------------------------------------

    def submit(mut self) raises -> Int:
        """Flushes queued SQEs without waiting."""
        return self.q.enter(0)

    def wait(mut self, min_complete: Int = 1) raises -> Int:
        """Flushes queued SQEs and waits for at least `min_complete`
        completions to be available."""
        return self.q.enter(min_complete)

    def next_completion(mut self) raises -> Optional[Completion]:
        """Pops one completion if available; None when the CQ is
        drained. Slot buffers move into the Completion here. A
        multishot completion with more=True leaves its op armed (the
        slot stays live); the terminal one (more=False) releases it."""
        if not self.q.cqe_pending():
            return None
        var cqe = self.q.pop_cqe()
        var idx = Int(cqe.user_data & 0xFFFFFFFF)
        var gen = UInt16((cqe.user_data >> 32) & 0xFFFF)
        var kind = UInt8((cqe.user_data >> 48) & 0xFF)
        if idx >= len(self.slots) or not self.slots[idx].active:
            raise Error("socket.ring: completion for unknown slot")
        if self.slots[idx].gen != gen:
            raise Error("socket.ring: completion for stale generation")
        var more = (cqe.flags & CQE_F_MORE) != 0
        var bid = -1
        if (cqe.flags & CQE_F_BUFFER) != 0:
            bid = Int(cqe.flags >> UInt32(CQE_BUFFER_SHIFT))
        var fd = self.slots[idx].fd
        if more:
            # armed multishot: the slot (and any owned memory) lives on
            return Completion(
                OpId(cqe.user_data),
                kind,
                fd,
                cqe.res,
                List[UInt8](),
                bid,
                True,
            )
        var buf = List[UInt8]()
        swap(buf, self.slots[idx].buf)
        # recycle the slot
        self.slots[idx].active = False
        self.slots[idx].gen += 1
        self.free.append(UInt32(idx))
        self.inflight -= 1
        # recv: truncate the buffer to what actually arrived
        if kind == KIND_RECV and cqe.res > 0 and Int(cqe.res) < len(buf):
            buf.shrink(Int(cqe.res))
        if kind == KIND_RECV and cqe.res <= 0:
            buf.shrink(0)
        return Completion(
            OpId(cqe.user_data), kind, fd, cqe.res, buf^, bid, False
        )
