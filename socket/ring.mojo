# The completion engine: a safe operation table over UringQueue.
#
# Lifetime rule: every byte of memory the kernel can read or write
# for an in-flight operation is OWNED BY THE OPERATION'S SLOT until
# its completion is reaped. Callers hand buffers in (send) and take
# buffers out (recv completions); they never share memory with the
# kernel. Mojo's ASAP destruction therefore cannot free anything the
# kernel still sees.
#
# user_data packing: slot index (32 bits) | generation (24) | kind (8).
# Generations make completions of recycled slots detectable; the
# engine raises on a stale generation instead of misrouting it.
# 24-bit generation = 16M cycles before wrap; a slot would have to
# recycle that many times within the lifetime of a still-in-flight
# CQE for the ABA window to close.
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

from socket._syscalls import (
    SOCKADDR_STORAGE_SIZE,
    SYS_IO_URING_REGISTER,
    errno_message,
    read_sockaddr,
    syscall,
    write_sockaddr,
)
from socket.addr import IpAddress, SocketAddr
from socket.bufring import BufRing
from socket.uring_sys import (
    ACCEPT_MULTISHOT,
    CQE_BUFFER_SHIFT,
    CQE_F_BUFFER,
    CQE_F_MORE,
    CQE_F_NOTIF,
    FILE_INDEX_ALLOC,
    IOSQE_BUFFER_SELECT,
    IOSQE_FIXED_FILE,
    IOSQE_IO_LINK,
    OP_ACCEPT,
    OP_ASYNC_CANCEL,
    OP_CLOSE,
    OP_CONNECT,
    OP_LINK_TIMEOUT,
    OP_MSG_RING,
    OP_NOP,
    OP_RECV,
    OP_SEND,
    OP_SEND_ZC,
    OP_SHUTDOWN,
    OP_SOCKET,
    OP_TIMEOUT,
    RECV_MULTISHOT,
    REGISTER_FILES,
    UNREGISTER_FILES,
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
# A linked-timeout partner of a recv_with_timeout: the kernel always
# posts its CQE, but the engine drains it internally — callers see
# only the recv. Without this, forgetting to reap the partner leaks
# both the slot and one inflight count.
comptime KIND_TIMEOUT_LINKED = UInt8(11)
# Registered fd table family. CQE.res for these is a *slot index*
# in the registered table, not a kernel fd; downstream ops use that
# slot with `fixed=True` (which sets IOSQE_FIXED_FILE on the SQE).
comptime KIND_ACCEPT_DIRECT = UInt8(12)
comptime KIND_ACCEPT_MULTI_DIRECT = UInt8(13)
comptime KIND_SOCKET = UInt8(14)
# OP_SEND_ZC posts TWO CQEs per submission — the "send done" one
# (carries F_MORE; res = bytes sent) which the engine surfaces, and
# the "buffer reusable" notif (F_NOTIF, no F_MORE) which the engine
# drains. The slot stays alive across both so the user-passed
# buffer survives the kernel's retransmit window.
comptime KIND_SEND_ZC = UInt8(15)
# Cross-ring messaging. KIND_MSG_RING is the LOCAL CQE the sender
# gets back (an ack: res = 0 on delivery, -errno on failure).
# KIND_MSG_INCOMING is the CQE the kernel posts on the TARGET ring;
# it has no associated local slot (the sender constructed the
# target's user_data, not the engine), so next_completion() surfaces
# it verbatim without slot lookup.
comptime KIND_MSG_RING = UInt8(16)
comptime KIND_MSG_INCOMING = UInt8(17)


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
    if kind == KIND_TIMEOUT_LINKED:
        return "timeout-linked"
    if kind == KIND_CANCEL:
        return "cancel"
    if kind == KIND_ACCEPT_DIRECT:
        return "accept-direct"
    if kind == KIND_ACCEPT_MULTI_DIRECT:
        return "accept-multishot-direct"
    if kind == KIND_SOCKET:
        return "socket-direct"
    if kind == KIND_SEND_ZC:
        return "send-zc"
    if kind == KIND_MSG_RING:
        return "msg-ring"
    if kind == KIND_MSG_INCOMING:
        return "msg-incoming"
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
    # 24 bits used (masked on increment); 32-bit field for arithmetic.
    var gen: UInt32
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
        """For accept / accept_direct completions: the peer's address.
        Multishot variants (KIND_ACCEPT_MULTI / _MULTI_DIRECT) don't
        carry per-completion sockaddr — fetch via getpeername if
        needed."""
        var ok = self.kind == KIND_ACCEPT or self.kind == KIND_ACCEPT_DIRECT
        if not ok or len(self.buf) < SOCKADDR_STORAGE_SIZE:
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

    def __init__(
        out self,
        entries: Int = 256,
        *,
        sqpoll: Bool = False,
        sqpoll_idle_ms: UInt32 = 1000,
        single_issuer: Bool = False,
        defer_taskrun: Bool = False,
        coop_taskrun: Bool = False,
    ) raises:
        """Ring options:
          * `sqpoll`           kernel SQ submission kthread — steady-
                                state submit can collapse to ZERO
                                syscalls. Linux 5.11+ unprivileged.
          * `defer_taskrun`    defer completion task work until we
                                wait() — best cache locality. Linux
                                6.0+; implies single_issuer.
          * `coop_taskrun`     run completions in the calling task
                                (vs. random kernel threads). Linux
                                5.19+.
          * `single_issuer`    only one thread submits; the kernel
                                drops several internal locks. Linux
                                6.0+. Required by defer_taskrun.

        Older kernels reject unknown flags with -EINVAL. Defaults are
        OFF — opt in once you know your kernel."""
        self.q = UringQueue(
            entries,
            sqpoll=sqpoll,
            sqpoll_idle_ms=sqpoll_idle_ms,
            single_issuer=single_issuer,
            defer_taskrun=defer_taskrun,
            coop_taskrun=coop_taskrun,
        )
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

    @always_inline
    def fd(self) -> Int32:
        """The underlying io_uring fd. Pass to another Ring's
        `msg_ring()` to deliver a cross-thread CQE here."""
        return self.q.fd

    def msg_ring(
        mut self,
        target_ring_fd: Int32,
        payload: UInt64,
        target_res: Int32 = 0,
    ) raises -> OpId:
        """Post a CQE on `target_ring_fd` (a different Ring's io_uring
        fd). The target's next reap surfaces a KIND_MSG_INCOMING
        completion carrying `payload` (low 56 bits) and `target_res`.
        Top 8 bits of the target's user_data are reserved by the engine
        for the kind tag — callers must keep their payload below 2^56.
        The local CQE this op posts is just a delivery ack (res = 0 on
        success). Cross-thread / cross-ring signalling primitive
        (Linux 5.18+)."""
        if (payload & (UInt64(0xFF) << 56)) != 0:
            raise Error(
                "socket.ring: msg_ring payload must fit in the low 56 bits"
            )
        self._room()
        var idx = self._alloc(KIND_MSG_RING, target_ring_fd, List[UInt8]())
        var local_ud = self._user_data(idx, KIND_MSG_RING)
        # Target sees this user_data verbatim — tag with KIND_MSG_INCOMING
        # in the top 8 bits so the receiver's next_completion() handles
        # it without a slot lookup.
        var target_ud = payload | (UInt64(KIND_MSG_INCOMING) << 56)
        # SQE for OP_MSG_RING (io_uring/msg_ring.c):
        #   sqe.fd  = target ring fd          (push_sqe `fd`)
        #   sqe.addr = mode (0 = MSG_DATA)    (push_sqe `addr`)
        #   sqe.len = res to post on target   (push_sqe `length`)
        #   sqe.off = user_data on target     (push_sqe `off_or_addr2`)
        self.q.push_sqe(
            OP_MSG_RING,
            target_ring_fd,
            0,
            UInt32(Int(target_res)),
            target_ud,
            0,
            local_ud,
        )
        self.inflight += 1
        return OpId(local_ud)

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
        # The backing buffer is owned by the BufRing held inside the
        # Ring; the caller-visible Span lives only until recycle_buffer
        # is called. We discard the natural origin explicitly so the
        # Span type doesn't leak the BufRing's lifetime into callers.
        var p = (
            self.bufs.value().backing.unsafe_ptr()
            + bid * self.bufs.value().buf_size
        ).as_unsafe_any_origin()
        return Span(ptr=p, length=length)

    def recycle_buffer(mut self, bid: Int) raises:
        if not self.bufs:
            raise Error("socket.ring: no buffer pool registered")
        if bid < 0 or bid >= self.bufs.value().entries:
            raise Error("socket.ring: recycle_buffer bid out of range")
        self.bufs[].recycle(bid)

    # --- registered fd table -----------------------------------------------

    def register_files(mut self, count: Int) raises:
        """Set up a sparse registered fd table of `count` slots. Once
        registered, accept_direct / socket_direct allocate into the
        table (kernel picks a free slot), and recv / send / close
        with `fixed=True` reference table slots by index — skipping
        the per-op fget refcount bump that raw fds pay."""
        if count <= 0:
            raise Error("socket.ring: register_files count must be > 0")
        # IORING_REGISTER_FILES takes an array of __s32 fds; -1 means
        # "empty slot, kernel allocates here later." 0xFF-fill makes
        # every i32 read as -1.
        var fds = List[UInt8](length=count * 4, fill=0xFF)
        var rc = syscall(
            SYS_IO_URING_REGISTER,
            Int(self.q.fd),
            REGISTER_FILES,
            Int(fds.unsafe_ptr()),
            count,
        )
        if rc < 0:
            raise Error(
                "socket.ring: register_files failed (errno "
                + String(-rc)
                + ")"
            )
        _ = fds[0]  # keep alive past the kernel read

    def unregister_files(mut self) raises:
        """Tear down the registered fd table. Any direct fds become
        invalid; callers should close_direct them first."""
        var rc = syscall(
            SYS_IO_URING_REGISTER,
            Int(self.q.fd),
            UNREGISTER_FILES,
            0,
            0,
        )
        if rc < 0:
            raise Error(
                "socket.ring: unregister_files failed (errno "
                + String(-rc)
                + ")"
            )

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
            | (UInt64(self.slots[idx].gen & 0xFFFFFF) << 32)
            | (UInt64(kind) << 56)
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

    def connect(
        mut self, fd: Int32, addr: SocketAddr, *, fixed: Bool = False
    ) raises -> OpId:
        self._room()
        var st = List[UInt8](length=SOCKADDR_STORAGE_SIZE, fill=0)
        var alen = write_sockaddr(
            st.unsafe_ptr().as_unsafe_any_origin(),
            addr.ip.is_v6,
            addr.ip.octets,
            addr.port,
        )
        var addr_ptr = UInt64(Int(st.unsafe_ptr()))
        var idx = self._alloc(KIND_CONNECT, fd, st^)
        var ud = self._user_data(idx, KIND_CONNECT)
        var sqe_flags = IOSQE_FIXED_FILE if fixed else UInt8(0)
        self.q.push_sqe(
            OP_CONNECT, fd, addr_ptr, 0, UInt64(alen), 0, ud, sqe_flags=sqe_flags
        )
        self.inflight += 1
        return OpId(ud)

    def recv(
        mut self, fd: Int32, max_bytes: Int, *, fixed: Bool = False
    ) raises -> OpId:
        """`fixed=True` interprets `fd` as a slot index in the
        registered fd table (set up by register_files()) instead of
        a raw kernel fd. The kernel skips the fget refcount bump
        that a raw fd costs every op."""
        self._room()
        # Uninitialized: the kernel fills it; a zero-fill would be thrown
        # away on the next syscall.
        var buf = List[UInt8](capacity=max_bytes)
        buf.resize(unsafe_uninit_length=max_bytes)
        var ptr = UInt64(Int(buf.unsafe_ptr()))
        var idx = self._alloc(KIND_RECV, fd, buf^)
        var ud = self._user_data(idx, KIND_RECV)
        var sqe_flags = IOSQE_FIXED_FILE if fixed else UInt8(0)
        self.q.push_sqe(
            OP_RECV,
            fd,
            ptr,
            UInt32(max_bytes),
            0,
            0,
            ud,
            sqe_flags=sqe_flags,
        )
        self.inflight += 1
        return OpId(ud)

    def send(
        mut self,
        fd: Int32,
        var data: List[UInt8],
        *,
        fixed: Bool = False,
        zero_copy: Bool = False,
    ) raises -> OpId:
        """Takes ownership of `data` until the completion is reaped.
        `fixed=True`: `fd` is a registered-table slot index.
        `zero_copy=True`: use OP_SEND_ZC (the kernel keeps the buffer
        pinned through its retransmit window; valuable when `data` is
        large, typically >16 KiB). The slot owns `data` across both
        the user-visible "send done" CQE and the hidden notif CQE so
        the buffer remains valid until the kernel releases it."""
        self._room()
        var ptr = UInt64(Int(data.unsafe_ptr()))
        var n = len(data)
        var kind = KIND_SEND_ZC if zero_copy else KIND_SEND
        var op = OP_SEND_ZC if zero_copy else OP_SEND
        var idx = self._alloc(kind, fd, data^)
        var ud = self._user_data(idx, kind)
        var sqe_flags = IOSQE_FIXED_FILE if fixed else UInt8(0)
        # MSG_NOSIGNAL: a dead peer must surface as -EPIPE, not SIGPIPE
        self.q.push_sqe(
            op, fd, ptr, UInt32(n), 0, UInt32(0x4000), ud, sqe_flags=sqe_flags
        )
        self.inflight += 1
        return OpId(ud)

    def send_copy(
        mut self,
        fd: Int32,
        data: Span[UInt8, _],
        *,
        fixed: Bool = False,
        zero_copy: Bool = False,
    ) raises -> OpId:
        var owned = List[UInt8](capacity=len(data))
        owned.extend(data)
        return self.send(fd, owned^, fixed=fixed, zero_copy=zero_copy)

    def send_borrowed(
        mut self,
        fd: Int32,
        addr: UInt64,
        length: Int,
        *,
        fixed: Bool = False,
    ) raises -> OpId:
        """Submit a send that references existing memory at `addr` /
        `length` WITHOUT taking ownership of it. The caller MUST
        keep the memory pinned and unmodified until the returned
        OpId's CQE arrives, and the kernel must finish reading it
        before the buffer is reused — for plain TCP/UDP this is
        guaranteed by the time `wait()` returns the send completion.

        Unsafe in general — useful when you have a long-lived static
        buffer or pool and want to skip the per-call allocation in
        send_copy. Symmetric with `recv` accepting any pointer."""
        self._room()
        var idx = self._alloc(KIND_SEND, fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_SEND)
        var sqe_flags = IOSQE_FIXED_FILE if fixed else UInt8(0)
        self.q.push_sqe(
            OP_SEND,
            fd,
            addr,
            UInt32(length),
            0,
            UInt32(0x4000),
            ud,
            sqe_flags=sqe_flags,
        )
        self.inflight += 1
        return OpId(ud)

    def close_fd(
        mut self, fd: Int32, *, fixed: Bool = False
    ) raises -> OpId:
        """When `fixed=True`, closes a direct fd (releases the table
        slot via sqe.file_index); the slot is available for
        re-allocation immediately after this op is processed."""
        self._room()
        var idx = self._alloc(KIND_CLOSE, fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_CLOSE)
        if fixed:
            # OP_CLOSE on a direct fd: the kernel rejects with EINVAL
            # if both sqe.fd and sqe.file_index are non-zero, so the
            # fd field must be 0 here. file_index = slot + 1 (1-based;
            # 0 means "no slot").
            self.q.push_sqe(
                OP_CLOSE,
                0,
                0,
                0,
                0,
                0,
                ud,
                file_index=UInt32(fd) + UInt32(1),
            )
        else:
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
        getpeername if a protocol needs them, or use accept_direct
        single-shots (which DO carry peer addresses)."""
        self._room()
        var idx = self._alloc(KIND_ACCEPT_MULTI, listen_fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_ACCEPT_MULTI)
        self.q.push_sqe(
            OP_ACCEPT, listen_fd, 0, 0, 0, 0, ud, ioprio=ACCEPT_MULTISHOT
        )
        self.inflight += 1
        return OpId(ud)

    def accept_direct(mut self, listen_fd: Int32) raises -> OpId:
        """accept(2) where the new fd is allocated into the
        registered fd table (set up via register_files() first). The
        CQE.res carries the table SLOT INDEX, not a kernel fd.
        Subsequent ops on that connection pass the slot index with
        `fixed=True`; close_direct() releases the slot. Peer address
        is collected as in the regular accept()."""
        self._room()
        var st = List[UInt8](length=SOCKADDR_STORAGE_SIZE + 4, fill=0)
        st[SOCKADDR_STORAGE_SIZE] = UInt8(SOCKADDR_STORAGE_SIZE)
        var addr_ptr = UInt64(Int(st.unsafe_ptr()))
        var len_ptr = UInt64(Int(st.unsafe_ptr() + SOCKADDR_STORAGE_SIZE))
        var idx = self._alloc(KIND_ACCEPT_DIRECT, listen_fd, st^)
        var ud = self._user_data(idx, KIND_ACCEPT_DIRECT)
        self.q.push_sqe(
            OP_ACCEPT,
            listen_fd,
            addr_ptr,
            0,
            len_ptr,
            0,
            ud,
            file_index=FILE_INDEX_ALLOC,
        )
        self.inflight += 1
        return OpId(ud)

    def accept_multishot_direct(mut self, listen_fd: Int32) raises -> OpId:
        """Multishot accept that allocates each new fd directly into
        the registered table — the steady-state shape of a busy
        connection-oriented server. Each completion's res is a new
        slot index; peer addresses are not collected (use
        accept_direct for those)."""
        self._room()
        var idx = self._alloc(KIND_ACCEPT_MULTI_DIRECT, listen_fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_ACCEPT_MULTI_DIRECT)
        self.q.push_sqe(
            OP_ACCEPT,
            listen_fd,
            0,
            0,
            0,
            0,
            ud,
            ioprio=ACCEPT_MULTISHOT,
            file_index=FILE_INDEX_ALLOC,
        )
        self.inflight += 1
        return OpId(ud)

    def socket_direct(
        mut self, domain: Int, type_: Int, protocol: Int
    ) raises -> OpId:
        """Create a socket whose fd lands in the registered table —
        no userspace fd allocation at all. CQE.res is the table slot
        index. Used to open client connections fully under the Ring
        (followed by a connect on the same slot)."""
        self._room()
        var idx = self._alloc(KIND_SOCKET, -1, List[UInt8]())
        var ud = self._user_data(idx, KIND_SOCKET)
        # OP_SOCKET SQE encoding (io_uring/net.c):
        #   sqe.fd     = domain
        #   sqe.off    = type
        #   sqe.len    = protocol
        #   file_index = slot+1, or FILE_INDEX_ALLOC for "any free"
        self.q.push_sqe(
            OP_SOCKET,
            Int32(domain),
            0,
            UInt32(protocol),
            UInt64(type_),
            0,
            ud,
            file_index=FILE_INDEX_ALLOC,
        )
        self.inflight += 1
        return OpId(ud)

    def recv_multishot(
        mut self, fd: Int32, *, fixed: Bool = False
    ) raises -> OpId:
        """One armed SQE that produces a buffer-carrying completion per
        arriving chunk, drawing from the registered pool. ANY completion
        with bid >= 0 — INCLUDING the terminal one (more == False) — owns
        a pool buffer: read it with buffer_view(bid, res) and you MUST
        recycle_buffer(bid) afterwards. A multishot can terminate WHILE
        committing a buffer (res > 0, more == False) when the pool drains
        or the CQ overflows; skipping recycle there leaks that buffer and
        starves the pool toward -ENOBUFS. res == 0 means peer EOF (no
        buffer, bid == -1); -ENOBUFS means the pool starved.
        `fixed=True`: `fd` is a registered-table slot index."""
        if not self.bufs:
            raise Error("socket.ring: setup_buffers() first")
        self._room()
        var idx = self._alloc(KIND_RECV_MULTI, fd, List[UInt8]())
        var ud = self._user_data(idx, KIND_RECV_MULTI)
        var sqe_flags = IOSQE_BUFFER_SELECT
        if fixed:
            sqe_flags |= IOSQE_FIXED_FILE
        self.q.push_sqe(
            OP_RECV,
            fd,
            0,
            0,
            0,
            0,
            ud,
            sqe_flags=sqe_flags,
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

        The linked-timeout partner CQE the kernel posts is drained
        inside the engine (kind KIND_TIMEOUT_LINKED); the caller sees
        exactly ONE completion for the returned OpId — the recv,
        carrying either bytes or -ECANCELED."""
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
        # The linked timeout still gets a CQE (one of -ETIME if it
        # fired or -ECANCELED if recv won the race), but we tag it
        # KIND_TIMEOUT_LINKED so next_completion() drops it silently.
        var tidx = self._alloc(KIND_TIMEOUT_LINKED, -1, List[UInt8]())
        var tud = self._user_data(tidx, KIND_TIMEOUT_LINKED)
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
        slot stays live); the terminal one (more=False) releases it.
        KIND_TIMEOUT_LINKED CQEs (the partner of a recv_with_timeout)
        are drained internally — they release their slot and we loop
        to the next CQE without surfacing them."""
        while True:
            if not self.q.cqe_pending():
                return None
            var cqe = self.q.pop_cqe()
            var kind = UInt8((cqe.user_data >> 56) & 0xFF)
            # External msg_ring CQE: the sender packed KIND_MSG_INCOMING
            # in the top 8 bits and the low 56 bits are their payload —
            # there's no local slot to look up.
            if kind == KIND_MSG_INCOMING:
                return Completion(
                    OpId(cqe.user_data),
                    kind,
                    Int32(-1),
                    cqe.res,
                    List[UInt8](),
                    -1,
                    False,
                )
            var idx = Int(cqe.user_data & 0xFFFFFFFF)
            var gen = UInt32((cqe.user_data >> 32) & 0xFFFFFF)
            if idx >= len(self.slots) or not self.slots[idx].active:
                raise Error("socket.ring: completion for unknown slot")
            if (self.slots[idx].gen & 0xFFFFFF) != gen:
                raise Error("socket.ring: completion for stale generation")
            var more = (cqe.flags & CQE_F_MORE) != 0
            var notif = (cqe.flags & CQE_F_NOTIF) != 0
            var bid = -1
            if (cqe.flags & CQE_F_BUFFER) != 0:
                bid = Int(cqe.flags >> UInt32(CQE_BUFFER_SHIFT))
            var fd = self.slots[idx].fd
            # SEND_ZC two-CQE protocol: F_MORE on the first CQE
            # (the send result) and F_NOTIF on the second (the
            # "buffer is reusable" notif). Engine surfaces the
            # result, drains the notif silently, keeps the slot
            # alive across both so the buffer remains pinned for
            # the kernel's retransmit window.
            if kind == KIND_SEND_ZC:
                if more:
                    return Completion(
                        OpId(cqe.user_data),
                        kind,
                        fd,
                        cqe.res,
                        List[UInt8](),
                        -1,
                        False,
                    )
                if notif:
                    self.slots[idx].active = False
                    self.slots[idx].gen += 1
                    self.free.append(UInt32(idx))
                    self.inflight -= 1
                    continue
                # Error-only single CQE: fall through to normal release.
            elif more:
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
            # Linked-timeout partner: release the slot and loop. The
            # caller never sees this CQE — they see only the recv's.
            if kind == KIND_TIMEOUT_LINKED:
                self.slots[idx].active = False
                self.slots[idx].gen += 1
                self.free.append(UInt32(idx))
                self.inflight -= 1
                continue
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
