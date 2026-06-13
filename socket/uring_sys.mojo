# io_uring floor: raw syscalls (425/426/427), ring mmap, SQE/CQE
# layout. No liburing — the kernel ABI is the interface and the rings
# are shared memory we manage directly (proven in
# .probe/uring_probe.mojo / uring_echo_probe.mojo).
#
# This layer has NO policy: no buffers, no operation table, no errno
# translation. socket/ring.mojo builds the safe engine on top.
#
# Two traps this file encodes (see .probe/SYNTAX.md):
#   - libc syscall(2) must be declared with exactly ONE signature, so
#     every call routes through the uniform 7-Int `_syscall` below.
#   - The shared head/tail words are touched only through
#     Atomic[DType.uint32] views of the mmap'd ring (layout-verified).

from std.atomic import Atomic
from std.ffi import external_call
from std.memory import UnsafePointer, memset_zero

comptime SYS_IO_URING_SETUP = 425
comptime SYS_IO_URING_ENTER = 426
comptime SYS_IO_URING_REGISTER = 427

comptime ENTER_GETEVENTS = UInt32(1)

# io_uring_params.features bit (offset 20). SINGLE_MMAP means the SQ and
# CQ rings share one mapping — the layout this file assumes (Linux 5.4+).
comptime FEAT_SINGLE_MMAP = UInt32(1 << 0)

comptime _PROT_READ_WRITE = 3
comptime _MAP_SHARED_POPULATE = 0x8001
comptime _OFF_SQ_RING = 0
comptime _OFF_SQES = 0x10000000

# Opcodes (include/uapi/linux/io_uring.h). M0 uses the socket set;
# the rest of the enum lands with the milestones that need it.
comptime OP_NOP = UInt8(0)
comptime OP_TIMEOUT = UInt8(11)
comptime OP_ACCEPT = UInt8(13)
comptime OP_ASYNC_CANCEL = UInt8(14)
comptime OP_LINK_TIMEOUT = UInt8(15)
comptime OP_CONNECT = UInt8(16)
comptime OP_CLOSE = UInt8(19)
comptime OP_SEND = UInt8(26)
comptime OP_RECV = UInt8(27)
comptime OP_SHUTDOWN = UInt8(34)

comptime SQE_SIZE = 64
comptime CQE_SIZE = 16

# sqe->flags bits
comptime IOSQE_IO_LINK = UInt8(1 << 2)
comptime IOSQE_BUFFER_SELECT = UInt8(1 << 5)

# per-op ioprio bits
comptime ACCEPT_MULTISHOT = UInt16(1 << 0)
comptime RECV_MULTISHOT = UInt16(1 << 1)

# cqe->flags bits
comptime CQE_F_BUFFER = UInt32(1 << 0)
comptime CQE_F_MORE = UInt32(1 << 1)
comptime CQE_BUFFER_SHIFT = 16

comptime REGISTER_PBUF_RING = 22
comptime UNREGISTER_PBUF_RING = 23


@always_inline
def _syscall(n: Int, a: Int, b: Int, c: Int, d: Int, e: Int, f: Int) -> Int:
    return external_call["syscall", Int](n, a, b, c, d, e, f)


@always_inline
def _mmap(
    length: Int, prot: Int, flags: Int, fd: Int32, off: Int
) -> UnsafePointer[UInt8, MutAnyOrigin]:
    """The ONE mmap declaration in the process (a libc symbol may only
    ever be declared with a single signature — see .probe/SYNTAX.md)."""
    return external_call["mmap", UnsafePointer[UInt8, MutAnyOrigin]](
        UInt(0), length, prot, flags, fd, off
    )


@always_inline
def _u32_field(params: List[UInt8], off: Int) -> UInt32:
    return (
        UInt32(params[off])
        | (UInt32(params[off + 1]) << 8)
        | (UInt32(params[off + 2]) << 16)
        | (UInt32(params[off + 3]) << 24)
    )


struct Cqe(Copyable, ImplicitlyCopyable, Movable):
    """One completion: the submission's user_data and the op result
    (negative errno on failure, count/fd/zero on success)."""

    var user_data: UInt64
    var res: Int32
    var flags: UInt32

    def __init__(out self, user_data: UInt64, res: Int32, flags: UInt32):
        self.user_data = user_data
        self.res = res
        self.flags = flags


struct UringQueue(Movable):
    """The mmap'd submission/completion rings of one io_uring
    instance. Single-threaded by design: one ring per thread."""

    var fd: Int32
    var ring: UnsafePointer[UInt8, MutAnyOrigin]
    var ring_sz: Int
    var sqes: UnsafePointer[UInt8, MutAnyOrigin]
    var sqes_sz: Int
    var sq_entries: UInt32
    var sq_mask: UInt32
    var sq_tail_off: Int
    var sq_array_off: Int
    var cq_mask: UInt32
    var cq_head_off: Int
    var cq_tail_off: Int
    var cq_cqes_off: Int
    var to_submit: UInt32  # SQEs queued locally since the last enter

    def __init__(out self, entries: Int) raises:
        var params = List[UInt8](length=120, fill=0)
        var rc = _syscall(
            SYS_IO_URING_SETUP, entries, Int(params.unsafe_ptr()), 0, 0, 0, 0
        )
        if rc < 0:
            raise Error(
                "socket.uring: io_uring_setup failed (errno "
                + String(-rc)
                + ")"
            )
        self.fd = Int32(rc)
        self.sq_entries = _u32_field(params, 0)
        var cq_entries = _u32_field(params, 4)
        # io_sqring_offsets at byte 40, io_cqring_offsets at byte 80
        self.sq_tail_off = Int(_u32_field(params, 44))
        var sq_mask_off = Int(_u32_field(params, 48))
        self.sq_array_off = Int(_u32_field(params, 64))
        self.cq_head_off = Int(_u32_field(params, 80))
        self.cq_tail_off = Int(_u32_field(params, 84))
        var cq_mask_off = Int(_u32_field(params, 88))
        self.cq_cqes_off = Int(_u32_field(params, 100))
        # The single-mapping layout below (CQ offsets read from, and sized
        # into, the SQ-ring mapping) is only valid when the kernel set
        # IORING_FEAT_SINGLE_MMAP. Without it the CQ is a SEPARATE mapping
        # and these offsets/reads would silently target the wrong region.
        # A raising __init__ never runs __del__, so close the fd here.
        var features = _u32_field(params, 20)
        if (features & FEAT_SINGLE_MMAP) == 0:
            _ = external_call["close", Int32](self.fd)
            raise Error(
                "socket.uring: kernel lacks IORING_FEAT_SINGLE_MMAP"
                " (needs Linux 5.4+)"
            )
        # FEAT_SINGLE_MMAP: SQ and CQ share one mapping sized to the
        # larger of the two.
        self.ring_sz = self.sq_array_off + Int(self.sq_entries) * 4
        var cq_sz = self.cq_cqes_off + Int(cq_entries) * CQE_SIZE
        if cq_sz > self.ring_sz:
            self.ring_sz = cq_sz
        self.ring = _mmap(
            self.ring_sz,
            Int(_PROT_READ_WRITE),
            Int(_MAP_SHARED_POPULATE),
            self.fd,
            Int(_OFF_SQ_RING),
        )
        # mmap signals failure with MAP_FAILED == (void*)-1, never NULL.
        if Int(self.ring) == -1:
            _ = external_call["close", Int32](self.fd)
            raise Error("socket.uring: mmap SQ ring failed")
        self.sqes_sz = Int(self.sq_entries) * SQE_SIZE
        self.sqes = _mmap(
            self.sqes_sz,
            Int(_PROT_READ_WRITE),
            Int(_MAP_SHARED_POPULATE),
            self.fd,
            Int(_OFF_SQES),
        )
        if Int(self.sqes) == -1:
            _ = external_call["munmap", Int32](self.ring, self.ring_sz)
            _ = external_call["close", Int32](self.fd)
            raise Error("socket.uring: mmap SQEs failed")
        self.sq_mask = (self.ring + sq_mask_off).bitcast[UInt32]()[0]
        self.cq_mask = (self.ring + cq_mask_off).bitcast[UInt32]()[0]
        self.to_submit = 0
        # keep-alive: params must outlive both kernel reads above
        _ = params[0]

    def __del__(deinit self):
        _ = external_call["munmap", Int32](self.sqes, self.sqes_sz)
        _ = external_call["munmap", Int32](self.ring, self.ring_sz)
        _ = external_call["close", Int32](self.fd)

    @always_inline
    def sq_space(self) -> UInt32:
        """SQEs that can still be queued before an enter is required.
        Exact: to_submit always reflects exactly the published-but-not-
        yet-consumed SQEs occupying ring slots (enter() decrements it by
        what the kernel actually consumed)."""
        return self.sq_entries - self.to_submit

    @always_inline
    def push_sqe(
        mut self,
        opcode: UInt8,
        fd: Int32,
        addr: UInt64,
        length: UInt32,
        off_or_addr2: UInt64,
        op_flags: UInt32,
        user_data: UInt64,
        *,
        sqe_flags: UInt8 = 0,
        ioprio: UInt16 = 0,
        buf_group: UInt16 = 0,
    ):
        """Writes one SQE and publishes it with a release tail bump.
        Caller guarantees space (ring.mojo flushes when full). Every
        pointer in `addr`/`off_or_addr2` must stay valid until the
        operation's CQE is reaped — the op table in ring.mojo owns that
        memory precisely for this reason. `ioprio` doubles as the
        per-op flag word (multishot bits); `buf_group` selects a
        provided-buffer ring when IOSQE_BUFFER_SELECT is set."""
        var tail_atomic = (self.ring + self.sq_tail_off).bitcast[
            Atomic[DType.uint32]
        ]()
        var tail = tail_atomic[].load()
        var idx = Int(tail & self.sq_mask)
        var s = self.sqes + SQE_SIZE * idx
        # One vectorized clear of the whole 64-byte SQE (the field stores
        # below overwrite ~42 of those bytes); cheaper than 64 scalar
        # stores on this per-submission hot path.
        memset_zero(s, SQE_SIZE)
        s[0] = opcode
        s[1] = sqe_flags
        (s + 2).bitcast[UInt16]()[0] = ioprio
        (s + 4).bitcast[Int32]()[0] = fd
        (s + 8).bitcast[UInt64]()[0] = off_or_addr2
        (s + 16).bitcast[UInt64]()[0] = addr
        (s + 24).bitcast[UInt32]()[0] = length
        (s + 28).bitcast[UInt32]()[0] = op_flags
        (s + 32).bitcast[UInt64]()[0] = user_data
        (s + 40).bitcast[UInt16]()[0] = buf_group
        (self.ring + self.sq_array_off).bitcast[UInt32]()[idx] = UInt32(idx)
        # Load-bearing: this publishes the SQE to the kernel. Mojo's Atomic
        # defaults to SEQUENTIAL (seq_cst), so the SQE body stores above are
        # ordered before this tail bump becomes visible (release). Do not
        # weaken to relaxed without a separate release fence.
        _ = tail_atomic[].fetch_add(1)
        self.to_submit += 1

    def enter(mut self, min_complete: Int) raises -> Int:
        """Submits everything queued and (optionally) waits for at least
        `min_complete` completions. Returns the SQEs the kernel consumed.

        to_submit is decremented ONLY by what the kernel reports consumed
        and is left fully intact on an error return. On a CQ-overflow
        backlog io_uring_enter returns -EBUSY having consumed zero SQEs;
        preserving the count means the still-published SQEs are re-counted
        and resubmitted on the next enter() instead of being stranded
        (which would otherwise pin ring.mojo slots/buffers and leave
        inflight permanently non-zero). Partial submits (rc < n) leave the
        remainder counted so the next enter() carries them."""
        var n = Int(self.to_submit)
        var flags = Int(ENTER_GETEVENTS) if min_complete > 0 else 0
        var rc = _syscall(
            SYS_IO_URING_ENTER, Int(self.fd), n, min_complete, flags, 0, 0
        )
        if rc < 0:
            # to_submit left intact: the published SQEs are still in the
            # ring and will be re-counted on the next enter().
            raise Error(
                "socket.uring: io_uring_enter failed (errno "
                + String(-rc)
                + ")"
            )
        # The kernel may consume fewer than n; retire only those.
        self.to_submit -= UInt32(rc)
        return rc

    @always_inline
    def cqe_pending(self) -> Bool:
        var head = (
            (self.ring + self.cq_head_off)
            .bitcast[Atomic[DType.uint32]]()[]
            .load()
        )
        var tail = (
            (self.ring + self.cq_tail_off)
            .bitcast[Atomic[DType.uint32]]()[]
            .load()
        )
        return head != tail

    @always_inline
    def pop_cqe(mut self) -> Cqe:
        """Caller must have checked cqe_pending()."""
        var headp = (self.ring + self.cq_head_off).bitcast[
            Atomic[DType.uint32]
        ]()
        var head = headp[].load()
        var idx = Int(head & self.cq_mask)
        var c = self.ring + self.cq_cqes_off + CQE_SIZE * idx
        var out = Cqe(
            c.bitcast[UInt64]()[0],
            (c + 8).bitcast[Int32]()[0],
            (c + 12).bitcast[UInt32]()[0],
        )
        _ = headp[].fetch_add(1)
        return out
