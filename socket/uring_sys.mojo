# io_uring floor: SQE/CQE layout, ring mmap, raw setup/enter/register
# syscalls. No liburing — the kernel ABI is the interface and the
# rings are shared memory we manage directly.
#
# This layer has NO policy: no buffers, no operation table, no error
# translation. socket/ring.mojo builds the safe engine on top.
#
# Synchronisation: the shared head/tail words are touched only
# through Atomic[DType.uint32] views of the mmap'd ring. Mojo's
# Atomic defaults to seq_cst, which is stronger than necessary
# (release would do) but never wrong.

from std.atomic import Atomic
from std.memory import UnsafePointer, memset_zero

from socket._syscalls import (
    MAP_POPULATE,
    MAP_SHARED,
    PROT_READ,
    PROT_WRITE,
    SYS_IO_URING_ENTER,
    SYS_IO_URING_SETUP,
    is_syscall_error,
    sys_close,
    sys_mmap_or_raise,
    sys_munmap,
    syscall,
)

comptime ENTER_GETEVENTS = UInt32(1)
comptime ENTER_SQ_WAKEUP = UInt32(1 << 1)

# io_uring_setup flags (params.flags at byte 8)
comptime SETUP_SQPOLL = UInt32(1 << 1)
comptime SETUP_SQ_AFF = UInt32(1 << 2)
# Modern taskrun model (Linux 5.19+ for COOP, 6.0+ for SINGLE_ISSUER /
# DEFER_TASKRUN). COOP_TASKRUN runs completions in the calling task.
# SINGLE_ISSUER + DEFER_TASKRUN further defers until we explicitly
# wait — best cache locality on a one-Ring-per-thread server.
comptime SETUP_COOP_TASKRUN = UInt32(1 << 8)
comptime SETUP_TASKRUN_FLAG = UInt32(1 << 9)
comptime SETUP_SINGLE_ISSUER = UInt32(1 << 12)
comptime SETUP_DEFER_TASKRUN = UInt32(1 << 13)

# io_uring_params.features bit (offset 20). SINGLE_MMAP means the SQ
# and CQ rings share one mapping — the layout this file assumes
# (Linux 5.4+).
comptime FEAT_SINGLE_MMAP = UInt32(1 << 0)

# sqring->flags bits (the word the kernel exposes at sq_off.flags).
# NEED_WAKEUP signals the SQPOLL kthread has gone to sleep and we
# must call io_uring_enter with ENTER_SQ_WAKEUP to nudge it.
comptime SQ_NEED_WAKEUP = UInt32(1 << 0)
comptime SQ_CQ_OVERFLOW = UInt32(1 << 1)

comptime _MAP_FLAGS = MAP_SHARED | MAP_POPULATE
comptime _PROT_RW = PROT_READ | PROT_WRITE
comptime _OFF_SQ_RING = 0
comptime _OFF_SQES = 0x10000000

# Opcodes (include/uapi/linux/io_uring.h).
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
comptime OP_MSG_RING = UInt8(40)
comptime OP_SOCKET = UInt8(45)
comptime OP_SEND_ZC = UInt8(47)

comptime SQE_SIZE = 64
comptime CQE_SIZE = 16

# sqe->flags bits
comptime IOSQE_FIXED_FILE = UInt8(1 << 0)
comptime IOSQE_IO_LINK = UInt8(1 << 2)
comptime IOSQE_BUFFER_SELECT = UInt8(1 << 5)

# per-op ioprio bits
comptime ACCEPT_MULTISHOT = UInt16(1 << 0)
comptime RECV_MULTISHOT = UInt16(1 << 1)

# cqe->flags bits
comptime CQE_F_BUFFER = UInt32(1 << 0)
comptime CQE_F_MORE = UInt32(1 << 1)
comptime CQE_F_NOTIF = UInt32(1 << 3)
comptime CQE_BUFFER_SHIFT = 16

# io_uring_register opcodes
comptime REGISTER_FILES = 2
comptime UNREGISTER_FILES = 3
comptime REGISTER_PBUF_RING = 22
comptime UNREGISTER_PBUF_RING = 23

# Sentinel for sqe->file_index meaning "kernel allocates any free
# slot in the registered fd table" (rather than a specific slot+1).
comptime FILE_INDEX_ALLOC = UInt32(0xFFFFFFFF)


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
    var sq_head_off: Int
    var sq_tail_off: Int
    var sq_flags_off: Int
    var sq_array_off: Int
    var cq_mask: UInt32
    var cq_head_off: Int
    var cq_tail_off: Int
    var cq_cqes_off: Int
    var to_submit: UInt32  # SQEs queued locally since the last enter
    # When sqpoll is on, the kernel runs a dedicated thread that
    # consumes our SQ tail autonomously. submit() may not call
    # io_uring_enter at all; the kthread only needs an explicit
    # wakeup via ENTER_SQ_WAKEUP when it has dozed off (SQ_NEED_WAKEUP
    # set in sq_flags). Drops the per-batch syscall overhead.
    var sqpoll: Bool

    def __init__(
        out self,
        entries: Int,
        *,
        sqpoll: Bool = False,
        sqpoll_idle_ms: UInt32 = 1000,
        single_issuer: Bool = False,
        defer_taskrun: Bool = False,
        coop_taskrun: Bool = False,
    ) raises:
        # Compose the params.flags word (offset 8 in io_uring_params).
        var setup_flags = UInt32(0)
        if sqpoll:
            setup_flags |= SETUP_SQPOLL
        # DEFER_TASKRUN requires SINGLE_ISSUER; force it on.
        if defer_taskrun or single_issuer:
            setup_flags |= SETUP_SINGLE_ISSUER
        if defer_taskrun:
            setup_flags |= SETUP_DEFER_TASKRUN
        elif coop_taskrun:
            setup_flags |= SETUP_COOP_TASKRUN
        var params = List[UInt8](length=120, fill=0)
        if setup_flags != 0:
            (params.unsafe_ptr() + 8).bitcast[UInt32]()[0] = setup_flags
        if sqpoll:
            # params.sq_thread_idle @ byte 16
            (params.unsafe_ptr() + 16).bitcast[UInt32]()[0] = sqpoll_idle_ms
        var rc = syscall(
            SYS_IO_URING_SETUP, entries, Int(params.unsafe_ptr())
        )
        if rc < 0:
            raise Error(
                "socket.uring: io_uring_setup failed (errno "
                + String(-rc)
                + ")"
            )
        self.fd = Int32(rc)
        self.sqpoll = sqpoll
        self.sq_entries = _u32_field(params, 0)
        var cq_entries = _u32_field(params, 4)
        # io_sqring_offsets at byte 40, io_cqring_offsets at byte 80
        self.sq_head_off = Int(_u32_field(params, 40))
        self.sq_tail_off = Int(_u32_field(params, 44))
        var sq_mask_off = Int(_u32_field(params, 48))
        self.sq_flags_off = Int(_u32_field(params, 56))
        self.sq_array_off = Int(_u32_field(params, 64))
        self.cq_head_off = Int(_u32_field(params, 80))
        self.cq_tail_off = Int(_u32_field(params, 84))
        var cq_mask_off = Int(_u32_field(params, 88))
        self.cq_cqes_off = Int(_u32_field(params, 100))
        # The single-mapping layout below (CQ offsets read from, and
        # sized into, the SQ-ring mapping) is only valid when the
        # kernel set IORING_FEAT_SINGLE_MMAP. Without it the CQ is a
        # SEPARATE mapping and these offsets/reads would silently
        # target the wrong region. A raising __init__ never runs
        # __del__, so close the fd here.
        var features = _u32_field(params, 20)
        if (features & FEAT_SINGLE_MMAP) == 0:
            _ = sys_close(self.fd)
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
        try:
            self.ring = sys_mmap_or_raise(
                self.ring_sz, _PROT_RW, _MAP_FLAGS, self.fd, _OFF_SQ_RING
            )
        except e:
            _ = sys_close(self.fd)
            raise Error("socket.uring: mmap SQ ring failed")
        self.sqes_sz = Int(self.sq_entries) * SQE_SIZE
        try:
            self.sqes = sys_mmap_or_raise(
                self.sqes_sz, _PROT_RW, _MAP_FLAGS, self.fd, _OFF_SQES
            )
        except e:
            _ = sys_munmap(self.ring, self.ring_sz)
            _ = sys_close(self.fd)
            raise Error("socket.uring: mmap SQEs failed")
        self.sq_mask = (self.ring + sq_mask_off).bitcast[UInt32]()[0]
        self.cq_mask = (self.ring + cq_mask_off).bitcast[UInt32]()[0]
        self.to_submit = 0
        # keep-alive: params must outlive both kernel reads above
        _ = params[0]

    def __del__(deinit self):
        _ = sys_munmap(self.sqes, self.sqes_sz)
        _ = sys_munmap(self.ring, self.ring_sz)
        _ = sys_close(self.fd)

    @always_inline
    def sq_space(self) -> UInt32:
        """SQEs that can still be queued before an enter is required.
        In non-SQPOLL mode this is exact (to_submit reflects the
        outstanding count). In SQPOLL mode the kthread consumes
        asynchronously, so we read the kernel-maintained sq_head to
        get the real outstanding count (tail - head)."""
        if self.sqpoll:
            var head = (
                (self.ring + self.sq_head_off)
                .bitcast[Atomic[DType.uint32]]()[]
                .load()
            )
            var tail = (
                (self.ring + self.sq_tail_off)
                .bitcast[Atomic[DType.uint32]]()[]
                .load()
            )
            return self.sq_entries - (tail - head)
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
        file_index: UInt32 = 0,
    ):
        """Writes one SQE and publishes it with a release tail bump.
        Caller guarantees space (ring.mojo flushes when full). Every
        pointer in `addr`/`off_or_addr2` must stay valid until the
        operation's CQE is reaped — the op table in ring.mojo owns
        that memory precisely for this reason. `ioprio` doubles as
        the per-op flag word (multishot bits); `buf_group` selects a
        provided-buffer ring when IOSQE_BUFFER_SELECT is set."""
        var tail_atomic = (self.ring + self.sq_tail_off).bitcast[
            Atomic[DType.uint32]
        ]()
        var tail = tail_atomic[].load()
        var idx = Int(tail & self.sq_mask)
        var s = self.sqes + SQE_SIZE * idx
        # One vectorized clear of the whole 64-byte SQE (the field
        # stores below overwrite ~42 of those bytes); cheaper than 64
        # scalar stores on this per-submission hot path.
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
        # offset 44 is splice_fd_in (i32) AKA file_index (u32). Used
        # by accept_direct / socket_direct / close_direct to identify
        # a slot in the registered fd table. memset_zero above keeps
        # this zero by default — only writes when caller specifies.
        (s + 44).bitcast[UInt32]()[0] = file_index
        (self.ring + self.sq_array_off).bitcast[UInt32]()[idx] = UInt32(idx)
        # Load-bearing: this publishes the SQE to the kernel. Mojo's
        # Atomic defaults to SEQUENTIAL (seq_cst), so the SQE body
        # stores above are ordered before this tail bump becomes
        # visible (release). Do not weaken to relaxed without a
        # separate release fence.
        _ = tail_atomic[].fetch_add(1)
        self.to_submit += 1

    def enter(mut self, min_complete: Int) raises -> Int:
        """Submits everything queued and (optionally) waits for at
        least `min_complete` completions. Returns the SQEs the kernel
        consumed (or 0 when the SQPOLL kthread will pick them up
        without a syscall).

        Non-SQPOLL: to_submit is decremented ONLY by what the kernel
        reports consumed and is left fully intact on an error return.
        On a CQ-overflow backlog io_uring_enter returns -EBUSY having
        consumed zero SQEs; preserving the count means the still-
        published SQEs are re-counted and resubmitted on the next
        enter() instead of being stranded. Partial submits (rc < n)
        leave the remainder counted so the next enter() carries them.

        SQPOLL: the kthread consumes our SQEs autonomously. We only
        need to enter() if (a) the kthread has dozed off (NEED_WAKEUP)
        or (b) we want to wait for completions (min_complete > 0).
        When neither, this collapses to zero syscalls — the headline
        SQPOLL win."""
        if self.sqpoll:
            var enter_flags = Int(0)
            var sq_flags = (
                (self.ring + self.sq_flags_off)
                .bitcast[Atomic[DType.uint32]]()[]
                .load()
            )
            var has_work = self.to_submit > 0
            var need_wake = (sq_flags & SQ_NEED_WAKEUP) != 0
            if has_work and need_wake:
                enter_flags |= Int(ENTER_SQ_WAKEUP)
            if min_complete > 0:
                enter_flags |= Int(ENTER_GETEVENTS)
            # to_submit is now "consumed by the kthread on its own
            # schedule" — let it drop to zero regardless of whether we
            # enter() (capacity is tracked via tail-head in sq_space).
            self.to_submit = 0
            if enter_flags == 0:
                return 0
            var rc = syscall(
                SYS_IO_URING_ENTER, Int(self.fd), 0, min_complete, enter_flags
            )
            if rc < 0:
                raise Error(
                    "socket.uring: io_uring_enter (sqpoll) failed (errno "
                    + String(-rc)
                    + ")"
                )
            return rc
        var n = Int(self.to_submit)
        var flags = Int(ENTER_GETEVENTS) if min_complete > 0 else 0
        var rc = syscall(
            SYS_IO_URING_ENTER, Int(self.fd), n, min_complete, flags
        )
        if rc < 0:
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
