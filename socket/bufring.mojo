# Provided buffer ring (IORING_REGISTER_PBUF_RING): a pool of receive
# buffers the KERNEL picks from at completion time. Multishot recv
# plus this pool is the steady state of a busy server — one armed SQE
# per connection and zero per-read buffer management.
#
# Memory model: the pool owns both the ring of io_uring_buf
# descriptors (16 bytes each: addr u64, len u32, bid u16, resv u16;
# the ring tail overlays byte 14 of entry 0) and the flat backing
# storage. A completion borrows buffer `bid`; the consumer reads
# `view(bid, len)` and MUST `recycle(bid)` afterwards to return it to
# the kernel. Unrecycled buffers eventually starve the pool — recv
# completions then fail with -ENOBUFS, which the Ring surfaces.

from std.atomic import Atomic
from std.ffi import external_call
from std.memory import UnsafePointer

from socket.uring_sys import (
    REGISTER_PBUF_RING,
    SYS_IO_URING_REGISTER,
    UNREGISTER_PBUF_RING,
    _mmap,
    _syscall,
)


struct BufRing(Movable):
    var bgid: UInt16
    var entries: Int  # power of two
    var buf_size: Int
    var ring_mem: UnsafePointer[UInt8, MutAnyOrigin]
    var ring_bytes: Int
    var backing: List[UInt8]
    var ring_fd: Int32  # owning io_uring fd (for unregister)
    var tail_local: UInt16

    def __init__(
        out self, ring_fd: Int32, bgid: UInt16, entries: Int, buf_size: Int
    ) raises:
        if entries & (entries - 1) != 0:
            raise Error("socket.bufring: entries must be a power of two")
        self.bgid = bgid
        self.entries = entries
        self.buf_size = buf_size
        self.ring_fd = ring_fd
        self.ring_bytes = entries * 16
        var pages = (self.ring_bytes + 4095) & ~4095
        # MAP_PRIVATE | MAP_ANONYMOUS
        self.ring_mem = _mmap(pages, 3, 0x22, Int32(-1), 0)
        self.backing = List[UInt8](length=entries * buf_size, fill=0)
        var bp = self.backing.unsafe_ptr()
        for b in range(entries):
            var e = self.ring_mem + 16 * b
            e.bitcast[UInt64]()[0] = UInt64(Int(bp + b * buf_size))
            (e + 8).bitcast[UInt32]()[0] = UInt32(buf_size)
            (e + 12).bitcast[UInt16]()[0] = UInt16(b)
        self.tail_local = UInt16(entries)
        # publish all buffers (tail u16 lives at byte 14 of the header)
        (self.ring_mem + 14).bitcast[Atomic[DType.uint16]]()[].store(
            self.tail_local
        )
        # io_uring_buf_reg { ring_addr u64, ring_entries u32, bgid u16,
        # flags u16, resv u64[3] }
        var reg = List[UInt8](length=40, fill=0)
        reg.unsafe_ptr().bitcast[UInt64]()[0] = UInt64(Int(self.ring_mem))
        (reg.unsafe_ptr() + 8).bitcast[UInt32]()[0] = UInt32(entries)
        (reg.unsafe_ptr() + 12).bitcast[UInt16]()[0] = bgid
        var rc = _syscall(
            SYS_IO_URING_REGISTER,
            Int(ring_fd),
            REGISTER_PBUF_RING,
            Int(reg.unsafe_ptr()),
            1,
            0,
            0,
        )
        if rc < 0:
            raise Error(
                "socket.bufring: register failed (errno " + String(-rc) + ")"
            )
        _ = reg[0]  # outlive the kernel read

    def __del__(deinit self):
        var reg = List[UInt8](length=40, fill=0)
        (reg.unsafe_ptr() + 12).bitcast[UInt16]()[0] = self.bgid
        _ = _syscall(
            SYS_IO_URING_REGISTER,
            Int(self.ring_fd),
            UNREGISTER_PBUF_RING,
            Int(reg.unsafe_ptr()),
            1,
            0,
            0,
        )
        _ = reg[0]
        var pages = (self.ring_bytes + 4095) & ~4095
        _ = external_call["munmap", Int32](self.ring_mem, pages)

    @always_inline
    def view(mut self, bid: Int, length: Int) -> Span[UInt8, MutAnyOrigin]:
        """Borrowed bytes of buffer `bid` (valid until recycle)."""
        var p: UnsafePointer[UInt8, MutAnyOrigin] = (
            self.backing.unsafe_ptr() + bid * self.buf_size
        )
        return Span(ptr=p, length=length)

    def recycle(mut self, bid: Int):
        """Returns buffer `bid` to the kernel's pool."""
        var slot = Int(self.tail_local) & (self.entries - 1)
        var e = self.ring_mem + 16 * slot
        var bp = self.backing.unsafe_ptr()
        e.bitcast[UInt64]()[0] = UInt64(Int(bp + bid * self.buf_size))
        (e + 8).bitcast[UInt32]()[0] = UInt32(self.buf_size)
        (e + 12).bitcast[UInt16]()[0] = UInt16(bid)
        self.tail_local += 1
        (self.ring_mem + 14).bitcast[Atomic[DType.uint16]]()[].store(
            self.tail_local
        )
