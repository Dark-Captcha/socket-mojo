# Probe: can we use epoll_create1/epoll_ctl/epoll_wait via FFI?
# Also: can we use fcntl to make a socket non-blocking?
from std.ffi import external_call
from std.memory import UnsafePointer

comptime EPOLL_CTL_ADD = 1
comptime EPOLL_CTL_MOD = 3
comptime EPOLL_CTL_DEL = 2

comptime EPOLLIN = 0x001
comptime EPOLLOUT = 0x004
comptime EPOLLET = 0x80000000

comptime F_GETFL = 3
comptime F_SETFL = 4
comptime O_NONBLOCK = 0x800
comptime AF_INET = 2
comptime SOCK_STREAM = 1

def main() raises:
    var epfd = external_call["epoll_create1", Int32](Int32(0))
    print("epoll_create1:", epfd)
    var s = external_call["socket", Int32](Int32(AF_INET), Int32(SOCK_STREAM), Int32(0))
    print("socket:", s)
    # fcntl to mark non-blocking
    var flags = external_call["fcntl", Int32](s, Int32(F_GETFL), Int32(0))
    print("current flags:", flags)
    var rv = external_call["fcntl", Int32](s, Int32(F_SETFL), Int32(flags | O_NONBLOCK))
    print("set nonblock rv:", rv)
    # Register socket in epoll. epoll_event is { u32 events; u64 data } packed = 12 bytes
    var ev = InlineArray[UInt8, 12](fill=0)
    # events = EPOLLIN | EPOLLOUT (LE)
    ev[0] = UInt8(EPOLLIN | EPOLLOUT)
    # data union = fd at offset 4 (we store the fd as int32 in the low 4 bytes of data)
    var fd_bytes = UInt32(s)
    ev[4] = UInt8(fd_bytes & 0xFF)
    ev[5] = UInt8((fd_bytes >> 8) & 0xFF)
    ev[6] = UInt8((fd_bytes >> 16) & 0xFF)
    ev[7] = UInt8((fd_bytes >> 24) & 0xFF)
    var rv2 = external_call["epoll_ctl", Int32](epfd, Int32(EPOLL_CTL_ADD), s, ev.unsafe_ptr())
    print("epoll_ctl ADD rv:", rv2)
    # epoll_wait with timeout=0 (immediate return)
    var events = InlineArray[UInt8, 12 * 64](fill=0)
    var n = external_call["epoll_wait", Int32](epfd, events.unsafe_ptr(), Int32(64), Int32(0))
    print("epoll_wait n=", n)
    _ = external_call["close", Int32](s)
    _ = external_call["close", Int32](epfd)
