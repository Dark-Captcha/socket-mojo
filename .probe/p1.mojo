# Probe libc socket FFI: can we call socket(), bind a port, set
# sockopt, get the assigned port back, close?
from std.ffi import external_call
from std.memory import UnsafePointer

comptime AF_INET = 2
comptime SOCK_STREAM = 1
comptime SOL_SOCKET = 1
comptime SO_REUSEADDR = 2

def main() raises:
    var fd = external_call["socket", Int32](Int32(AF_INET), Int32(SOCK_STREAM), Int32(0))
    print("socket fd:", fd)
    if fd < 0:
        raise Error("socket failed")
    # setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, 4)
    var one = Int32(1)
    var rv = external_call["setsockopt", Int32](
        fd, Int32(SOL_SOCKET), Int32(SO_REUSEADDR),
        UnsafePointer(to=one), Int32(4),
    )
    print("setsockopt rv:", rv)
    var crv = external_call["close", Int32](fd)
    print("close rv:", crv)
