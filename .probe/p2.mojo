# Probe: build a sockaddr_in in memory and connect() to 127.0.0.1:80
# (will fail with ECONNREFUSED on most boxes — what we test is whether
# the syscall is reachable and returns the right errno).
from std.ffi import external_call
from std.memory import UnsafePointer

comptime AF_INET = 2
comptime SOCK_STREAM = 1

def errno() -> Int32:
    # glibc: __errno_location() returns &errno
    var p = external_call["__errno_location", UnsafePointer[Int32]]()
    return p[]

def main() raises:
    var fd = external_call["socket", Int32](Int32(AF_INET), Int32(SOCK_STREAM), Int32(0))
    print("socket fd:", fd)
    # sockaddr_in is 16 bytes:
    #   [0..2]   sin_family = AF_INET = 2 (host-byte-order; on Linux x86 this is 0x0200 stored LE)
    #   [2..4]   sin_port   = htons(80) = 0x5000
    #   [4..8]   sin_addr   = 127.0.0.1 = 0x7F 0x00 0x00 0x01 (network byte order = big-endian)
    #   [8..16]  zero padding
    var addr = InlineArray[UInt8, 16](fill=0)
    addr[0] = 2   # AF_INET (little end of sin_family u16)
    addr[1] = 0
    # port = 80 in network byte order
    addr[2] = 0
    addr[3] = 80
    # ip 127.0.0.1
    addr[4] = 127
    addr[5] = 0
    addr[6] = 0
    addr[7] = 1
    var rv = external_call["connect", Int32](
        fd, addr.unsafe_ptr(), Int32(16),
    )
    print("connect rv:", rv, "errno:", errno())
    # errno meanings: 111 = ECONNREFUSED, 113 = EHOSTUNREACH, 101 = ENETUNREACH, 110 = ETIMEDOUT
    _ = external_call["close", Int32](fd)
