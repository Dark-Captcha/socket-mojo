from std.ffi import external_call
from std.memory import UnsafePointer

def main() raises:
    var fd = external_call["socket", Int32](Int32(2), Int32(1), Int32(0))
    print("socket fd:", fd)
    var addr = InlineArray[UInt8, 16](fill=0)
    addr[0] = 2     # AF_INET, low byte (sin_family u16 LE)
    addr[1] = 0
    addr[2] = 0     # port BE: 80 = 0x0050
    addr[3] = 80
    addr[4] = 127   # 127.0.0.1
    addr[5] = 0
    addr[6] = 0
    addr[7] = 1
    var rv = external_call["connect", Int32](
        fd, addr.unsafe_ptr(), UInt32(16),
    )
    # errno via __errno_location
    var ep = external_call["__errno_location", UnsafePointer[Int32, MutAnyOrigin]]()
    print("connect rv:", rv, "errno:", ep[])
    _ = external_call["close", Int32](fd)
