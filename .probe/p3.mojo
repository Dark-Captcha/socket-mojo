from std.ffi import external_call
from std.memory import UnsafePointer, memcpy

def main() raises:
    var fd = external_call["socket", Int32](Int32(2), Int32(1), Int32(0))
    print("fd:", fd)
    var addr = InlineArray[UInt8, 16](fill=0)
    addr[0] = 2
    addr[1] = 0
    addr[2] = UInt8(19998 >> 8)  # 0x4E
    addr[3] = UInt8(19998 & 0xFF)  # 0x1F
    addr[4] = 127; addr[5] = 0; addr[6] = 0; addr[7] = 1
    var rv = external_call["connect", Int32](fd, addr.unsafe_ptr(), UInt32(16))
    print("connect:", rv)
    # send
    var msg = "Hello socket-mojo!".as_bytes()
    var n = external_call["send", Int](fd, msg.unsafe_ptr(), len(msg), Int32(0))
    print("send:", n)
    # recv
    var buf = List[UInt8](length=64, fill=0)
    var r = external_call["recv", Int](fd, buf.unsafe_ptr(), len(buf), Int32(0))
    print("recv:", r)
    # print as string
    var got = List[UInt8](capacity=r)
    for i in range(r):
        got.append(buf[i])
    print("got:", String(unsafe_from_utf8=got))
    _ = external_call["close", Int32](fd)
