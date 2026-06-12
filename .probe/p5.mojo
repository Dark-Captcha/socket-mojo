from std.ffi import external_call
from std.memory import UnsafePointer
def main():
    # The "service" arg is char*; can we pass UInt(0) for NULL?
    var hostz = "127.0.0.1\0".as_bytes()
    var hints = InlineArray[UInt8, 48](fill=0)
    hints[8] = 1   # SOCK_STREAM
    var result_storage = InlineArray[UInt8, 8](fill=0)  # pointer-sized slot
    var rv = external_call["getaddrinfo", Int32](
        hostz.unsafe_ptr(),
        UInt(0),  # NULL service
        hints.unsafe_ptr(),
        result_storage.unsafe_ptr(),
    )
    print("rv:", rv)
    # Read pointer back from the 8-byte slot
    var w = UInt64(0)
    for i in range(8):
        w |= UInt64(result_storage[i]) << UInt64(8 * i)
    print("res ptr:", hex(Int(w)))
    if w != 0:
        external_call["freeaddrinfo", NoneType](UInt(w))
