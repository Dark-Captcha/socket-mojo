# DNS resolution via libc `getaddrinfo`. Synchronous and blocking, like
# every other v0 entry point. The function follows the system resolver
# (`/etc/resolv.conf` on Linux), so it inherits whatever DNS-over-TLS /
# resolved / mDNS configuration is in place.
#
# For literal IP strings (`127.0.0.1`, `::1`) we short-circuit and skip
# the resolver entirely.
#
# Pointer handling note: this Mojo nightly's `UnsafePointer` is non-
# nullable, so we never construct one from `nullptr`. Foreign pointers
# the C ABI hands back through out-params land in an 8-byte InlineArray
# slot; we read them as a `UInt64` and only convert to an
# UnsafePointer-shaped UInt when handing them straight back to libc
# (`freeaddrinfo`). The byte-by-byte poke into `struct addrinfo` works
# because we only ever read it.

from std.ffi import external_call

from socket._libc import AF_INET, AF_INET6, AF_UNSPEC, SOCK_STREAM
from socket.addr import IpAddress, parse_ip


# struct addrinfo on Linux glibc (48 bytes; offsets matter):
#   [0..4]   ai_flags     int
#   [4..8]   ai_family    int
#   [8..12]  ai_socktype  int
#   [12..16] ai_protocol  int
#   [16..20] ai_addrlen   socklen_t (uint32)
#   [20..24] padding
#   [24..32] ai_addr      sockaddr*
#   [32..40] ai_canonname char*
#   [40..48] ai_next      addrinfo*


@always_inline
def _load_u64_le(buf: InlineArray[UInt8, 8]) -> UInt64:
    var w = UInt64(0)
    for i in range(8):
        w |= UInt64(buf[i]) << UInt64(8 * i)
    return w


@always_inline
def _read_u8_at_addr(addr: UInt64, offset: Int) -> UInt8:
    """Treat `addr` as a raw foreign pointer and read one byte at
    `addr + offset`. Used to walk the libc-allocated addrinfo linked
    list without ever constructing an UnsafePointer through `nullptr`.
    """
    # We bridge through libc memcpy: copy 1 byte from (addr+offset) into
    # a local stack slot. This avoids any UnsafePointer construction
    # for the unknown remote address.
    var slot = InlineArray[UInt8, 1](fill=0)
    _ = external_call["memcpy", UInt](
        slot.unsafe_ptr(),
        UInt(Int(addr) + offset),
        UInt(1),
    )
    return slot[0]


@always_inline
def _read_u32_at_addr(addr: UInt64, offset: Int) -> UInt32:
    var slot = InlineArray[UInt8, 4](fill=0)
    _ = external_call["memcpy", UInt](
        slot.unsafe_ptr(),
        UInt(Int(addr) + offset),
        UInt(4),
    )
    return (
        UInt32(slot[0])
        | (UInt32(slot[1]) << 8)
        | (UInt32(slot[2]) << 16)
        | (UInt32(slot[3]) << 24)
    )


@always_inline
def _read_u64_at_addr(addr: UInt64, offset: Int) -> UInt64:
    var slot = InlineArray[UInt8, 8](fill=0)
    _ = external_call["memcpy", UInt](
        slot.unsafe_ptr(),
        UInt(Int(addr) + offset),
        UInt(8),
    )
    return _load_u64_le(slot)


def resolve(host: String) raises -> List[IpAddress]:
    """Resolve `host` to a list of IP addresses. Literal IPs short-
    circuit. Raises with prefix `socket.dns:` on failure."""
    # Literal-IP fast path.
    try:
        var literal = parse_ip(host)
        var out = List[IpAddress]()
        out.append(literal)
        return out^
    except:
        pass

    # NUL-terminated host name for libc.
    var host_c = List[UInt8](capacity=host.byte_length() + 1)
    host_c.extend(host.as_bytes())
    host_c.append(0)

    var hints = InlineArray[UInt8, 48](fill=0)
    # ai_family = AF_UNSPEC (0), ai_socktype = SOCK_STREAM (1)
    hints[8] = UInt8(SOCK_STREAM)

    # `res` is an `out` pointer-to-pointer; stash the 8-byte foreign
    # pointer libc writes here in an InlineArray.
    var res_slot = InlineArray[UInt8, 8](fill=0)
    var rv = external_call["getaddrinfo", Int32](
        host_c.unsafe_ptr(),
        UInt(0),  # service = NULL
        hints.unsafe_ptr(),
        res_slot.unsafe_ptr(),
    )
    if rv != 0:
        raise Error(
            "socket.dns: getaddrinfo('"
            + host
            + "') failed with code "
            + String(Int(rv))
        )
    var head = _load_u64_le(res_slot)
    var out = List[IpAddress]()
    var node = head
    while node != 0:
        var family = _read_u32_at_addr(node, 4)
        var addr_ptr = _read_u64_at_addr(node, 24)  # ai_addr
        if family == UInt32(AF_INET):
            # sockaddr_in: family(2) | port(2) | inaddr(4) | pad(8)
            var b0 = _read_u8_at_addr(addr_ptr, 4)
            var b1 = _read_u8_at_addr(addr_ptr, 5)
            var b2 = _read_u8_at_addr(addr_ptr, 6)
            var b3 = _read_u8_at_addr(addr_ptr, 7)
            out.append(IpAddress.v4(b0, b1, b2, b3))
        elif family == UInt32(AF_INET6):
            # sockaddr_in6: family(2) | port(2) | flowinfo(4) | addr(16) | scope(4)
            var bytes16 = InlineArray[UInt8, 16](fill=0)
            for i in range(16):
                bytes16[i] = _read_u8_at_addr(addr_ptr, 8 + i)
            out.append(IpAddress(True, bytes16))
        # else: skip unknown families (AF_PACKET, etc.)
        node = _read_u64_at_addr(node, 40)  # ai_next
    _ = external_call["freeaddrinfo", NoneType](UInt(Int(head)))
    return out^
