# SocketAddr — a sum of `Ipv4Address` (RFC 791) and `Ipv6Address`
# (RFC 8200) paired with a 16-bit port. The variant is discriminated by
# `AddressFamily` (NOT a bool): `.kind()` reports it, `.as_v4()`/`.as_v6()`
# project to the typed address (raising on the wrong variant). This is the
# unifying type for a heterogeneous address list — DNS returns a mix of A
# (v4) and AAAA (v6) records, which only a sum type can hold.
#
# This module also owns the kernel sockaddr serialization: `write_sockaddr`
# / `read_sockaddr` translate a `SocketAddr` to/from the Linux UAPI
# `sockaddr_in` (16 B) / `sockaddr_in6` (28 B) layouts, dispatching on the
# family. They live here (not in `_syscalls`) so the low-level syscall
# module stays free of any dependency on the address types.

from socket._syscalls import AF_INET, AF_INET6, SOCKADDR_STORAGE_SIZE
from socket.addr.family import AddressFamily
from socket.addr.ipv4 import Ipv4Address, parse_ipv4
from socket.addr.ipv6 import Ipv6Address, parse_ipv6


struct SocketAddr(Copyable, ImplicitlyCopyable, Movable):
    """An IPv4 or IPv6 address paired with a 16-bit port. Construct via
    `SocketAddr.v4(addr, port)` / `SocketAddr.v6(addr, port)`; discriminate
    via `.kind()` and project via `.as_v4()` / `.as_v6()`."""

    var family: AddressFamily
    # Exactly one variant is live (per `family`); the other holds a zero
    # value. This keeps the type register-friendly without a tagged-pointer.
    # Private storage so the `v4` / `v6` static constructors don't collide.
    var _v4: Ipv4Address
    var _v6: Ipv6Address
    var port: UInt16

    def __init__(
        out self,
        family: AddressFamily,
        v4_addr: Ipv4Address,
        v6_addr: Ipv6Address,
        port: UInt16,
    ):
        self.family = family
        self._v4 = v4_addr
        self._v6 = v6_addr
        self.port = port

    @staticmethod
    def v4(addr: Ipv4Address, port: UInt16) -> SocketAddr:
        return SocketAddr(AddressFamily.V4, addr, Ipv6Address.any(), port)

    @staticmethod
    def v6(addr: Ipv6Address, port: UInt16) -> SocketAddr:
        return SocketAddr(AddressFamily.V6, Ipv4Address.any(), addr, port)

    def kind(self) -> AddressFamily:
        return self.family

    def as_v4(self) raises -> Ipv4Address:
        """The IPv4 variant; raises if this is a v6 address."""
        if self.family != AddressFamily.V4:
            raise Error("socket.addr: SocketAddr is not IPv4 (it is v6)")
        return self._v4

    def as_v6(self) raises -> Ipv6Address:
        """The IPv6 variant; raises if this is a v4 address."""
        if self.family != AddressFamily.V6:
            raise Error("socket.addr: SocketAddr is not IPv6 (it is v4)")
        return self._v6

    def with_port(self, port: UInt16) -> SocketAddr:
        """A copy of this address with a different port. Used to stamp the
        connect/bind port onto an address that came out of DNS (port 0)."""
        return SocketAddr(self.family, self._v4, self._v6, port)

    def is_loopback(self) -> Bool:
        if self.family == AddressFamily.V6:
            return self._v6.is_loopback()
        return self._v4.is_loopback()

    def ip_string(self) -> String:
        """Just the address half (no port / brackets)."""
        if self.family == AddressFamily.V6:
            return self._v6.to_string()
        return self._v4.to_string()

    def __eq__(self, other: SocketAddr) -> Bool:
        if self.family != other.family or self.port != other.port:
            return False
        if self.family == AddressFamily.V6:
            return self._v6 == other._v6
        return self._v4 == other._v4

    def __ne__(self, other: SocketAddr) -> Bool:
        return not (self == other)

    @staticmethod
    def parse(text: String) raises -> SocketAddr:
        """Parses "ip:port" or "[v6]:port" forms."""
        var tb = text.as_bytes()
        if len(tb) > 0 and tb[0] == UInt8(ord("[")):
            var rbracket = text.find("]")
            if rbracket < 0:
                raise Error("socket.addr: missing ']' in '[v6]:port'")
            var ip6 = parse_ipv6(String(text[byte=1:rbracket]))
            if rbracket + 1 >= len(tb) or tb[rbracket + 1] != UInt8(ord(":")):
                raise Error("socket.addr: missing ':port' after ']'")
            var port = _parse_port(String(text[byte = rbracket + 2 : len(tb)]))
            return SocketAddr.v6(ip6, port)
        var first_colon = text.find(":")
        if first_colon < 0:
            raise Error("socket.addr: missing ':port'")
        # More than one colon and no brackets => ambiguous bare IPv6;
        # require the '[v6]:port' form to attach a port to an IPv6 literal.
        if text.find(":", first_colon + 1) >= 0:
            raise Error("socket.addr: bracket IPv6 as '[v6]:port'")
        var colon = first_colon
        var addr = parse_ip(String(text[byte=0:colon]))
        var port = _parse_port(String(text[byte = colon + 1 : len(tb)]))
        return addr.with_port(port)

    def to_string(self) -> String:
        # Build "[ip]:port" / "ip:port" into one buffer, then convert once.
        var ip_str = self.ip_string()
        var ip_bytes = ip_str.as_bytes()
        var port = Int(self.port)
        var buf = List[UInt8](capacity=48)
        if self.family == AddressFamily.V6:
            buf.append(UInt8(ord("[")))
            buf.extend(ip_bytes)
            buf.append(UInt8(ord("]")))
        else:
            buf.extend(ip_bytes)
        buf.append(UInt8(ord(":")))
        # Port is 0..65535; emit minimal width.
        if port < 10:
            buf.append(UInt8(ord("0")) + UInt8(port))
        elif port < 100:
            buf.append(UInt8(ord("0")) + UInt8(port // 10))
            buf.append(UInt8(ord("0")) + UInt8(port % 10))
        elif port < 1000:
            buf.append(UInt8(ord("0")) + UInt8(port // 100))
            buf.append(UInt8(ord("0")) + UInt8((port // 10) % 10))
            buf.append(UInt8(ord("0")) + UInt8(port % 10))
        elif port < 10000:
            buf.append(UInt8(ord("0")) + UInt8(port // 1000))
            buf.append(UInt8(ord("0")) + UInt8((port // 100) % 10))
            buf.append(UInt8(ord("0")) + UInt8((port // 10) % 10))
            buf.append(UInt8(ord("0")) + UInt8(port % 10))
        else:
            buf.append(UInt8(ord("0")) + UInt8(port // 10000))
            buf.append(UInt8(ord("0")) + UInt8((port // 1000) % 10))
            buf.append(UInt8(ord("0")) + UInt8((port // 100) % 10))
            buf.append(UInt8(ord("0")) + UInt8((port // 10) % 10))
            buf.append(UInt8(ord("0")) + UInt8(port % 10))
        return String(unsafe_from_utf8=buf)


def parse_ip(text: String) raises -> SocketAddr:
    """Auto-detect a bare IP literal (no port) into a `SocketAddr` with
    port 0: colon present → IPv6, else dot present → IPv4, else error. The
    sum return type is what lets a single call site accept either family."""
    var has_dot = text.find(".") >= 0
    var has_colon = text.find(":") >= 0
    if has_colon:
        return SocketAddr.v6(parse_ipv6(text), 0)
    if has_dot:
        return SocketAddr.v4(parse_ipv4(text), 0)
    raise Error("socket.addr: not an IP address: '" + text + "'")


def _parse_port(text: String) raises -> UInt16:
    if text.byte_length() == 0:
        raise Error("socket.addr: empty port")
    var sb = text.as_bytes()
    # Bound the length first so an overlong digit string surfaces the
    # domain error here rather than Int()'s generic conversion failure.
    if len(sb) > 5:
        raise Error("socket.addr: port out of range 0..65535")
    for i in range(len(sb)):
        if sb[i] < UInt8(ord("0")) or sb[i] > UInt8(ord("9")):
            raise Error("socket.addr: non-digit in port")
    var v = Int(text)
    if v < 0 or v > 65535:
        raise Error("socket.addr: port out of range 0..65535")
    return UInt16(v)


# --- kernel sockaddr serialization ------------------------------------


def write_sockaddr[
    O: Origin[mut=True]
](out_buf: UnsafePointer[UInt8, O], addr: SocketAddr) -> UInt32:
    """Serialise `addr` into the kernel's `sockaddr_in[6]` layout,
    dispatching on the address family. Returns the byte length the kernel
    expects (16 for IPv4, 28 for IPv6)."""
    for i in range(SOCKADDR_STORAGE_SIZE):
        out_buf[i] = 0
    var port = addr.port
    if addr.family != AddressFamily.V6:
        # struct sockaddr_in:
        #   [0..2]   sin_family (host order; LE on x86 → 0x02 0x00)
        #   [2..4]   sin_port   (network = big-endian)
        #   [4..8]   sin_addr   (network)
        #   [8..16]  zero padding
        out_buf[0] = UInt8(AF_INET)
        out_buf[1] = 0
        out_buf[2] = UInt8((port >> 8) & 0xFF)
        out_buf[3] = UInt8(port & 0xFF)
        out_buf[4] = addr._v4.octets[0]
        out_buf[5] = addr._v4.octets[1]
        out_buf[6] = addr._v4.octets[2]
        out_buf[7] = addr._v4.octets[3]
        return 16
    # struct sockaddr_in6:
    #   [0..2]   sin6_family
    #   [2..4]   sin6_port      (BE)
    #   [4..8]   sin6_flowinfo
    #   [8..24]  sin6_addr      (16 B, network)
    #   [24..28] sin6_scope_id
    out_buf[0] = UInt8(AF_INET6)
    out_buf[1] = 0
    out_buf[2] = UInt8((port >> 8) & 0xFF)
    out_buf[3] = UInt8(port & 0xFF)
    for i in range(16):
        out_buf[8 + i] = addr._v6.octets[i]
    return 28


def read_sockaddr(buf: UnsafePointer[UInt8, _]) -> SocketAddr:
    """Inverse of `write_sockaddr`: decode a kernel sockaddr into a typed
    `SocketAddr`."""
    var family = buf[0]
    var port = (UInt16(buf[2]) << 8) | UInt16(buf[3])
    if family == UInt8(AF_INET6):
        var octets = InlineArray[UInt8, 16](fill=0)
        for i in range(16):
            octets[i] = buf[8 + i]
        return SocketAddr.v6(Ipv6Address(octets), port)
    return SocketAddr.v4(Ipv4Address(buf[4], buf[5], buf[6], buf[7]), port)
