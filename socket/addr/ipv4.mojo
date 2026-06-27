# IPv4 address value type (RFC 791, 1981 — Internet Protocol).
#
# A 32-bit address stored as four octets. Pure Mojo, no syscalls. Dotted-
# quad parsing is strict-decimal: leading zeros are rejected ("01.2.3.4" →
# error) to avoid the octal-vs-decimal ambiguity classic resolvers inherit
# from inet_aton.
#
# NOT implemented: classful (A/B/C) semantics, CIDR prefixes, the historical
# inet_aton short forms ("127.1", "0x7f.0.0.1"), broadcast/multicast
# classification. This is a pure address container + canonical dotted-quad
# codec.


struct Ipv4Address(Copyable, ImplicitlyCopyable, Movable):
    """An IPv4 address — four octets, big-endian network order in
    `octets[0..4]`."""

    var octets: InlineArray[UInt8, 4]

    def __init__(out self, octets: InlineArray[UInt8, 4]):
        self.octets = octets

    def __init__(out self, a: UInt8, b: UInt8, c: UInt8, d: UInt8):
        self.octets = InlineArray[UInt8, 4](fill=0)
        self.octets[0] = a
        self.octets[1] = b
        self.octets[2] = c
        self.octets[3] = d

    @staticmethod
    def loopback() -> Ipv4Address:
        """127.0.0.1."""
        return Ipv4Address(127, 0, 0, 1)

    @staticmethod
    def any() -> Ipv4Address:
        """0.0.0.0 — the wildcard / unspecified address."""
        return Ipv4Address(0, 0, 0, 0)

    def is_loopback(self) -> Bool:
        """Any address in 127.0.0.0/8 (RFC 1122 §3.2.1.3)."""
        return self.octets[0] == 127

    def __eq__(self, other: Ipv4Address) -> Bool:
        for i in range(4):
            if self.octets[i] != other.octets[i]:
                return False
        return True

    def __ne__(self, other: Ipv4Address) -> Bool:
        return not (self == other)

    def to_string(self) -> String:
        # Build the dotted-quad into one byte buffer (no per-segment String
        # reallocation).
        var out = List[UInt8](capacity=15)
        for i in range(4):
            if i > 0:
                out.append(UInt8(ord(".")))
            var v = Int(self.octets[i])
            if v >= 100:
                out.append(UInt8(ord("0") + v // 100))
            if v >= 10:
                out.append(UInt8(ord("0") + (v // 10) % 10))
            out.append(UInt8(ord("0") + v % 10))
        return String(unsafe_from_utf8=out)


def parse_ipv4(text: String) raises -> Ipv4Address:
    """Parse a dotted-quad IPv4 string. Strict: leading zeros are
    rejected ("01.2.3.4" → error) to avoid octal-vs-decimal ambiguity."""
    var parts = text.split(".")
    if len(parts) != 4:
        raise Error("socket.addr: IPv4 requires four dot-separated octets")
    var octets = InlineArray[UInt8, 4](fill=0)
    for i in range(4):
        var s = String(parts[i])
        if s.byte_length() == 0:
            raise Error("socket.addr: empty octet")
        if s.byte_length() > 1 and s.as_bytes()[0] == UInt8(ord("0")):
            raise Error("socket.addr: leading-zero octet")
        var sb = s.as_bytes()
        for j in range(len(sb)):
            if sb[j] < UInt8(ord("0")) or sb[j] > UInt8(ord("9")):
                raise Error("socket.addr: non-digit in octet")
        var v = Int(s)
        if v < 0 or v > 255:
            raise Error("socket.addr: octet out of range 0..255")
        octets[i] = UInt8(v)
    return Ipv4Address(octets)
