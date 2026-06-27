# IPv6 address value type (RFC 8200, 2017 — IPv6 spec; RFC 4291 addressing
# architecture; RFC 5952 text representation).
#
# A 128-bit address stored as sixteen octets. Pure Mojo, no syscalls. The
# parser supports `::` zero-run compression (at most one per address) and
# the embedded-IPv4 tail (`::ffff:1.2.3.4`, and the uncompressed
# `1:2:3:4:5:6:1.2.3.4` form).
#
# NOT implemented: scope/zone IDs (`fe80::1%eth0`), `::` run *elision* in
# `to_string` (groups are emitted in full with per-group leading-zero
# stripping, which is uniquely decodable but not the shortest RFC 5952
# canonical form), IPv4-mapped detection helpers.

from socket.addr.ipv4 import parse_ipv4


struct Ipv6Address(Copyable, ImplicitlyCopyable, Movable):
    """An IPv6 address — sixteen octets, big-endian network order in
    `octets[0..16]`."""

    var octets: InlineArray[UInt8, 16]

    def __init__(out self, octets: InlineArray[UInt8, 16]):
        self.octets = octets

    @staticmethod
    def from_bytes(bytes16: Span[UInt8, _]) raises -> Ipv6Address:
        if len(bytes16) != 16:
            raise Error("socket.addr: IPv6 address requires 16 bytes")
        var o = InlineArray[UInt8, 16](fill=0)
        for i in range(16):
            o[i] = bytes16[i]
        return Ipv6Address(o)

    @staticmethod
    def loopback() -> Ipv6Address:
        """::1."""
        var o = InlineArray[UInt8, 16](fill=0)
        o[15] = 1
        return Ipv6Address(o)

    @staticmethod
    def any() -> Ipv6Address:
        """:: — the unspecified address (all zero)."""
        return Ipv6Address(InlineArray[UInt8, 16](fill=0))

    def is_loopback(self) -> Bool:
        """::1 (RFC 4291 §2.5.3)."""
        var leading = UInt8(0)
        for i in range(15):
            leading |= self.octets[i]
        return leading == 0 and self.octets[15] == 1

    def __eq__(self, other: Ipv6Address) -> Bool:
        for i in range(16):
            if self.octets[i] != other.octets[i]:
                return False
        return True

    def __ne__(self, other: Ipv6Address) -> Bool:
        return not (self == other)

    def to_string(self) -> String:
        # Render as 8 groups of 16 bits in hex with per-group leading-zero
        # stripping. No `::` run elision (purely cosmetic; the value is still
        # uniquely encoded).
        var hexchars = "0123456789abcdef".as_bytes()
        var out = List[UInt8](capacity=39)
        for grp in range(8):
            if grp > 0:
                out.append(UInt8(ord(":")))
            var hi = self.octets[2 * grp]
            var lo = self.octets[2 * grp + 1]
            var combined = (UInt32(hi) << 8) | UInt32(lo)
            var nibble3 = Int((combined >> 12) & 0xF)
            var nibble2 = Int((combined >> 8) & 0xF)
            var nibble1 = Int((combined >> 4) & 0xF)
            var nibble0 = Int(combined & 0xF)
            if nibble3 != 0:
                out.append(hexchars[nibble3])
            if nibble3 != 0 or nibble2 != 0:
                out.append(hexchars[nibble2])
            if nibble3 != 0 or nibble2 != 0 or nibble1 != 0:
                out.append(hexchars[nibble1])
            out.append(hexchars[nibble0])
        return String(unsafe_from_utf8=out)


def _hex_nibble(c: UInt8) raises -> UInt8:
    if c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
        return c - UInt8(ord("0"))
    if c >= UInt8(ord("a")) and c <= UInt8(ord("f")):
        return c - UInt8(ord("a")) + 10
    if c >= UInt8(ord("A")) and c <= UInt8(ord("F")):
        return c - UInt8(ord("A")) + 10
    raise Error("socket.addr: invalid hex digit in IPv6")


def _parse_ipv6_group(s: String) raises -> UInt16:
    if s.byte_length() == 0 or s.byte_length() > 4:
        raise Error("socket.addr: IPv6 group must be 1..4 hex digits")
    var v = UInt16(0)
    var sb = s.as_bytes()
    for i in range(len(sb)):
        v = (v << 4) | UInt16(_hex_nibble(sb[i]))
    return v


def _parse_ipv6_segment(
    seg: String, mut groups: List[UInt16], mut v4: InlineArray[UInt8, 4]
) raises -> Bool:
    """Parse a colon-separated segment into `groups`, claiming an embedded
    IPv4 in its LAST piece (written into `v4`) if present. Returns True if
    a v4 tail was found. Applies to BOTH the head (no `::`) and the tail
    (after `::`), so `1:2:3:4:5:6:1.2.3.4` parses as well as `::ffff:1.2.3.4`.
    """
    if seg.byte_length() == 0:
        return False
    var pieces = List[String]()
    for piece_str in seg.split(":"):
        pieces.append(String(piece_str))
    var has_v4 = False
    var last = pieces[len(pieces) - 1]
    if last.find(".") >= 0:
        var v = parse_ipv4(last)
        v4[0] = v.octets[0]
        v4[1] = v.octets[1]
        v4[2] = v.octets[2]
        v4[3] = v.octets[3]
        has_v4 = True
        _ = pieces.pop()
    for piece in pieces:
        if piece.byte_length() == 0:
            raise Error("socket.addr: empty IPv6 group")
        groups.append(_parse_ipv6_group(piece))
    return has_v4


def parse_ipv6(text: String) raises -> Ipv6Address:
    """Parse an RFC 5952 IPv6 string. Supports `::` compression and the
    embedded-IPv4 tail (`::ffff:1.2.3.4`)."""
    var tb = text.as_bytes()
    # Locate `::` (the run of zeros marker; at most one occurrence).
    var dcolon = -1
    var i = 0
    while i + 1 < len(tb):
        if tb[i] == UInt8(ord(":")) and tb[i + 1] == UInt8(ord(":")):
            if dcolon >= 0:
                raise Error("socket.addr: IPv6 may contain at most one '::'")
            dcolon = i
            i += 2
        else:
            i += 1
    # Split into head and tail around '::' (or the whole string if none).
    var head: String
    var tail = String("")
    if dcolon >= 0:
        head = String(text[byte=0:dcolon])
        tail = String(text[byte = dcolon + 2 : len(tb)])
    else:
        head = text
    # An embedded IPv4 at the end of `tail` (or `head` if no `::`)
    # claims the last 32 bits.
    var head_groups = List[UInt16]()
    var tail_groups = List[UInt16]()
    var tail_v4_octets = InlineArray[UInt8, 4](fill=0)
    var tail_has_v4: Bool
    if dcolon < 0:
        # Whole address is in `head`; an embedded IPv4 may be its last
        # piece (the uncompressed `1:2:3:4:5:6:1.2.3.4` form).
        tail_has_v4 = _parse_ipv6_segment(head, head_groups, tail_v4_octets)
    else:
        if head.byte_length() > 0:
            for piece_str in head.split(":"):
                var piece = String(piece_str)
                if piece.byte_length() == 0:
                    raise Error("socket.addr: empty IPv6 group")
                head_groups.append(_parse_ipv6_group(piece))
        tail_has_v4 = _parse_ipv6_segment(tail, tail_groups, tail_v4_octets)
    var v4_groups = 2 if tail_has_v4 else 0
    var total = len(head_groups) + len(tail_groups) + v4_groups
    if dcolon < 0:
        if total != 8:
            raise Error(
                "socket.addr: IPv6 must have 8 groups when no '::' present"
            )
    else:
        if total >= 8:
            # '::' must compress at least one zero group (RFC 4291/5952);
            # a full 8-group address with a '::' is invalid.
            raise Error(
                "socket.addr: '::' must compress at least one zero group"
            )
    var zero_groups = 8 - total
    var octets = InlineArray[UInt8, 16](fill=0)
    var pos = 0
    for grp in head_groups:
        octets[pos] = UInt8((grp >> 8) & 0xFF)
        octets[pos + 1] = UInt8(grp & 0xFF)
        pos += 2
    pos += 2 * zero_groups
    for grp in tail_groups:
        octets[pos] = UInt8((grp >> 8) & 0xFF)
        octets[pos + 1] = UInt8(grp & 0xFF)
        pos += 2
    if tail_has_v4:
        octets[pos] = tail_v4_octets[0]
        octets[pos + 1] = tail_v4_octets[1]
        octets[pos + 2] = tail_v4_octets[2]
        octets[pos + 3] = tail_v4_octets[3]
    return Ipv6Address(octets)
