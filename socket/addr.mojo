# IP address and socket-address value types. Pure Mojo, no FFI.
#
# IpAddress always stores 16 bytes; IPv4 fills only the first 4. The
# `is_v6` flag selects between IPv4-mapped IPv6 (`::ffff:1.2.3.4`) and
# native IPv4 representation. SocketAddr ties an IpAddress to a 16-bit
# port and is what `connect`/`bind`/`recv_from` exchange.


struct IpAddress(Copyable, ImplicitlyCopyable, Movable):
    """An IPv4 or IPv6 address."""

    var is_v6: Bool
    # IPv4 occupies octets[0..4]; the remaining 12 bytes are zero.
    var octets: InlineArray[UInt8, 16]

    def __init__(out self):
        self.is_v6 = False
        self.octets = InlineArray[UInt8, 16](fill=0)

    def __init__(out self, is_v6: Bool, octets: InlineArray[UInt8, 16]):
        self.is_v6 = is_v6
        self.octets = octets

    @staticmethod
    def v4(a: UInt8, b: UInt8, c: UInt8, d: UInt8) -> IpAddress:
        var o = InlineArray[UInt8, 16](fill=0)
        o[0] = a
        o[1] = b
        o[2] = c
        o[3] = d
        return IpAddress(False, o)

    @staticmethod
    def v6(bytes16: Span[UInt8, _]) raises -> IpAddress:
        if len(bytes16) != 16:
            raise Error("socket.addr: IPv6 address requires 16 bytes")
        var o = InlineArray[UInt8, 16](fill=0)
        for i in range(16):
            o[i] = bytes16[i]
        return IpAddress(True, o)

    @staticmethod
    def loopback_v4() -> IpAddress:
        return IpAddress.v4(127, 0, 0, 1)

    @staticmethod
    def loopback_v6() -> IpAddress:
        var o = InlineArray[UInt8, 16](fill=0)
        o[15] = 1
        return IpAddress(True, o)

    @staticmethod
    def any_v4() -> IpAddress:
        return IpAddress.v4(0, 0, 0, 0)

    @staticmethod
    def any_v6() -> IpAddress:
        return IpAddress(True, InlineArray[UInt8, 16](fill=0))

    def is_loopback(self) -> Bool:
        if not self.is_v6:
            return self.octets[0] == 127
        var leading = UInt8(0)
        for i in range(15):
            leading |= self.octets[i]
        return leading == 0 and self.octets[15] == 1

    def __eq__(self, other: IpAddress) -> Bool:
        if self.is_v6 != other.is_v6:
            return False
        var n = 16 if self.is_v6 else 4
        for i in range(n):
            if self.octets[i] != other.octets[i]:
                return False
        return True

    def __ne__(self, other: IpAddress) -> Bool:
        return not (self == other)

    def to_string(self) -> String:
        if not self.is_v6:
            # Build the dotted-quad into one byte buffer (no per-segment
            # String reallocation), matching the v6 branch below.
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
        # IPv6: render as 8 groups of 16 bits in hex. No `::` compression
        # for now (purely cosmetic; the value is still uniquely encoded).
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
            # Strip leading zeros within the group (canonical RFC 5952 form).
            if nibble3 != 0:
                out.append(hexchars[nibble3])
            if nibble3 != 0 or nibble2 != 0:
                out.append(hexchars[nibble2])
            if nibble3 != 0 or nibble2 != 0 or nibble1 != 0:
                out.append(hexchars[nibble1])
            out.append(hexchars[nibble0])
        return String(unsafe_from_utf8=out)


def parse_ipv4(text: String) raises -> IpAddress:
    """Parse a dotted-quad IPv4 string. Strict: leading zeros are
    rejected ("01.2.3.4" → error) to avoid octal-vs-decimal ambiguity."""
    var parts = text.split(".")
    if len(parts) != 4:
        raise Error("socket.addr: IPv4 requires four dot-separated octets")
    var octets = InlineArray[UInt8, 16](fill=0)
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
    return IpAddress(False, octets)


def _hex_nibble(c: UInt8) raises -> UInt8:
    if c >= UInt8(ord("0")) and c <= UInt8(ord("9")):
        return c - UInt8(ord("0"))
    if c >= UInt8(ord("a")) and c <= UInt8(ord("f")):
        return c - UInt8(ord("a")) + 10
    if c >= UInt8(ord("A")) and c <= UInt8(ord("F")):
        return c - UInt8(ord("A")) + 10
    raise Error("socket.addr: invalid hex digit in IPv6")


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


def parse_ipv6(text: String) raises -> IpAddress:
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
    return IpAddress(True, octets)


def _parse_ipv6_group(s: String) raises -> UInt16:
    if s.byte_length() == 0 or s.byte_length() > 4:
        raise Error("socket.addr: IPv6 group must be 1..4 hex digits")
    var v = UInt16(0)
    var sb = s.as_bytes()
    for i in range(len(sb)):
        v = (v << 4) | UInt16(_hex_nibble(sb[i]))
    return v


def parse_ip(text: String) raises -> IpAddress:
    """Auto-detect: dot present → IPv4 (unless also a colon, then v6),
    colon present → IPv6, else error."""
    var has_dot = text.find(".") >= 0
    var has_colon = text.find(":") >= 0
    if has_colon:
        return parse_ipv6(text)
    if has_dot:
        return parse_ipv4(text)
    raise Error("socket.addr: not an IP address: '" + text + "'")


struct SocketAddr(Copyable, ImplicitlyCopyable, Movable):
    """An IP address paired with a 16-bit port."""

    var ip: IpAddress
    var port: UInt16

    def __init__(out self, ip: IpAddress, port: UInt16):
        self.ip = ip
        self.port = port

    @staticmethod
    def parse(text: String) raises -> SocketAddr:
        """Parses "ip:port" or "[v6]:port" forms."""
        var tb = text.as_bytes()
        if len(tb) > 0 and tb[0] == UInt8(ord("[")):
            var rbracket = text.find("]")
            if rbracket < 0:
                raise Error("socket.addr: missing ']' in '[v6]:port'")
            var ip = parse_ipv6(String(text[byte=1:rbracket]))
            if rbracket + 1 >= len(tb) or tb[rbracket + 1] != UInt8(ord(":")):
                raise Error("socket.addr: missing ':port' after ']'")
            var port = _parse_port(String(text[byte = rbracket + 2 : len(tb)]))
            return SocketAddr(ip, port)
        var first_colon = text.find(":")
        if first_colon < 0:
            raise Error("socket.addr: missing ':port'")
        # More than one colon and no brackets => ambiguous bare IPv6;
        # require the '[v6]:port' form to attach a port to an IPv6 literal.
        if text.find(":", first_colon + 1) >= 0:
            raise Error("socket.addr: bracket IPv6 as '[v6]:port'")
        var colon = first_colon
        var ip = parse_ip(String(text[byte=0:colon]))
        var port = _parse_port(String(text[byte = colon + 1 : len(tb)]))
        return SocketAddr(ip, port)

    def to_string(self) -> String:
        # Build "[ip]:port" / "ip:port" into one buffer, then convert once.
        # The fragments are short (≤47 bytes for v6 with bracket+port) so the
        # initial capacity covers every legal value.
        var ip_str = self.ip.to_string()
        var ip_bytes = ip_str.as_bytes()
        var port = Int(self.port)
        var buf = List[UInt8](capacity=48)
        if self.ip.is_v6:
            buf.append(UInt8(ord("[")))
            buf.extend(ip_bytes)
            buf.append(UInt8(ord("]")))
        else:
            buf.extend(ip_bytes)
        buf.append(UInt8(ord(":")))
        # Port is 0..65535; emit minimal width with the standard /100 + table
        # chunking, but inlined here so addr.mojo has no internal deps.
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

    def __eq__(self, other: SocketAddr) -> Bool:
        return self.port == other.port and self.ip == other.ip


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
