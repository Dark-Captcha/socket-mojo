# DNS wire format (RFC 1035): pure query building and response
# parsing — the library's first sans-io protocol. No sockets, no fds;
# bytes in, records out. socket/dns.mojo drives these through the Ring
# (UDP with retry, TCP fallback on truncation).
#
# Scope: queries for A / AAAA with RD=1; response parsing decodes
# name-compression pointers (hop-bounded against pointer loops),
# verifies every record's owner against the qname -> CNAME chain (a
# resolver that collects by type alone would accept unrelated,
# potentially attacker-injected records), and surfaces the TC bit so
# the transport can retry over TCP.

from socket.addr import IpAddress

comptime QTYPE_A = UInt16(1)
comptime QTYPE_CNAME = UInt16(5)
comptime QTYPE_AAAA = UInt16(28)

comptime _CLASS_IN = UInt16(1)
comptime _MAX_NAME_HOPS = 32  # compression-pointer loop bound


struct DnsAnswer(Copyable, Movable):
    """Parsed answer section of one response."""

    var addresses: List[IpAddress]
    var truncated: Bool  # TC bit: retry the query over TCP
    var rcode: UInt8

    def __init__(out self):
        self.addresses = List[IpAddress]()
        self.truncated = False
        self.rcode = 0


def dns_build_query(
    txid: UInt16, name: String, qtype: UInt16
) raises -> List[UInt8]:
    """One-question query (RD=1). `name` is dotted form without a
    trailing dot; labels must each fit 63 bytes (RFC 1035 §2.3.4)."""
    var out = List[UInt8](capacity=12 + name.byte_length() + 6)
    out.append(UInt8(txid >> 8))
    out.append(UInt8(txid & 0xFF))
    out.append(0x01)  # RD
    out.append(0x00)
    out.append(0x00)
    out.append(0x01)  # QDCOUNT = 1
    for _ in range(6):
        out.append(0x00)  # AN/NS/AR counts
    var nb = name.as_bytes()
    var start = 0
    var encoded = 0  # wire-encoded QNAME length so far (RFC 1035 §3.1: <= 255)
    for i in range(len(nb) + 1):
        var at_end = i == len(nb)
        if at_end or nb[i] == UInt8(ord(".")):
            var label_len = i - start
            if label_len == 0 or label_len > 63:
                raise Error("socket.dnswire: bad label in '" + name + "'")
            encoded += 1 + label_len  # length octet + label octets
            if encoded > 254:  # +1 for the trailing root octet => 255 max
                raise Error("socket.dnswire: name too long: '" + name + "'")
            out.append(UInt8(label_len))
            for j in range(start, i):
                out.append(nb[j])
            start = i + 1
    out.append(0x00)  # root
    out.append(UInt8(qtype >> 8))
    out.append(UInt8(qtype & 0xFF))
    out.append(UInt8(_CLASS_IN >> 8))
    out.append(UInt8(_CLASS_IN & 0xFF))
    return out^


def _read_name(msg: Span[UInt8, _], start: Int) raises -> Tuple[String, Int]:
    """Decodes the (possibly compressed) name at `start`, following
    pointers with a hop bound. Returns (lower-cased dotted name,
    offset just past the name's bytes at the original position)."""
    # Accumulate into one byte buffer (no per-character String realloc).
    var name = List[UInt8]()
    var off = start
    var next_off = -1  # set when the first pointer is taken
    var hops = 0
    while True:
        if off >= len(msg):
            raise Error("socket.dnswire: truncated name")
        var n = Int(msg[off])
        if n == 0:
            if next_off < 0:
                next_off = off + 1
            return (String(unsafe_from_utf8=name), next_off)
        if n >= 0xC0:
            if off + 1 >= len(msg):
                raise Error("socket.dnswire: truncated pointer")
            if next_off < 0:
                next_off = off + 2
            hops += 1
            if hops > _MAX_NAME_HOPS:
                raise Error("socket.dnswire: compression pointer loop")
            off = ((n & 0x3F) << 8) | Int(msg[off + 1])
            continue
        if n > 63:
            raise Error("socket.dnswire: bad label length")
        # Bound the label content against the message before reading it
        # (the loop below reads up to msg[off + n]).
        if off + 1 + n > len(msg):
            raise Error("socket.dnswire: truncated label")
        if len(name) > 0:
            name.append(UInt8(ord(".")))
        for i in range(n):
            var c = msg[off + 1 + i]
            if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
                c += 32
            name.append(c)
        if len(name) > 255:
            raise Error("socket.dnswire: name too long")
        off += 1 + n


def _lower_ascii(s: String) -> String:
    """Fold ASCII A-Z to a-z so a queried host compares equal to the
    lowercased name _read_name produces (DNS names are ASCII)."""
    var nb = s.as_bytes()
    var out = List[UInt8](capacity=len(nb))
    for i in range(len(nb)):
        var c = nb[i]
        if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
            c += 32
        out.append(c)
    return String(unsafe_from_utf8=out)


def dns_parse_response(
    msg: Span[UInt8, _], expect_txid: UInt16, qtype: UInt16, expect_qname: String
) raises -> DnsAnswer:
    """Validates the header against the query and walks the answer
    section, following CNAMEs within the message. Raises on malformed
    or mismatched packets (including a question that does not echo the
    queried name/type/class); NXDOMAIN and friends come back via rcode."""
    if len(msg) < 12:
        raise Error("socket.dnswire: short response")
    var txid = (UInt16(msg[0]) << 8) | UInt16(msg[1])
    if txid != expect_txid:
        raise Error("socket.dnswire: transaction id mismatch")
    var flags_hi = msg[2]
    if (flags_hi & 0x80) == 0:
        raise Error("socket.dnswire: not a response (QR=0)")
    var out = DnsAnswer()
    out.truncated = (flags_hi & 0x02) != 0
    out.rcode = msg[3] & 0x0F
    var qdcount = (UInt16(msg[4]) << 8) | UInt16(msg[5])
    var ancount = (UInt16(msg[6]) << 8) | UInt16(msg[7])
    if qdcount != 1:
        raise Error("socket.dnswire: unexpected question count")
    # question: capture the canonical qname, verify it echoes the queried
    # host, and verify the qtype/qclass echo
    var q = _read_name(msg, 12)
    var current = q[0]
    if current != _lower_ascii(expect_qname):
        raise Error("socket.dnswire: question name mismatch")
    var qend = q[1]
    if qend + 4 > len(msg):
        raise Error("socket.dnswire: truncated question")
    var rq_type = (UInt16(msg[qend]) << 8) | UInt16(msg[qend + 1])
    var rq_class = (UInt16(msg[qend + 2]) << 8) | UInt16(msg[qend + 3])
    if rq_type != qtype or rq_class != _CLASS_IN:
        raise Error("socket.dnswire: question type/class mismatch")
    var off = qend + 4
    # answers: follow the qname -> CNAME chain, collect matching types
    for _ in range(Int(ancount)):
        var owner_and_off = _read_name(msg, off)
        var owner = owner_and_off[0]
        off = owner_and_off[1]
        if off + 10 > len(msg):
            raise Error("socket.dnswire: truncated answer header")
        var rtype = (UInt16(msg[off]) << 8) | UInt16(msg[off + 1])
        var rdlen = Int((UInt16(msg[off + 8]) << 8) | UInt16(msg[off + 9]))
        off += 10
        if off + rdlen > len(msg):
            raise Error("socket.dnswire: truncated rdata")
        if owner == current:
            if rtype == QTYPE_CNAME:
                var t = _read_name(msg, off)
                current = t[0]
            elif rtype == qtype and qtype == QTYPE_A and rdlen == 4:
                out.addresses.append(
                    IpAddress.v4(
                        msg[off], msg[off + 1], msg[off + 2], msg[off + 3]
                    )
                )
            elif rtype == qtype and qtype == QTYPE_AAAA and rdlen == 16:
                var oct = InlineArray[UInt8, 16](fill=0)
                for i in range(16):
                    oct[i] = msg[off + i]
                out.addresses.append(IpAddress(True, oct))
        off += rdlen
    return out^
