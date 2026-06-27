# Ring-driven DNS resolver vs the deterministic truth server
# (tests/dns_server.py on 127.0.0.1:19553, UDP+TCP — start it like
# the echo peers). Exercises: multi-A answers, AAAA, CNAME chains
# with compression pointers (including an owner name that points into
# another record's rdata), TCP fallback on truncation, the UDP retry
# path, NXDOMAIN as a raised error, and the pure parser's rejection
# of malformed/mismatched packets.

from socket.addr import IpAddress, SocketAddr
from socket.dns import resolve_dns
from socket.dnswire import (
    QTYPE_A,
    QTYPE_AAAA,
    dns_build_query,
    dns_parse_response,
)

from tests.helpers import check


def _server() -> SocketAddr:
    return SocketAddr(IpAddress.v4(127, 0, 0, 1), UInt16(19553))


def _test_resolver() raises -> Int:
    var f = 0
    # two A records
    var a = resolve_dns("a.test", server=_server())
    f += check(len(a) == 2, "dns: a.test record count")
    f += check(
        a[0] == IpAddress.v4(1, 2, 3, 4) and a[1] == IpAddress.v4(5, 6, 7, 8),
        "dns: a.test addresses",
    )

    # AAAA
    var aaaa = resolve_dns("aaaa.test", server=_server(), qtype=QTYPE_AAAA)
    f += check(len(aaaa) == 1 and aaaa[0].is_v6, "dns: aaaa.test v6 answer")
    f += check(
        aaaa[0].octets[0] == 0x20
        and aaaa[0].octets[1] == 0x01
        and aaaa[0].octets[15] == 0x42,
        "dns: aaaa.test bytes",
    )

    # CNAME chain with compression pointers
    var cn = resolve_dns("cname.test", server=_server())
    f += check(
        len(cn) == 1 and cn[0] == IpAddress.v4(1, 2, 3, 4),
        "dns: cname chain followed",
    )

    # TC over UDP -> full answer over TCP
    var big = resolve_dns("big.test", server=_server())
    f += check(
        len(big) == 1 and big[0] == IpAddress.v4(9, 9, 9, 9),
        "dns: tcp fallback on truncation",
    )

    # first UDP packet dropped -> retry succeeds
    var dropped = resolve_dns(
        "retry.test", server=_server(), timeout_ms=300, retries=3
    )
    f += check(len(dropped) == 0, "dns: retry path reached the server")

    # NXDOMAIN raises
    var caught = False
    try:
        _ = resolve_dns("nx.test", server=_server())
    except:
        caught = True
    f += check(caught, "dns: nxdomain raises")

    # literal IP short-circuit
    var lit = resolve_dns("203.0.113.7", server=_server())
    f += check(
        len(lit) == 1 and lit[0] == IpAddress.v4(203, 0, 113, 7),
        "dns: literal ip fast path",
    )
    if f == 0:
        print("  ring resolver vs truth server: OK")
    return f


def _test_parser_negatives() raises -> Int:
    var f = 0
    var q = dns_build_query(UInt16(0x1234), "a.test", QTYPE_A)
    f += check(len(q) == 12 + 8 + 4, "dns: query length")
    f += check(q[0] == 0x12 and q[1] == 0x34, "dns: query txid bytes")
    f += check(q[2] == 0x01, "dns: RD set")

    # short packet
    var caught = False
    try:
        var short = List[UInt8](length=4, fill=0)
        _ = dns_parse_response(Span(short), UInt16(0), QTYPE_A, String("x"))
    except:
        caught = True
    f += check(caught, "dns: short packet rejected")

    # txid mismatch
    caught = False
    try:
        var fake = List[UInt8](length=12, fill=0)
        fake[2] = 0x80  # QR=1
        _ = dns_parse_response(Span(fake), UInt16(7), QTYPE_A, String("x"))
    except:
        caught = True
    f += check(caught, "dns: txid mismatch rejected")

    # QR=0 (a query, not a response)
    caught = False
    try:
        var fake2 = List[UInt8](length=12, fill=0)
        _ = dns_parse_response(Span(fake2), UInt16(0), QTYPE_A, String("x"))
    except:
        caught = True
    f += check(caught, "dns: QR=0 rejected")

    # compression pointer loop: name at 12 points to itself
    caught = False
    try:
        var lp = List[UInt8](length=18, fill=0)
        lp[2] = 0x80
        lp[5] = 0x01  # QDCOUNT=1
        lp[12] = 0xC0
        lp[13] = 0x0C  # pointer to offset 12 = itself
        _ = dns_parse_response(Span(lp), UInt16(0), QTYPE_A, String("x"))
    except:
        caught = True
    f += check(caught, "dns: pointer loop rejected")

    # ANCOUNT DoS guard: a malicious server claiming 65535 answers is
    # rejected before the parser starts walking name compression for
    # each record.
    caught = False
    try:
        var dos = List[UInt8](length=12, fill=0)
        dos[2] = 0x80  # QR=1
        dos[5] = 0x01  # QDCOUNT=1
        dos[6] = 0xFF
        dos[7] = 0xFF  # ANCOUNT=65535
        _ = dns_parse_response(Span(dos), UInt16(0), QTYPE_A, String("x"))
    except:
        caught = True
    f += check(caught, "dns: ANCOUNT DoS cap")
    if f == 0:
        print("  wire codec negatives: OK")
    return f


def run() raises -> Int:
    var f = 0
    f += _test_parser_negatives()
    f += _test_resolver()
    if f == 0:
        print("test_dns_ring: OK")
    return f


def main() raises:
    var fails = run()
    if fails > 0:
        raise Error("test_dns_ring: " + String(fails) + " failures")
