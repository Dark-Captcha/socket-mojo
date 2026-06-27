# Address parsing and serialization. Pure-Mojo, no syscalls. Exercises the
# v4/v6 type split: Ipv4Address (RFC 791) and Ipv6Address (RFC 8200) are
# distinct types; SocketAddr is the family-discriminated sum.

from socket.addr import (
    AddressFamily,
    Ipv4Address,
    Ipv6Address,
    SocketAddr,
    parse_ip,
    parse_ipv4,
    parse_ipv6,
)
from tests.helpers import check


def run() raises -> Int:
    var f = 0

    # IPv4 parse + stringify
    var v4 = parse_ipv4("192.168.1.42")
    f += check(v4.octets[0] == 192 and v4.octets[3] == 42, "v4 octets")
    f += check(v4.to_string() == "192.168.1.42", "v4 to_string")
    f += check(Ipv4Address.loopback().is_loopback(), "127.0.0.1 is loopback")
    f += check(
        Ipv4Address(8, 8, 8, 8).is_loopback() == False,
        "8.8.8.8 not loopback",
    )

    var caught = False
    try:
        _ = parse_ipv4("256.0.0.1")
    except:
        caught = True
    f += check(caught, "reject out-of-range octet")

    caught = False
    try:
        _ = parse_ipv4("01.2.3.4")
    except:
        caught = True
    f += check(caught, "reject leading-zero octet")

    # IPv6 parse + stringify (full form)
    var full = parse_ipv6("2001:db8:85a3:0:0:8a2e:370:7334")
    f += check(
        full.octets[0] == 0x20 and full.octets[1] == 0x01, "v6 head bytes"
    )
    f += check(
        full.octets[14] == 0x73 and full.octets[15] == 0x34, "v6 tail bytes"
    )

    # IPv6 `::` compression
    var loop6 = parse_ipv6("::1")
    f += check(loop6.is_loopback(), "::1 is loopback")
    var any6 = parse_ipv6("::")
    f += check(any6.octets[0] == 0 and any6.octets[15] == 0, "::: all zeros")
    f += check(any6 == Ipv6Address.any(), "::: equals any()")

    # IPv4-mapped IPv6 with embedded v4 tail
    var mapped = parse_ipv6("::ffff:192.0.2.128")
    f += check(
        mapped.octets[10] == 0xFF and mapped.octets[11] == 0xFF,
        "v4-mapped marker",
    )
    f += check(
        mapped.octets[12] == 192 and mapped.octets[15] == 128, "v4-mapped tail"
    )

    # SocketAddr parsing — IPv4
    var sa = SocketAddr.parse("127.0.0.1:8080")
    f += check(sa.port == 8080, "sa.port")
    f += check(sa.kind() == AddressFamily.V4, "sa is v4")
    f += check(sa.is_loopback(), "sa loopback")
    f += check(sa.to_string() == "127.0.0.1:8080", "sa.to_string round trip")
    f += check(sa.as_v4() == Ipv4Address(127, 0, 0, 1), "sa.as_v4")

    # as_v6 on a v4 address must raise (the compiler-refuses-to-mix promise,
    # enforced at the variant boundary).
    caught = False
    try:
        _ = sa.as_v6()
    except:
        caught = True
    f += check(caught, "as_v6 on v4 raises")

    # SocketAddr parsing — IPv6 with brackets
    var sa6 = SocketAddr.parse("[::1]:443")
    f += check(sa6.port == 443, "sa6 port")
    f += check(sa6.kind() == AddressFamily.V6, "sa6 is v6")
    f += check(sa6.is_loopback(), "sa6 loopback")
    f += check(sa6.as_v6().is_loopback(), "sa6.as_v6 loopback")

    # with_port stamps a fresh port onto a port-0 (DNS-shaped) address.
    var bare = parse_ip("10.0.0.1")
    f += check(bare.port == 0, "parse_ip has port 0")
    var stamped = bare.with_port(80)
    f += check(stamped.port == 80, "with_port stamps port")
    f += check(
        stamped == SocketAddr.v4(Ipv4Address(10, 0, 0, 1), 80),
        "with_port equality",
    )

    # Auto-detect IPv4 vs IPv6 in parse_ip
    var auto4 = parse_ip("10.0.0.1")
    f += check(auto4.kind() == AddressFamily.V4, "auto v4")
    var auto6 = parse_ip("::1")
    f += check(auto6.kind() == AddressFamily.V6, "auto v6")

    if f == 0:
        print("test_addr: OK")
    return f


def main() raises:
    var fails = run()
    if fails > 0:
        raise Error("test_addr: " + String(fails) + " failures")
