# Address parsing and serialization. Pure-Mojo, no syscalls.

from socket.addr import IpAddress, SocketAddr, parse_ip, parse_ipv4, parse_ipv6
from tests.helpers import check


def run() raises:
    # IPv4 parse + stringify
    var v4 = parse_ipv4("192.168.1.42")
    check(v4.octets[0] == 192 and v4.octets[3] == 42, "v4 octets")
    check(v4.to_string() == "192.168.1.42", "v4 to_string")
    check(IpAddress.loopback_v4().is_loopback(), "127.0.0.1 is loopback")
    check(
        IpAddress.v4(8, 8, 8, 8).is_loopback() == False, "8.8.8.8 not loopback"
    )

    var caught = False
    try:
        _ = parse_ipv4("256.0.0.1")
    except:
        caught = True
    check(caught, "reject out-of-range octet")

    caught = False
    try:
        _ = parse_ipv4("01.2.3.4")
    except:
        caught = True
    check(caught, "reject leading-zero octet")

    # IPv6 parse + stringify (full form)
    var full = parse_ipv6("2001:db8:85a3:0:0:8a2e:370:7334")
    check(full.octets[0] == 0x20 and full.octets[1] == 0x01, "v6 head bytes")
    check(full.octets[14] == 0x73 and full.octets[15] == 0x34, "v6 tail bytes")

    # IPv6 `::` compression
    var loop6 = parse_ipv6("::1")
    check(loop6.is_loopback(), "::1 is loopback")
    var any6 = parse_ipv6("::")
    check(any6.octets[0] == 0 and any6.octets[15] == 0, "::: all zeros")
    check(any6 == IpAddress.any_v6(), "::: equals any_v6")

    # IPv4-mapped IPv6 with embedded v4 tail
    var mapped = parse_ipv6("::ffff:192.0.2.128")
    check(
        mapped.octets[10] == 0xFF and mapped.octets[11] == 0xFF,
        "v4-mapped marker",
    )
    check(
        mapped.octets[12] == 192 and mapped.octets[15] == 128, "v4-mapped tail"
    )

    # SocketAddr parsing — IPv4
    var sa = SocketAddr.parse("127.0.0.1:8080")
    check(sa.port == 8080, "sa.port")
    check(sa.ip.is_loopback(), "sa.ip loopback")
    check(sa.to_string() == "127.0.0.1:8080", "sa.to_string round trip")

    # SocketAddr parsing — IPv6 with brackets
    var sa6 = SocketAddr.parse("[::1]:443")
    check(sa6.port == 443, "sa6 port")
    check(sa6.ip.is_v6 and sa6.ip.is_loopback(), "sa6 v6 loopback")

    # Auto-detect IPv4 vs IPv6 in parse_ip
    var auto4 = parse_ip("10.0.0.1")
    check(not auto4.is_v6, "auto v4")
    var auto6 = parse_ip("::1")
    check(auto6.is_v6, "auto v6")

    print("test_addr: OK")


def main() raises:
    run()
