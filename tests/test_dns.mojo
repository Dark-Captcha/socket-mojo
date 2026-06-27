# DNS resolution test. We resolve `localhost` (always present in /etc/
# hosts on Linux) and verify we get at least one IPv4 or IPv6 loopback
# answer. We also verify the literal-IP fast path.

from socket.addr import IpAddress
from socket.dns import resolve
from tests.helpers import check


def run() raises -> Int:
    var f = 0

    # Literal IPv4 short-circuit
    var lit_v4 = resolve("127.0.0.1")
    f += check(len(lit_v4) == 1, "literal v4 returns one answer")
    f += check(
        lit_v4[0] == IpAddress.loopback_v4(), "literal v4 matches loopback"
    )

    # Literal IPv6
    var lit_v6 = resolve("::1")
    f += check(len(lit_v6) == 1, "literal v6 returns one answer")
    f += check(
        lit_v6[0].is_v6 and lit_v6[0].is_loopback(), "literal v6 is loopback"
    )

    # Real DNS: localhost should always resolve to a loopback address.
    var local = resolve("localhost")
    f += check(len(local) >= 1, "localhost resolves to at least one IP")
    var any_loopback = False
    for i in range(len(local)):
        if local[i].is_loopback():
            any_loopback = True
    f += check(any_loopback, "localhost includes a loopback IP")

    if f == 0:
        print("test_dns: OK (" + String(len(local)) + " answers for localhost)")
    return f


def main() raises:
    var fails = run()
    if fails > 0:
        raise Error("test_dns: " + String(fails) + " failures")
