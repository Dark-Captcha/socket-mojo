# Aggregator. Each test exposes `run() raises -> Int` returning the
# number of check failures (0 == pass). We sum the per-file counts
# so a partial failure surfaces both the file boundary and the
# total. Errors raised from a test (e.g. a socket op failing
# unexpectedly) propagate out as test_*.run can `raises`.
#
# Note that test_tcp / test_tcp_dns require a Python echo server on
# 127.0.0.1:19501 and :19502 respectively — start them before
# running:
#
#   python3 tests/echo_server.py 19501 &
#   python3 tests/echo_server.py 19502 &
#   python3 tests/echo_server.py 19503 &
#   python3 tests/dns_server.py 19553 &
#   mojo run -I . tests/run_tests.mojo

import tests.test_addr
import tests.test_dns
import tests.test_dns_ring
import tests.test_errors
import tests.test_poller
import tests.test_ring
import tests.test_ring_direct
import tests.test_tcp
import tests.test_tcp_dns
import tests.test_udp


def main() raises:
    var total = 0
    total += tests.test_addr.run()
    total += tests.test_dns.run()
    total += tests.test_udp.run()
    total += tests.test_tcp.run()
    total += tests.test_tcp_dns.run()
    total += tests.test_poller.run()
    total += tests.test_ring.run()
    total += tests.test_ring_direct.run()
    total += tests.test_dns_ring.run()
    total += tests.test_errors.run()
    if total == 0:
        print("ALL SOCKET TESTS PASSED")
    else:
        print("FAILED: " + String(total) + " check(s) across the suite")
        raise Error("test failures: " + String(total))
