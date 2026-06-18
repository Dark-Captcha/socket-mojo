# Aggregator. Note that test_tcp / test_tcp_dns require a Python echo
# server on 127.0.0.1:19501 and :19502 respectively — start them
# before running:
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
    tests.test_addr.run()
    tests.test_dns.run()
    tests.test_udp.run()
    tests.test_tcp.run()
    tests.test_tcp_dns.run()
    tests.test_poller.run()
    tests.test_ring.run()
    tests.test_ring_direct.run()
    tests.test_dns_ring.run()
    tests.test_errors.run()
    print("ALL SOCKET TESTS PASSED")
