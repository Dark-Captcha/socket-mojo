# Integration test: TcpSocket.connect with a HOSTNAME (not a literal
# IP) — exercises the full DNS → connect → echo round trip. Uses the
# same Python echo server fixture on 127.0.0.1.

from socket.tcp import TcpSocket
from tests.helpers import check


def run() raises:
    var sock = TcpSocket.connect(
        "localhost", UInt16(19502), timeout_seconds=2.0
    )
    var msg = "hostname resolution works".as_bytes()
    sock.write(msg)
    var got = sock.read_exact(len(msg))
    check(
        String(unsafe_from_utf8=Span(got)) == String(unsafe_from_utf8=msg),
        "echo over DNS-resolved hostname",
    )
    print("test_tcp_dns: OK (DNS + connect + echo)")


def main() raises:
    run()
