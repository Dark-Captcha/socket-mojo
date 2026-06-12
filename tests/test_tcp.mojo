# End-to-end TCP loopback test. Spawns a Python echo server in the
# background, then connects via socket-mojo TcpSocket and checks the
# echo round trip. The shell helper runs *before* this Mojo program
# starts the server, so the test is portable: any Python 3 in $PATH.

from socket.addr import IpAddress, SocketAddr
from socket.tcp import TcpSocket
from tests.helpers import check


def run() raises:
    # The shell harness above this test starts a Python echo server on
    # 127.0.0.1:PORT_FROM_ENV. We hardcode the port and assume the
    # server is up. If you run this standalone, see the run_tests
    # wrapper.
    var port = UInt16(19501)
    var sock = TcpSocket.connect("127.0.0.1", port, timeout_seconds=2.0)
    var msg = "Hello from socket-mojo via TcpSocket.connect()!"
    sock.write(msg.as_bytes())
    var got_bytes = sock.read_exact(msg.byte_length())
    var got = String(unsafe_from_utf8=got_bytes)
    check(got == msg, "echo round trip: " + got)
    print("test_tcp: OK (echoed " + String(msg.byte_length()) + " bytes)")


def main() raises:
    run()
