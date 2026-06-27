# End-to-end TCP loopback test. Spawns a Python echo server in the
# background, then connects via socket-mojo TcpSocket and checks the
# echo round trip. The shell helper runs *before* this Mojo program
# starts the server, so the test is portable: any Python 3 in $PATH.

from socket.addr import IpAddress, SocketAddr
from socket.tcp import TcpSocket
from tests.helpers import check


def run() raises -> Int:
    var f = 0

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
    f += check(got == msg, "echo round trip: " + got)

    # connect_to_addrs: pre-resolved entry point used by DNS-caching callers.
    # Build a one-element address list and verify the same echo round trip.
    var addrs = List[IpAddress]()
    addrs.append(IpAddress.loopback_v4())
    var sock2 = TcpSocket.connect_to_addrs(
        addrs, port, timeout_seconds=2.0
    )
    sock2.write(msg.as_bytes())
    var got2_bytes = sock2.read_exact(msg.byte_length())
    var got2 = String(unsafe_from_utf8=got2_bytes)
    f += check(
        got2 == msg, "connect_to_addrs echo round trip: " + got2
    )

    # connect_to_addrs raises on an empty address list (EAI_NONAME shape).
    var raised_empty = False
    try:
        var addrs_empty = List[IpAddress]()
        var _ = TcpSocket.connect_to_addrs(
            addrs_empty, port, timeout_seconds=2.0
        )
    except:
        raised_empty = True
    f += check(raised_empty, "connect_to_addrs raises on empty list")

    if f == 0:
        print("test_tcp: OK (echoed " + String(msg.byte_length()) + " bytes)")
    return f


def main() raises:
    var fails = run()
    if fails > 0:
        raise Error("test_tcp: " + String(fails) + " failures")
