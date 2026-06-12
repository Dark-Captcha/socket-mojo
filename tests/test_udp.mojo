# UDP loopback test. We bind a UDP listener on one port and a UDP
# sender on an ephemeral port (kernel-assigned); the sender sends a
# datagram to the listener, the listener replies, the sender receives.

from socket.addr import IpAddress, SocketAddr
from socket.udp import UdpSocket
from tests.helpers import check


def run() raises:
    var listen_port = UInt16(19601)
    var server = UdpSocket.bind(
        SocketAddr(IpAddress.loopback_v4(), listen_port)
    )
    var server_addr = SocketAddr(IpAddress.loopback_v4(), listen_port)

    var client = UdpSocket.open()
    client.set_read_timeout(2.0)

    var msg = "ping from socket-mojo".as_bytes()
    _ = client.send_to(msg, server_addr)

    # Server reads, replies with the same bytes
    server.set_read_timeout(2.0)
    var got_pair = server.recv_from(2048)
    var pinged_len = len(got_pair[0])
    var client_addr = got_pair[1]
    check(pinged_len == len(msg), "server received full ping")
    _ = server.send_to(Span(got_pair[0]), client_addr)

    var reply_pair = client.recv_from(2048)
    var pong_len = len(reply_pair[0])
    var got = String(unsafe_from_utf8=Span(reply_pair[0]))
    check(
        got == String(unsafe_from_utf8=msg), "client got the echoed bytes back"
    )
    print("test_udp: OK (" + String(pong_len) + " bytes round-tripped)")


def main() raises:
    run()
