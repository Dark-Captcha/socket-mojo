# Ring (io_uring engine) tests.
#
# 1. NOP batch: engine mechanics (slots, generations, CQ drain).
# 2. In-process loopback echo entirely through the Ring: accept +
#    connect submitted together, send/recv, shutdown + close, peer
#    address recovery.
# 3. External truth: connect to the python echo server on 19503
#    (tests/echo_server.py — the same one-shot peer the tcp tests
#    use, on its own port) and verify the echo through Ring ops.

from socket._libc import (
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    SOCKADDR_STORAGE_SIZE,
    bind as libc_bind,
    close as libc_close,
    errno,
    errno_message,
    listen as libc_listen,
    setsockopt,
    socket as libc_socket,
    write_sockaddr,
)
from socket.addr import IpAddress, SocketAddr
from socket.ring import (
    KIND_ACCEPT,
    KIND_CLOSE,
    KIND_CONNECT,
    KIND_NOP,
    KIND_RECV,
    KIND_SEND,
    Completion,
    Ring,
)
from std.memory import UnsafePointer

from tests.helpers import check


def _listening_socket(port: UInt16) raises -> Int32:
    var fd = libc_socket(Int32(AF_INET), Int32(SOCK_STREAM), Int32(0))
    if fd < 0:
        raise Error("test_ring: socket() " + errno_message(errno()))
    var one = Int32(1)
    _ = setsockopt(
        fd,
        Int32(SOL_SOCKET),
        Int32(SO_REUSEADDR),
        UnsafePointer(to=one).bitcast[UInt8](),
        4,
    )
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var ip = IpAddress.v4(127, 0, 0, 1)
    var alen = write_sockaddr(sa.unsafe_ptr(), False, ip.octets, port)
    if libc_bind(fd, sa.unsafe_ptr(), alen) != 0:
        raise Error("test_ring: bind() " + errno_message(errno()))
    if libc_listen(fd, 8) != 0:
        raise Error("test_ring: listen() " + errno_message(errno()))
    return fd


def _test_nop_batch() raises:
    var ring = Ring(64)
    var ids = List[UInt64]()
    for _ in range(10):
        ids.append(ring.nop().raw)
    _ = ring.wait(min_complete=10)
    var seen = 0
    while True:
        var c = ring.next_completion()
        if not c:
            break
        var done = c.take()
        done.ok()
        check(done.kind == KIND_NOP, "ring: nop kind")
        seen += 1
    check(seen == 10, "ring: all 10 nops completed")
    check(ring.inflight == 0, "ring: nothing left inflight")
    print("  nop batch: OK")


def _test_loopback_echo() raises:
    var ring = Ring(64)
    var port = UInt16(19612)
    var lfd = _listening_socket(port)
    var cfd = libc_socket(Int32(AF_INET), Int32(SOCK_STREAM), Int32(0))
    check(cfd >= 0, "ring: client socket created")

    var dest = SocketAddr(IpAddress.v4(127, 0, 0, 1), port)
    var accept_op = ring.accept(lfd)
    var connect_op = ring.connect(cfd, dest)
    _ = ring.wait(min_complete=2)

    var afd = Int32(-1)
    for _ in range(2):
        var c = ring.next_completion()
        check(Bool(c), "ring: accept/connect completion present")
        var done = c.take()
        done.ok()
        if done.kind == KIND_ACCEPT:
            check(done.op == accept_op, "ring: accept op id matches")
            afd = done.res
            var peer = done.accepted_peer()
            check(
                peer.ip.is_loopback() and peer.port != 0,
                "ring: accepted peer is loopback with a real port",
            )
        else:
            check(done.kind == KIND_CONNECT, "ring: other op is connect")
            check(done.op == connect_op, "ring: connect op id matches")
    check(afd > 0, "ring: accepted fd valid")

    # client sends, server echoes back, client receives
    var payload = String("ring echo \xf0\x9f\x94\xa5 payload").as_bytes()
    var payload_copy = List[UInt8](capacity=len(payload))
    payload_copy.extend(payload)
    _ = ring.send(cfd, payload_copy^)
    var srv_recv = ring.recv(afd, 256)
    _ = ring.wait(min_complete=2)
    var echoed = List[UInt8]()
    for _ in range(2):
        var c = ring.next_completion()
        check(Bool(c), "ring: send/recv completion present")
        var done = c.take()
        done.ok()
        if done.kind == KIND_RECV:
            check(done.op == srv_recv, "ring: recv op id matches")
            echoed = done.take_buffer()
    check(len(echoed) == len(payload), "ring: server got full payload")

    # echo it back through the server side
    _ = ring.send(afd, echoed^)
    var cli_recv = ring.recv(cfd, 256)
    _ = ring.wait(min_complete=2)
    var round = List[UInt8]()
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        if done.kind == KIND_RECV:
            check(done.op == cli_recv, "ring: client recv op id matches")
            round = done.take_buffer()
    check(len(round) == len(payload), "ring: round-trip length")
    var same = True
    for i in range(len(round)):
        if round[i] != payload[i]:
            same = False
    check(same, "ring: round-trip bytes identical")

    # close everything through the ring
    _ = ring.close_fd(cfd)
    _ = ring.close_fd(afd)
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=3)
    for _ in range(3):
        var c = ring.next_completion()
        check(Bool(c), "ring: close completion present")
        var done = c.take()
        done.ok()
        check(done.kind == KIND_CLOSE, "ring: close kind")
    check(ring.inflight == 0, "ring: drained")
    print("  loopback echo: OK")


def _test_external_echo() raises:
    # python tests/echo_server.py 19503 must be running (same
    # convention as test_tcp.mojo, dedicated port).
    var ring = Ring(32)
    var cfd = libc_socket(Int32(AF_INET), Int32(SOCK_STREAM), Int32(0))
    var dest = SocketAddr(IpAddress.v4(127, 0, 0, 1), UInt16(19503))
    _ = ring.connect(cfd, dest)
    _ = ring.wait(min_complete=1)
    var c0 = ring.next_completion()
    var conn = c0.take()
    conn.ok()

    var msg = String("hello from the io_uring ring engine").as_bytes()
    _ = ring.send_copy(cfd, msg)
    _ = ring.wait(min_complete=1)
    var c1 = ring.next_completion()
    var sent = c1.take()
    sent.ok()
    check(Int(sent.res) == len(msg), "ring: external send full write")

    _ = ring.recv(cfd, 256)
    _ = ring.wait(min_complete=1)
    var c2 = ring.next_completion()
    var got = c2.take()
    got.ok()
    var data = got.take_buffer()
    check(len(data) == len(msg), "ring: external echo length")
    var same = True
    for i in range(len(data)):
        if data[i] != msg[i]:
            same = False
    check(same, "ring: external echo bytes")

    _ = ring.close_fd(cfd)
    _ = ring.wait(min_complete=1)
    var c3 = ring.next_completion()
    c3.take().ok()
    print("  external echo via python peer: OK")


def run() raises:
    _test_nop_batch()
    _test_loopback_echo()
    _test_external_echo()
    print("test_ring: OK")


def main() raises:
    run()
