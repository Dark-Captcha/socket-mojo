# Ring (io_uring engine) tests.
#
# 1. NOP batch: engine mechanics (slots, generations, CQ drain).
# 2. In-process loopback echo entirely through the Ring: accept +
#    connect submitted together, send/recv, shutdown + close, peer
#    address recovery.
# 3. External truth: connect to the python echo server on 19503
#    (tests/echo_server.py — the same one-shot peer the tcp tests
#    use, on its own port) and verify the echo through Ring ops.

from socket._syscalls import (
    AF_INET,
    SOCK_CLOEXEC,
    SOCK_STREAM,
    SOCKADDR_STORAGE_SIZE,
    SOL_SOCKET,
    SO_REUSEADDR,
    errno_message,
    sys_bind,
    sys_listen,
    sys_setsockopt,
    sys_socket,
)
from socket.addr import Ipv4Address, SocketAddr, write_sockaddr
from socket.ring import Completion, CompletionKind, Ring
from std.memory import UnsafePointer

from tests.helpers import check


def _client_sock() raises -> Int32:
    var rc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if rc < 0:
        raise Error("test_ring: socket() " + errno_message(Int32(-rc)))
    return Int32(rc)


def _listening_socket(port: UInt16) raises -> Int32:
    var rc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if rc < 0:
        raise Error("test_ring: socket() " + errno_message(Int32(-rc)))
    var fd = Int32(rc)
    var one = Int32(1)
    _ = sys_setsockopt(
        fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        UnsafePointer(to=one).bitcast[UInt8](),
        4,
    )
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var ip = Ipv4Address(127, 0, 0, 1)
    var alen = write_sockaddr(sa.unsafe_ptr(), SocketAddr.v4(ip, port))
    var brc = sys_bind(fd, sa.unsafe_ptr(), Int(alen))
    if brc != 0:
        raise Error("test_ring: bind() " + errno_message(Int32(-brc)))
    var lrc = sys_listen(fd, 8)
    if lrc != 0:
        raise Error("test_ring: listen() " + errno_message(Int32(-lrc)))
    return fd


def _test_nop_batch() raises -> Int:
    var f = 0
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
        f += check(done.kind == CompletionKind.NOP, "ring: nop kind")
        seen += 1
    f += check(seen == 10, "ring: all 10 nops completed")
    f += check(ring.inflight == 0, "ring: nothing left inflight")
    if f == 0:
        print("  nop batch: OK")
    return f


def _test_loopback_echo() raises -> Int:
    var f = 0
    var ring = Ring(64)
    var port = UInt16(19612)
    var lfd = _listening_socket(port)
    var cfd = _client_sock()

    var dest = SocketAddr.v4(Ipv4Address(127, 0, 0, 1), port)
    var accept_op = ring.accept(lfd)
    var connect_op = ring.connect(cfd, dest)
    _ = ring.wait(min_complete=2)

    var afd = Int32(-1)
    for _ in range(2):
        var c = ring.next_completion()
        f += check(Bool(c), "ring: accept/connect completion present")
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.ACCEPT:
            f += check(done.op == accept_op, "ring: accept op id matches")
            afd = done.res
            var peer = done.accepted_peer()
            f += check(
                peer.is_loopback() and peer.port != 0,
                "ring: accepted peer is loopback with a real port",
            )
        else:
            f += check(
                done.kind == CompletionKind.CONNECT, "ring: other op is connect"
            )
            f += check(done.op == connect_op, "ring: connect op id matches")
    f += check(afd > 0, "ring: accepted fd valid")

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
        f += check(Bool(c), "ring: send/recv completion present")
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.RECV:
            f += check(done.op == srv_recv, "ring: recv op id matches")
            echoed = done.take_buffer()
    f += check(len(echoed) == len(payload), "ring: server got full payload")

    # echo it back through the server side
    _ = ring.send(afd, echoed^)
    var cli_recv = ring.recv(cfd, 256)
    _ = ring.wait(min_complete=2)
    var round = List[UInt8]()
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.RECV:
            f += check(done.op == cli_recv, "ring: client recv op id matches")
            round = done.take_buffer()
    f += check(len(round) == len(payload), "ring: round-trip length")
    var same = True
    for i in range(len(round)):
        if round[i] != payload[i]:
            same = False
    f += check(same, "ring: round-trip bytes identical")

    # close everything through the ring
    _ = ring.close_fd(cfd)
    _ = ring.close_fd(afd)
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=3)
    for _ in range(3):
        var c = ring.next_completion()
        f += check(Bool(c), "ring: close completion present")
        var done = c.take()
        done.ok()
        f += check(done.kind == CompletionKind.CLOSE, "ring: close kind")
    f += check(ring.inflight == 0, "ring: drained")
    if f == 0:
        print("  loopback echo: OK")
    return f


def _test_external_echo() raises -> Int:
    var f = 0
    # python tests/echo_server.py 19503 must be running (same
    # convention as test_tcp.mojo, dedicated port).
    var ring = Ring(32)
    var cfd = _client_sock()
    var dest = SocketAddr.v4(Ipv4Address(127, 0, 0, 1), UInt16(19503))
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
    f += check(Int(sent.res) == len(msg), "ring: external send full write")

    _ = ring.recv(cfd, 256)
    _ = ring.wait(min_complete=1)
    var c2 = ring.next_completion()
    var got = c2.take()
    got.ok()
    var data = got.take_buffer()
    f += check(len(data) == len(msg), "ring: external echo length")
    var same = True
    for i in range(len(data)):
        if data[i] != msg[i]:
            same = False
    f += check(same, "ring: external echo bytes")

    _ = ring.close_fd(cfd)
    _ = ring.wait(min_complete=1)
    var c3 = ring.next_completion()
    c3.take().ok()
    if f == 0:
        print("  external echo via python peer: OK")
    return f


def _test_multishot_and_buffers() raises -> Int:
    var f = 0
    # one armed accept + buffer-pool multishot recv, three clients
    var ring = Ring(64)
    ring.setup_buffers(entries=16, buf_size=512, bgid=3)
    var port = UInt16(19613)
    var lfd = _listening_socket(port)
    var ms_accept = ring.accept_multishot(lfd)
    _ = ring.submit()

    var dest = SocketAddr.v4(Ipv4Address(127, 0, 0, 1), port)
    var clients = List[Int32]()
    for _ in range(3):
        var cfd = _client_sock()
        _ = ring.connect(cfd, dest)
        clients.append(cfd)
    _ = ring.wait(min_complete=6)  # 3 connects + 3 multishot accepts

    var accepted = List[Int32]()
    var more_seen = 0
    for _ in range(6):
        var c = ring.next_completion()
        f += check(Bool(c), "m1: completion present")
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.ACCEPT_MULTI:
            f += check(done.op == ms_accept, "m1: multishot accept op id")
            accepted.append(done.res)
            if done.more:
                more_seen += 1
    f += check(len(accepted) == 3, "m1: three conns from one armed accept")
    f += check(more_seen == 3, "m1: F_MORE on every multishot accept")

    # multishot recv on the first conn: two sends -> two buffer CQEs
    var ms_recv = ring.recv_multishot(accepted[0])
    _ = ring.submit()
    var m1 = String("first message").as_bytes()
    _ = ring.send_copy(clients[0], m1)
    _ = ring.wait(min_complete=2)
    var m2 = String("second!").as_bytes()
    _ = ring.send_copy(clients[0], m2)
    _ = ring.wait(min_complete=2)

    var msgs = 0
    for _ in range(4):
        var c = ring.next_completion()
        f += check(Bool(c), "m1: send/recv completion present")
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.RECV_MULTI:
            f += check(done.op == ms_recv, "m1: multishot recv op id")
            f += check(done.bid >= 0, "m1: kernel picked a buffer")
            f += check(done.more, "m1: recv stays armed")
            var want = m1 if msgs == 0 else m2
            var view = ring.buffer_view(done.bid, Int(done.res))
            f += check(len(view) == len(want), "m1: recv chunk length")
            var same = True
            for i in range(len(view)):
                if view[i] != want[i]:
                    same = False
            f += check(same, "m1: recv chunk bytes")
            ring.recycle_buffer(done.bid)
            msgs += 1
    f += check(msgs == 2, "m1: two multishot recv chunks")

    # cancel the armed recv; its terminal completion frees the slot
    _ = ring.cancel(ms_recv)
    _ = ring.wait(min_complete=2)
    var canceled = False
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        if done.kind == CompletionKind.RECV_MULTI:
            f += check(done.res == -125, "m1: canceled recv res ECANCELED")
            f += check(not done.more, "m1: terminal completion")
            canceled = True
        else:
            f += check(done.kind == CompletionKind.CANCEL, "m1: cancel ack")
            done.ok()
    f += check(canceled, "m1: multishot recv canceled")

    # cancel the armed accept too, then close everything
    _ = ring.cancel(ms_accept)
    _ = ring.wait(min_complete=2)
    for _ in range(2):
        var c = ring.next_completion()
        _ = c.take()
    for i in range(len(clients)):
        _ = ring.close_fd(clients[i])
    for i in range(len(accepted)):
        _ = ring.close_fd(accepted[i])
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=7)
    while True:
        var c = ring.next_completion()
        if not c:
            break
        c.take().ok()
    f += check(ring.inflight == 0, "m1: drained")
    if f == 0:
        print("  multishot + buffer pool: OK")
    return f


def _test_timers() raises -> Int:
    var f = 0
    var ring = Ring(32)
    # standalone timer fires with -ETIME
    _ = ring.timeout(30_000_000)  # 30 ms
    _ = ring.wait(min_complete=1)
    var c = ring.next_completion()
    var done = c.take()
    f += check(done.kind == CompletionKind.TIMEOUT, "m1: timeout kind")
    f += check(done.res == -62, "m1: timer fired ETIME")

    # recv deadline on a silent connection
    var port = UInt16(19614)
    var lfd = _listening_socket(port)
    var cfd = _client_sock()
    _ = ring.connect(cfd, SocketAddr.v4(Ipv4Address(127, 0, 0, 1), port))
    var acc = ring.accept(lfd)
    _ = ring.wait(min_complete=2)
    var afd = Int32(-1)
    for _ in range(2):
        var cc = ring.next_completion()
        var dd = cc.take()
        dd.ok()
        if dd.op == acc:
            afd = dd.res
    _ = ring.recv_with_timeout(afd, 128, 40_000_000)  # nobody sends
    # The kernel delivers two CQEs (the recv and its link-timeout
    # partner), but the engine swallows the partner. Wait for both
    # so the kernel doesn't carry one over and confuse the close
    # path below, then expect exactly ONE user-visible completion.
    _ = ring.wait(min_complete=2)
    var cc = ring.next_completion()
    var dd = cc.take()
    f += check(
        dd.kind == CompletionKind.RECV, "m1: recv-with-timeout user kind"
    )
    f += check(dd.res == -125, "m1: recv deadline ECANCELED")
    f += check(
        Bool(not ring.next_completion()),
        "m1: link-timeout partner drained internally",
    )
    _ = ring.close_fd(cfd)
    _ = ring.close_fd(afd)
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=3)
    while True:
        var cc = ring.next_completion()
        if not cc:
            break
        cc.take().ok()
    if f == 0:
        print("  timers + deadlines: OK")
    return f


def _test_msg_ring() raises -> Int:
    var f = 0
    # OP_MSG_RING posts a CQE on a SECOND ring, in the same process
    # for this test (cross-thread is the real use case). Top 8 bits
    # of payload are reserved by the engine for the kind tag.
    var a = Ring(16)
    var b = Ring(16)
    var op = a.msg_ring(b.fd(), UInt64(0xDEAD_BEEF), 0x4242)
    _ = a.wait(min_complete=1)
    var ca = a.next_completion()
    var ack = ca.take()
    ack.ok()
    f += check(ack.kind == CompletionKind.MSG_RING, "msg-ring: local ack kind")
    f += check(ack.op == op, "msg-ring: ack op id")
    # Now reap the message on the target ring.
    _ = b.wait(min_complete=1)
    var cb = b.next_completion()
    var incoming = cb.take()
    f += check(
        incoming.kind == CompletionKind.MSG_INCOMING, "msg-ring: target kind"
    )
    f += check(
        Int(incoming.res) == 0x4242,
        "msg-ring: target carried `res` payload",
    )
    var got_payload = incoming.op.raw & ((UInt64(1) << 56) - 1)
    f += check(
        got_payload == UInt64(0xDEAD_BEEF),
        "msg-ring: target carried 56-bit payload",
    )
    f += check(
        Bool(not b.next_completion()),
        "msg-ring: target CQ drained",
    )
    if f == 0:
        print("  cross-ring msg_ring: OK")
    return f


def run() raises -> Int:
    var f = 0
    f += _test_nop_batch()
    f += _test_loopback_echo()
    f += _test_multishot_and_buffers()
    f += _test_timers()
    f += _test_msg_ring()
    f += _test_external_echo()
    if f == 0:
        print("test_ring: OK")
    return f


def main() raises:
    var fails = run()
    if fails > 0:
        raise Error("test_ring: " + String(fails) + " failures")
