# Tests for the registered-fd table family + OP_SEND_ZC.
#
# 1. register/unregister: setup and teardown of the sparse fd table.
# 2. accept_direct + fixed I/O + close_direct: full lifecycle of a
#    connection that lives entirely in the registered table — peer
#    address recovered from the single-shot accept's sockaddr buffer.
# 3. accept_multishot_direct: stream of direct accepts from one
#    armed SQE.
# 4. socket_direct + connect (fixed) + send_zc: open a client socket
#    inside the ring's table, connect through it, then exercise the
#    OP_SEND_ZC two-CQE protocol (the engine surfaces the "send
#    done" result and silently drains the buffer-release notif).

from std.memory import UnsafePointer

from socket._syscalls import (
    AF_INET,
    SOCK_CLOEXEC,
    SOCK_STREAM,
    SOCKADDR_STORAGE_SIZE,
    SOL_SOCKET,
    SO_REUSEADDR,
    errno_message,
    sys_bind,
    sys_close,
    sys_listen,
    sys_setsockopt,
    sys_socket,
)
from socket.addr import Ipv4Address, SocketAddr, write_sockaddr
from socket.ring import CompletionKind, Ring
from tests.helpers import check


def _client_sock() raises -> Int32:
    var rc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if rc < 0:
        raise Error("test_ring_direct: socket " + errno_message(Int32(-rc)))
    return Int32(rc)


def _listening_socket(port: UInt16) raises -> Int32:
    var rc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if rc < 0:
        raise Error("test_ring_direct: socket " + errno_message(Int32(-rc)))
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
        raise Error("test_ring_direct: bind " + errno_message(Int32(-brc)))
    var lrc = sys_listen(fd, 8)
    if lrc != 0:
        raise Error("test_ring_direct: listen " + errno_message(Int32(-lrc)))
    return fd


def _test_register_files_lifecycle() raises -> Int:
    var ring = Ring(32)
    ring.register_files(64)
    ring.unregister_files()
    # Reuse: register again, then drop the ring (kernel auto-cleans).
    ring.register_files(16)
    print("  register/unregister: OK")
    return 0


def _test_accept_direct_echo() raises -> Int:
    var f = 0
    var ring = Ring(64)
    ring.register_files(32)
    var port = UInt16(19620)
    var lfd = _listening_socket(port)
    var cfd = _client_sock()

    var dest = SocketAddr.v4(Ipv4Address(127, 0, 0, 1), port)
    var accept_op = ring.accept_direct(lfd)
    # Connect using a raw fd (the standard, non-direct connect).
    var connect_op = ring.connect(cfd, dest)
    _ = ring.wait(min_complete=2)

    var direct_slot = Int32(-1)
    var saw_accept = False
    var saw_connect = False
    for _ in range(2):
        var c = ring.next_completion()
        f += check(Bool(c), "direct: accept/connect completion present")
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.ACCEPT_DIRECT:
            f += check(done.op == accept_op, "direct: accept op id matches")
            direct_slot = done.res
            var peer = done.accepted_peer()
            f += check(
                peer.is_loopback() and peer.port != 0,
                "direct: peer addr is loopback with a real port",
            )
            saw_accept = True
        else:
            f += check(
                done.kind == CompletionKind.CONNECT,
                "direct: other op is connect",
            )
            f += check(done.op == connect_op, "direct: connect op id matches")
            saw_connect = True
    f += check(saw_accept and saw_connect, "direct: both ops completed")
    f += check(direct_slot >= 0, "direct: kernel allocated a valid slot")

    # Client sends, the direct-fd server side recvs (fixed=True),
    # echoes back, client reads.
    var payload = String("hello over a direct fd!").as_bytes()
    var payload_copy = List[UInt8](capacity=len(payload))
    payload_copy.extend(payload)
    _ = ring.send(cfd, payload_copy^)
    _ = ring.recv(direct_slot, 256, fixed=True)
    _ = ring.wait(min_complete=2)
    var echoed = List[UInt8]()
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.RECV:
            echoed = done.take_buffer()
    f += check(len(echoed) == len(payload), "direct: server got full payload")

    # Echo back via the direct slot.
    _ = ring.send(direct_slot, echoed^, fixed=True)
    _ = ring.recv(cfd, 256)
    _ = ring.wait(min_complete=2)
    var roundtrip = List[UInt8]()
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.RECV:
            roundtrip = done.take_buffer()
    f += check(len(roundtrip) == len(payload), "direct: client got echo")
    var same = True
    for i in range(len(roundtrip)):
        if roundtrip[i] != payload[i]:
            same = False
    f += check(same, "direct: round-trip bytes identical")

    # Close: direct fd via close_direct, raw fds via close_fd.
    _ = ring.close_fd(direct_slot, fixed=True)
    _ = ring.close_fd(cfd)
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=3)
    for _ in range(3):
        var c = ring.next_completion()
        f += check(Bool(c), "direct: close completion present")
        var done = c.take()
        done.ok()
        f += check(done.kind == CompletionKind.CLOSE, "direct: close kind")
    f += check(ring.inflight == 0, "direct: drained")
    ring.unregister_files()
    if f == 0:
        print("  accept_direct + fixed I/O + close_direct: OK")
    return f


def _test_accept_multishot_direct() raises -> Int:
    var f = 0
    var ring = Ring(64)
    ring.register_files(16)
    var port = UInt16(19621)
    var lfd = _listening_socket(port)
    var ms_accept = ring.accept_multishot_direct(lfd)
    _ = ring.submit()

    var dest = SocketAddr.v4(Ipv4Address(127, 0, 0, 1), port)
    var clients = List[Int32]()
    for _ in range(3):
        var cfd = _client_sock()
        _ = ring.connect(cfd, dest)
        clients.append(cfd)
    _ = ring.wait(min_complete=6)  # 3 connects + 3 multishot accepts

    var direct_slots = List[Int32]()
    var more_seen = 0
    for _ in range(6):
        var c = ring.next_completion()
        f += check(Bool(c), "direct-ms: completion present")
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.ACCEPT_MULTI_DIRECT:
            f += check(done.op == ms_accept, "direct-ms: accept op id")
            direct_slots.append(done.res)
            if done.more:
                more_seen += 1
    f += check(len(direct_slots) == 3, "direct-ms: three direct slots")
    f += check(more_seen == 3, "direct-ms: F_MORE on each multishot accept")
    # The kernel must allocate distinct slot indices.
    for i in range(len(direct_slots)):
        for j in range(i + 1, len(direct_slots)):
            f += check(
                direct_slots[i] != direct_slots[j],
                "direct-ms: slots are unique",
            )

    # Cancel the multishot accept and close everything.
    _ = ring.cancel(ms_accept)
    _ = ring.wait(min_complete=2)
    for _ in range(2):
        var c = ring.next_completion()
        _ = c.take()
    for i in range(len(direct_slots)):
        _ = ring.close_fd(direct_slots[i], fixed=True)
    for i in range(len(clients)):
        _ = ring.close_fd(clients[i])
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=len(direct_slots) + len(clients) + 1)
    while True:
        var c = ring.next_completion()
        if not c:
            break
        _ = c.take()
    f += check(ring.inflight == 0, "direct-ms: drained")
    ring.unregister_files()
    if f == 0:
        print("  accept_multishot_direct: OK")
    return f


def _test_socket_direct_connect_and_io() raises -> Int:
    var f = 0
    # OP_SOCKET allocates a fresh socket directly into the registered
    # table; OP_CONNECT with fixed=True wires it up. Once connected,
    # the same slot drives recv/send.
    var ring = Ring(64)
    ring.register_files(8)
    var port = UInt16(19622)
    var lfd = _listening_socket(port)
    var dest = SocketAddr.v4(Ipv4Address(127, 0, 0, 1), port)
    var accept_op = ring.accept(lfd)
    var sock_op = ring.socket_direct(Int(AF_INET), Int(SOCK_STREAM), 0)
    _ = ring.wait(min_complete=1)  # OP_SOCKET completes immediately

    var client_slot = Int32(-1)
    while True:
        var c = ring.next_completion()
        if not c:
            break
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.SOCKET:
            f += check(done.op == sock_op, "sock-direct: op id matches")
            client_slot = done.res
    f += check(client_slot >= 0, "sock-direct: kernel allocated a slot")

    _ = ring.connect(client_slot, dest, fixed=True)
    _ = ring.wait(min_complete=2)  # accept + connect
    var server_fd = Int32(-1)
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        if done.op == accept_op:
            server_fd = done.res
    f += check(server_fd > 0, "sock-direct: accepted server fd valid")

    # Ping-pong on the fixed-fd client side.
    var msg = String("socket_direct + connect (fixed) ping").as_bytes()
    var msg_copy = List[UInt8](capacity=len(msg))
    msg_copy.extend(msg)
    _ = ring.send(client_slot, msg_copy^, fixed=True)
    _ = ring.recv(server_fd, 256)
    _ = ring.wait(min_complete=2)
    var got = List[UInt8]()
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.RECV:
            got = done.take_buffer()
    f += check(len(got) == len(msg), "sock-direct: server received full ping")

    _ = ring.close_fd(client_slot, fixed=True)
    _ = ring.close_fd(server_fd)
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=3)
    while True:
        var c = ring.next_completion()
        if not c:
            break
        _ = c.take()
    f += check(ring.inflight == 0, "sock-direct: drained")
    ring.unregister_files()
    if f == 0:
        print("  socket_direct + connect (fixed) + I/O: OK")
    return f


def _test_send_zc() raises -> Int:
    var f = 0
    # OP_SEND_ZC posts two CQEs (send done + buffer-reusable notif);
    # the engine surfaces exactly one Completion to the user (the
    # send-done one) and drains the notif silently.
    var ring = Ring(64)
    var port = UInt16(19623)
    var lfd = _listening_socket(port)
    var cfd = _client_sock()
    var dest = SocketAddr.v4(Ipv4Address(127, 0, 0, 1), port)
    var accept_op = ring.accept(lfd)
    _ = ring.connect(cfd, dest)
    _ = ring.wait(min_complete=2)
    var afd = Int32(-1)
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        if done.op == accept_op:
            afd = done.res
    f += check(afd > 0, "zc: accept ok")

    # 32 KiB payload — big enough that the kernel really does pin and
    # later release the buffer; small enough to round-trip cleanly
    # on loopback.
    var n = 32768
    var payload = List[UInt8](length=n, fill=0x5A)
    var payload_copy = List[UInt8](capacity=n)
    payload_copy.extend(Span(payload))
    var send_op = ring.send(cfd, payload_copy^, zero_copy=True)

    # Drain the send-done CQE first (it can arrive without the recv
    # having drained anything yet). Then refill recv until we have
    # the full payload back.
    _ = ring.wait(min_complete=1)
    var send_done = False
    while not send_done:
        var c = ring.next_completion()
        if not c:
            _ = ring.wait(min_complete=1)
            continue
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.SEND_ZC:
            f += check(done.op == send_op, "zc: send_zc op id matches")
            f += check(Int(done.res) == n, "zc: send_zc reported all bytes")
            send_done = True

    var got_n = 0
    while got_n < n:
        _ = ring.recv(afd, n - got_n)
        _ = ring.wait(min_complete=1)
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        got_n += Int(done.res)
    f += check(got_n == n, "zc: server got the full payload")

    # The notif CQE for the send_zc may arrive any time before the
    # closes — wait for it to drain plus the closes (afd, cfd, lfd).
    _ = ring.close_fd(cfd)
    _ = ring.close_fd(afd)
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=3)
    while True:
        var c = ring.next_completion()
        if not c:
            break
        _ = c.take()
    f += check(ring.inflight == 0, "zc: drained (notif consumed internally)")
    if f == 0:
        print("  send_zc (two-CQE protocol drained internally): OK")
    return f


def run() raises -> Int:
    var f = 0
    f += _test_register_files_lifecycle()
    f += _test_accept_direct_echo()
    f += _test_accept_multishot_direct()
    f += _test_socket_direct_connect_and_io()
    f += _test_send_zc()
    if f == 0:
        print("test_ring_direct: OK")
    return f


def main() raises:
    var fails = run()
    if fails > 0:
        raise Error("test_ring_direct: " + String(fails) + " failures")
