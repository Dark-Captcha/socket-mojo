# Echo round-trip throughput: the io_uring Ring (multishot recv +
# provided buffers) vs the epoll Poller tier vs plain blocking
# sockets. Loopback, one connection, ping-pong — measures engine
# overhead per operation, the number a protocol driver actually pays.
#
# Run: pixi run mojo run -I . benchmarks/bench_ring.mojo

from std.memory import UnsafePointer
from std.time import perf_counter_ns

from socket._syscalls import (
    AF_INET,
    MSG_DONTWAIT,
    MSG_NOSIGNAL,
    SOCK_CLOEXEC,
    SOCK_STREAM,
    SOCKADDR_STORAGE_SIZE,
    SOL_SOCKET,
    SO_REUSEADDR,
    errno_message,
    sys_accept4,
    sys_bind,
    sys_close,
    sys_connect,
    sys_getsockname,
    sys_listen,
    sys_recv,
    sys_send,
    sys_setsockopt,
    sys_socket,
    write_sockaddr,
)
from socket.addr import IpAddress, SocketAddr
from socket.nonblocking import set_nonblocking
from socket.poller import Poller
from socket.ring import CompletionKind, Ring


def _pair(port: UInt16) raises -> Tuple[Int32, Int32]:
    """(accepted_fd, client_fd) over loopback, blocking handshake.
    `port` is a hint; bind picks an ephemeral port if `port == 0`."""
    var lrc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if lrc < 0:
        raise Error("bench: socket " + errno_message(Int32(-lrc)))
    var lfd = Int32(lrc)
    var one = Int32(1)
    _ = sys_setsockopt(
        lfd,
        SOL_SOCKET,
        SO_REUSEADDR,
        UnsafePointer(to=one).bitcast[UInt8](),
        4,
    )
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var ip = IpAddress.v4(127, 0, 0, 1)
    var alen = write_sockaddr(
        sa.unsafe_ptr(), False, ip.octets, port
    )
    var brc = sys_bind(lfd, sa.unsafe_ptr(), Int(alen))
    if brc != 0:
        raise Error("bench: bind " + errno_message(Int32(-brc)))
    # if port == 0 the kernel picked; pull it back into `sa` for connect
    if port == 0:
        var got = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var glen = UInt32(SOCKADDR_STORAGE_SIZE)
        _ = sys_getsockname(lfd, got.unsafe_ptr(), UnsafePointer(to=glen))
        sa[2] = got[2]
        sa[3] = got[3]
    _ = sys_listen(lfd, 1)
    var crc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if crc < 0:
        raise Error("bench: socket " + errno_message(Int32(-crc)))
    var cfd = Int32(crc)
    var concrc = sys_connect(cfd, sa.unsafe_ptr(), Int(alen))
    if concrc != 0:
        raise Error("bench: connect " + errno_message(Int32(-concrc)))
    var alen2 = UInt32(SOCKADDR_STORAGE_SIZE)
    var asa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var afdrc = sys_accept4(
        lfd, asa.unsafe_ptr(), UnsafePointer(to=alen2), SOCK_CLOEXEC
    )
    if afdrc < 0:
        raise Error("bench: accept " + errno_message(Int32(-afdrc)))
    var afd = Int32(afdrc)
    _ = sys_close(lfd)
    return (afd, cfd)


def _bench_blocking(msg_size: Int, rounds: Int) raises -> Float64:
    var p = _pair(UInt16(19821))
    var afd = p[0]
    var cfd = p[1]
    var msg = List[UInt8](length=msg_size, fill=0x42)
    var buf = List[UInt8](length=msg_size, fill=0)
    var t0 = perf_counter_ns()
    for _ in range(rounds):
        _ = sys_send(cfd, msg.unsafe_ptr(), msg_size, MSG_NOSIGNAL)
        var got = 0
        while got < msg_size:
            var n = sys_recv(afd, buf.unsafe_ptr() + got, msg_size - got, 0)
            got += Int(n)
        _ = sys_send(afd, buf.unsafe_ptr(), msg_size, MSG_NOSIGNAL)
        got = 0
        while got < msg_size:
            var n = sys_recv(cfd, buf.unsafe_ptr() + got, msg_size - got, 0)
            got += Int(n)
    var t1 = perf_counter_ns()
    _ = sys_close(afd)
    _ = sys_close(cfd)
    return Float64(rounds) / (Float64(t1 - t0) / 1e9)


def _bench_ring_single(msg_size: Int, rounds: Int) raises -> Float64:
    # Fair single-conn comparison: armed multishot recv on both ends,
    # so each ping costs exactly one send SQE and the kernel pushes a
    # buffer-carrying completion straight back.
    var p = _pair(UInt16(19822))
    var afd = p[0]
    var cfd = p[1]
    var ring = Ring(64)
    ring.setup_buffers(entries=64, buf_size=32768, bgid=1)
    _ = ring.recv_multishot(afd)
    _ = ring.recv_multishot(cfd)
    var msg = List[UInt8](length=msg_size, fill=0x42)
    var pings = 0
    var t0 = perf_counter_ns()
    _ = ring.send_copy(cfd, Span(msg))
    while pings < rounds:
        _ = ring.wait(min_complete=1)
        while True:
            var c = ring.next_completion()
            if not c:
                break
            var done = c.take()
            if done.kind == CompletionKind.RECV_MULTI:
                if done.res <= 0:
                    continue
                var view = ring.buffer_view(done.bid, Int(done.res))
                if done.fd == afd:
                    _ = ring.send_copy(afd, view)  # echo back
                else:
                    pings += 1
                    if pings < rounds:
                        _ = ring.send_copy(cfd, view)  # next ping
                ring.recycle_buffer(done.bid)
    var t1 = perf_counter_ns()
    _ = ring.close_fd(afd)
    _ = ring.close_fd(cfd)
    _ = ring.wait(min_complete=2)
    return Float64(rounds) / (Float64(t1 - t0) / 1e9)


def _bench_ring_fanout(
    msg_size: Int, rounds: Int, conns: Int, *, sqpoll: Bool = False
) raises -> Float64:
    # The shape io_uring is actually built for: many concurrent
    # connections through ONE ring. Each conn ping-pongs in parallel;
    # one wait() reaps a burst of completions per syscall. SQPOLL on
    # top drops the per-submit syscall — the kthread polls our tail.
    var ring = Ring(max(256, conns * 4), sqpoll=sqpoll, sqpoll_idle_ms=2000)
    ring.setup_buffers(entries=max(64, conns * 2), buf_size=32768, bgid=1)
    var afds = List[Int32]()
    var cfds = List[Int32]()
    for _ in range(conns):
        var p = _pair(UInt16(0))
        afds.append(p[0])
        cfds.append(p[1])
    for i in range(conns):
        _ = ring.recv_multishot(afds[i])
        _ = ring.recv_multishot(cfds[i])
    var msg = List[UInt8](length=msg_size, fill=0x42)
    # O(1) server/client classification, built ONCE outside the timed
    # region (the old per-completion linear scan was O(conns^2) and
    # distorted the high-concurrency numbers).
    var is_server_fd = Dict[Int32, Bool]()
    for i in range(conns):
        is_server_fd[afds[i]] = True
        is_server_fd[cfds[i]] = False
    # prime one ping per connection
    for ci in range(conns):
        _ = ring.send_copy(cfds[ci], Span(msg))
    var pings = 0
    var target = rounds * conns
    var t0 = perf_counter_ns()
    while pings < target:
        _ = ring.wait(min_complete=1)
        while True:
            var c = ring.next_completion()
            if not c:
                break
            var done = c.take()
            if done.kind == CompletionKind.RECV_MULTI:
                if done.res <= 0:
                    continue
                var view = ring.buffer_view(done.bid, Int(done.res))
                if is_server_fd[done.fd]:
                    _ = ring.send_copy(done.fd, view)
                else:
                    pings += 1
                    if pings < target:
                        _ = ring.send_copy(done.fd, view)
                ring.recycle_buffer(done.bid)
    var t1 = perf_counter_ns()
    for i in range(conns):
        _ = ring.close_fd(afds[i])
        _ = ring.close_fd(cfds[i])
    _ = ring.wait(min_complete=conns * 2)
    return Float64(target) / (Float64(t1 - t0) / 1e9)


def _bench_ring_fanout_direct(
    msg_size: Int, rounds: Int, conns: Int, *, sqpoll: Bool = False
) raises -> Float64:
    """Same shape as _bench_ring_fanout but every fd lives in the
    registered table: socket_direct for clients, accept_direct for
    servers, recv/send/close with fixed=True. The kernel skips the
    per-op fget refcount bump on the hot path."""
    var ring = Ring(max(256, conns * 4), sqpoll=sqpoll, sqpoll_idle_ms=2000)
    ring.register_files(conns * 2 + 16)
    ring.setup_buffers(entries=max(64, conns * 2), buf_size=32768, bgid=1)

    # Set up one listener (raw), then spawn `conns` client/server
    # pairs entirely through direct fds.
    var lfd = _pair_listener(UInt16(0))
    var port = _pair_local_port(lfd)
    var dest = SocketAddr(IpAddress.v4(127, 0, 0, 1), port)

    var afds = List[Int32]()  # server-side direct slots
    var accept_ops = List[UInt64]()
    var connect_ops = List[UInt64]()
    var sock_ops = List[UInt64]()

    # First open all client direct sockets via OP_SOCKET (synchronous
    # in the kernel; they all complete after one wait).
    for _ in range(conns):
        sock_ops.append(
            ring.socket_direct(Int(AF_INET), Int(SOCK_STREAM), 0).raw
        )
    _ = ring.wait(min_complete=conns)
    var client_slots = List[Int32]()
    while True:
        var c = ring.next_completion()
        if not c:
            break
        var done = c.take()
        done.ok()
        client_slots.append(done.res)

    # Then issue accept_direct(s) and connect_fixed(s) interleaved.
    for i in range(conns):
        accept_ops.append(ring.accept_direct(lfd).raw)
        connect_ops.append(ring.connect(client_slots[i], dest, fixed=True).raw)
    _ = ring.wait(min_complete=conns * 2)
    while True:
        var c = ring.next_completion()
        if not c:
            break
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.ACCEPT_DIRECT:
            afds.append(done.res)
    var cfds = client_slots.copy()

    # Arm multishot recv on every direct fd.
    for i in range(conns):
        _ = ring.recv_multishot(afds[i], fixed=True)
        _ = ring.recv_multishot(cfds[i], fixed=True)

    var is_server_fd = Dict[Int32, Bool]()
    for i in range(conns):
        is_server_fd[afds[i]] = True
        is_server_fd[cfds[i]] = False
    var msg = List[UInt8](length=msg_size, fill=0x42)
    for ci in range(conns):
        _ = ring.send_copy(cfds[ci], Span(msg), fixed=True)
    var pings = 0
    var target = rounds * conns
    var t0 = perf_counter_ns()
    while pings < target:
        _ = ring.wait(min_complete=1)
        while True:
            var c = ring.next_completion()
            if not c:
                break
            var done = c.take()
            if done.kind == CompletionKind.RECV_MULTI:
                if done.res <= 0:
                    continue
                var view = ring.buffer_view(done.bid, Int(done.res))
                if is_server_fd[done.fd]:
                    _ = ring.send_copy(done.fd, view, fixed=True)
                else:
                    pings += 1
                    if pings < target:
                        _ = ring.send_copy(done.fd, view, fixed=True)
                ring.recycle_buffer(done.bid)
    var t1 = perf_counter_ns()
    for i in range(conns):
        _ = ring.close_fd(afds[i], fixed=True)
        _ = ring.close_fd(cfds[i], fixed=True)
    _ = ring.wait(min_complete=conns * 2)
    while True:
        var c = ring.next_completion()
        if not c:
            break
        _ = c.take()
    _ = sys_close(lfd)
    return Float64(target) / (Float64(t1 - t0) / 1e9)


def _pair_listener(port: UInt16) raises -> Int32:
    """Just the listening side of a _pair, returned as a raw fd."""
    var rc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if rc < 0:
        raise Error("bench: socket " + errno_message(Int32(-rc)))
    var lfd = Int32(rc)
    var one = Int32(1)
    _ = sys_setsockopt(
        lfd,
        SOL_SOCKET,
        SO_REUSEADDR,
        UnsafePointer(to=one).bitcast[UInt8](),
        4,
    )
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var ip = IpAddress.v4(127, 0, 0, 1)
    var alen = write_sockaddr(
        sa.unsafe_ptr(), False, ip.octets, port
    )
    _ = sys_bind(lfd, sa.unsafe_ptr(), Int(alen))
    _ = sys_listen(lfd, 256)
    return lfd


def _pair_local_port(lfd: Int32) raises -> UInt16:
    """Read the kernel-chosen local port of a listening socket."""
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var alen = UInt32(SOCKADDR_STORAGE_SIZE)
    _ = sys_getsockname(lfd, sa.unsafe_ptr(), UnsafePointer(to=alen))
    return (UInt16(sa[2]) << 8) | UInt16(sa[3])


def _bench_poller(msg_size: Int, rounds: Int) raises -> Float64:
    var p = _pair(UInt16(19823))
    var afd = p[0]
    var cfd = p[1]
    set_nonblocking(afd, True)
    var poller = Poller.open()
    poller.register(afd, readable=True, writable=False)
    var msg = List[UInt8](length=msg_size, fill=0x42)
    var buf = List[UInt8](length=msg_size, fill=0)
    var t0 = perf_counter_ns()
    for _ in range(rounds):
        _ = sys_send(cfd, msg.unsafe_ptr(), msg_size, MSG_NOSIGNAL)
        # server side: epoll-driven read of the full message, then echo
        var got = 0
        while got < msg_size:
            var events = poller.wait(timeout_ms=1000)
            for e_idx in range(len(events)):
                if events[e_idx].is_readable():
                    while got < msg_size:
                        var n = sys_recv(
                            afd,
                            buf.unsafe_ptr() + got,
                            msg_size - got,
                            MSG_DONTWAIT,
                        )
                        if n <= 0:
                            break
                        got += Int(n)
        _ = sys_send(afd, buf.unsafe_ptr(), msg_size, MSG_NOSIGNAL)
        var back = 0
        while back < msg_size:
            var n = sys_recv(cfd, buf.unsafe_ptr() + back, msg_size - back, 0)
            back += Int(n)
    var t1 = perf_counter_ns()
    poller.unregister(afd)
    _ = sys_close(afd)
    _ = sys_close(cfd)
    return Float64(rounds) / (Float64(t1 - t0) / 1e9)


def main() raises:
    print("=== single-connection ping-pong (rt/s) ===")
    for size_sel in range(2):
        var msg_size = 64 if size_sel == 0 else 16384
        var rounds = 20000 if size_sel == 0 else 8000
        var blocking = _bench_blocking(msg_size, rounds)
        var poller = _bench_poller(msg_size, rounds)
        var ring = _bench_ring_single(msg_size, rounds)
        print(
            String(msg_size) + "B:",
            " blocking",
            Int(blocking),
            " epoll",
            Int(poller),
            " ring",
            Int(ring),
        )
    print()
    print("=== fan-out: many parallel conns through one ring (rt/s) ===")
    # at high concurrency the ring batches completions; one wait()
    # reaps a burst, amortizing the per-op cost the single-conn test
    # has to pay one-at-a-time.
    var conn_counts = List[Int](capacity=3)
    conn_counts.append(8)
    conn_counts.append(64)
    conn_counts.append(256)
    for ci in range(len(conn_counts)):
        var conns = conn_counts[ci]
        var per = 1500
        var rate = _bench_ring_fanout(64, per, conns)
        var rate_sq = _bench_ring_fanout(64, per, conns, sqpoll=True)
        var rate_dx = _bench_ring_fanout_direct(64, per, conns)
        var rate_dx_sq = _bench_ring_fanout_direct(64, per, conns, sqpoll=True)
        print(
            String(conns) + " conns x 64B: ",
            " ring",
            Int(rate),
            " +sqpoll",
            Int(rate_sq),
            " +direct",
            Int(rate_dx),
            " +direct+sqpoll",
            Int(rate_dx_sq),
            "rt/s",
        )
