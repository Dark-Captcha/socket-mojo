# Echo round-trip throughput: the io_uring Ring (multishot recv +
# provided buffers) vs the epoll Poller tier vs plain blocking
# sockets. Loopback, one connection, ping-pong — measures engine
# overhead per operation, the number a protocol driver actually pays.
#
# Run: pixi run mojo run -I . benchmarks/bench_ring.mojo

from std.time import perf_counter_ns

from socket._libc import (
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    SOCKADDR_STORAGE_SIZE,
    bind as libc_bind,
    close as libc_close,
    connect as libc_connect,
    errno,
    errno_message,
    listen as libc_listen,
    recv as libc_recv,
    send as libc_send,
    setsockopt,
    socket as libc_socket,
    write_sockaddr,
)
from socket.addr import IpAddress, SocketAddr
from socket.nonblocking import set_nonblocking
from socket.poller import Poller
from socket.ring import KIND_RECV, KIND_RECV_MULTI, KIND_SEND, Ring


def _pair(port: UInt16) raises -> Tuple[Int32, Int32]:
    """(accepted_fd, client_fd) over loopback, blocking handshake.
    `port` is a hint; bind picks an ephemeral port if `port == 0`."""
    var lfd = libc_socket(Int32(AF_INET), Int32(SOCK_STREAM), Int32(0))
    var one = Int32(1)
    _ = setsockopt(
        lfd,
        Int32(SOL_SOCKET),
        Int32(SO_REUSEADDR),
        UnsafePointer(to=one).bitcast[UInt8](),
        4,
    )
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var ip = IpAddress.v4(127, 0, 0, 1)
    var alen = write_sockaddr(sa.unsafe_ptr(), False, ip.octets, port)
    if libc_bind(lfd, sa.unsafe_ptr(), alen) != 0:
        raise Error("bench: bind " + errno_message(errno()))
    # if port == 0 the kernel picked; pull it back into `sa` for connect
    if port == 0:
        var got = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var glen = UInt32(SOCKADDR_STORAGE_SIZE)
        _ = external_call["getsockname", Int32](
            lfd, got.unsafe_ptr(), UnsafePointer(to=glen)
        )
        sa[2] = got[2]
        sa[3] = got[3]
    _ = libc_listen(lfd, 1)
    var cfd = libc_socket(Int32(AF_INET), Int32(SOCK_STREAM), Int32(0))
    if libc_connect(cfd, sa.unsafe_ptr(), alen) != 0:
        raise Error("bench: connect " + errno_message(errno()))
    var afd = external_call["accept", Int32](lfd, UInt(0), UInt(0))
    _ = libc_close(lfd)
    return (afd, cfd)


from std.ffi import external_call
from std.memory import UnsafePointer


def _bench_blocking(msg_size: Int, rounds: Int) raises -> Float64:
    var p = _pair(UInt16(19821))
    var afd = p[0]
    var cfd = p[1]
    var msg = List[UInt8](length=msg_size, fill=0x42)
    var buf = List[UInt8](length=msg_size, fill=0)
    var t0 = perf_counter_ns()
    for _ in range(rounds):
        _ = libc_send(cfd, msg.unsafe_ptr(), msg_size, Int32(0x4000))
        var got = 0
        while got < msg_size:
            var n = libc_recv(
                afd, buf.unsafe_ptr() + got, msg_size - got, Int32(0)
            )
            got += Int(n)
        _ = libc_send(afd, buf.unsafe_ptr(), msg_size, Int32(0x4000))
        got = 0
        while got < msg_size:
            var n = libc_recv(
                cfd, buf.unsafe_ptr() + got, msg_size - got, Int32(0)
            )
            got += Int(n)
    var t1 = perf_counter_ns()
    _ = libc_close(afd)
    _ = libc_close(cfd)
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
            if done.kind == KIND_RECV_MULTI:
                if not done.more or done.res <= 0:
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
    msg_size: Int, rounds: Int, conns: Int
) raises -> Float64:
    # The shape io_uring is actually built for: many concurrent
    # connections through ONE ring. Each conn ping-pongs in parallel;
    # one wait() reaps a burst of completions per syscall.
    var ring = Ring(max(256, conns * 4))
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
            if done.kind == KIND_RECV_MULTI:
                if not done.more or done.res <= 0:
                    continue
                var view = ring.buffer_view(done.bid, Int(done.res))
                # is this an "a" side (server) or "c" side (client) fd?
                var is_server = False
                for i in range(conns):
                    if afds[i] == done.fd:
                        is_server = True
                if is_server:
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
        _ = libc_send(cfd, msg.unsafe_ptr(), msg_size, Int32(0x4000))
        # server side: epoll-driven read of the full message, then echo
        var got = 0
        while got < msg_size:
            var events = poller.wait(timeout_ms=1000)
            for e_idx in range(len(events)):
                if events[e_idx].is_readable():
                    while got < msg_size:
                        var n = libc_recv(
                            afd,
                            buf.unsafe_ptr() + got,
                            msg_size - got,
                            Int32(0x40),  # MSG_DONTWAIT
                        )
                        if n <= 0:
                            break
                        got += Int(n)
        _ = libc_send(afd, buf.unsafe_ptr(), msg_size, Int32(0x4000))
        var back = 0
        while back < msg_size:
            var n = libc_recv(
                cfd, buf.unsafe_ptr() + back, msg_size - back, Int32(0)
            )
            back += Int(n)
    var t1 = perf_counter_ns()
    poller.unregister(afd)
    _ = libc_close(afd)
    _ = libc_close(cfd)
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
        print(String(conns) + " conns x 64B:", " ring", Int(rate), "rt/s")
