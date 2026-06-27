# Two-process benchmark — closer to real-NIC behaviour than the in-
# process loopback in bench_ring.mojo. The kernel mediates a full
# TCP path across the process boundary, exercising the actual socket
# layer instead of taking the same-process shortcut.
#
# Usage:
#   pixi run mojo run -I . benchmarks/bench_proc.mojo server <port> <conns> [sqpoll]
#   pixi run mojo run -I . benchmarks/bench_proc.mojo client <port> <conns> <rounds> [payload] [sqpoll]
#
# Pass "sqpoll" as the last positional arg to engage the kernel SQ
# poller on both ends. Payload defaults to 64 bytes.
#
# The shell driver below spawns both:
#   ./benchmarks/run_bench_proc.sh

from std.sys import argv
from std.time import perf_counter_ns

from socket._syscalls import (
    AF_INET,
    SOCK_CLOEXEC,
    SOCK_STREAM,
    SOCKADDR_STORAGE_SIZE,
    SOL_SOCKET,
    SO_REUSEADDR,
    SO_REUSEPORT,
    errno_message,
    sys_bind,
    sys_close,
    sys_listen,
    sys_setsockopt,
    sys_socket,
    write_sockaddr,
)
from socket.addr import IpAddress, SocketAddr
from socket.ring import CompletionKind, Ring
from std.memory import UnsafePointer


def _bind_listener(port: UInt16, reuseport: Bool = False) raises -> Int32:
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
    if reuseport:
        _ = sys_setsockopt(
            lfd,
            SOL_SOCKET,
            SO_REUSEPORT,
            UnsafePointer(to=one).bitcast[UInt8](),
            4,
        )
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var ip = IpAddress.v4(127, 0, 0, 1)
    var alen = write_sockaddr(
        sa.unsafe_ptr(), False, ip.octets, port
    )
    if sys_bind(lfd, sa.unsafe_ptr(), Int(alen)) != 0:
        raise Error("bench: bind")
    if sys_listen(lfd, 1024) != 0:
        raise Error("bench: listen")
    return lfd


def _run_server(
    port: UInt16, conns: Int, sqpoll: Bool, reuseport: Bool = False
) raises:
    """Echo server. Accepts `conns` connections via multishot accept,
    arms multishot recv on each, echoes everything back. Exits when
    every connection has closed cleanly. Reports nothing — the client
    is the timing authority."""
    var ring = Ring(
        max(256, conns * 4),
        sqpoll=sqpoll,
        sqpoll_idle_ms=2000,
        defer_taskrun=not sqpoll,  # defer_taskrun doesn't compose with sqpoll
    )
    ring.setup_buffers(entries=max(128, conns * 2), buf_size=16384, bgid=0)
    var lfd = _bind_listener(port, reuseport)
    _ = ring.accept_multishot(lfd)

    var accepted = 0
    var closed = 0
    while closed < conns:
        _ = ring.wait(min_complete=1)
        while True:
            var c = ring.next_completion()
            if not c:
                break
            var done = c.take()
            if done.kind == CompletionKind.ACCEPT_MULTI:
                if done.res > 0:
                    _ = ring.recv_multishot(done.res)
                    accepted += 1
            elif done.kind == CompletionKind.RECV_MULTI:
                if done.res <= 0:
                    if done.bid >= 0:
                        ring.recycle_buffer(done.bid)
                    if not done.more:
                        closed += 1
                    continue
                # Echo and recycle.
                var view = ring.buffer_view(done.bid, Int(done.res))
                _ = ring.send_copy(done.fd, view)
                ring.recycle_buffer(done.bid)
    _ = sys_close(lfd)


def _run_client(
    port: UInt16, conns: Int, rounds: Int, payload_size: Int, sqpoll: Bool
) raises:
    """Open `conns` sockets, ping-pong each `rounds` times, print
    rt/s. Mirrors the existing in-process fan-out benchmark but the
    other end is a separate process talking through real loopback
    TCP."""
    var ring = Ring(
        max(256, conns * 4),
        sqpoll=sqpoll,
        sqpoll_idle_ms=2000,
        defer_taskrun=not sqpoll,
    )
    ring.setup_buffers(
        entries=max(128, conns * 2),
        buf_size=max(16384, payload_size * 2),
        bgid=0,
    )
    var dest = SocketAddr(IpAddress.v4(127, 0, 0, 1), port)

    # Open + connect each socket.
    var fds = List[Int32]()
    for _ in range(conns):
        var rc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
        if rc < 0:
            raise Error("bench client: socket")
        var fd = Int32(rc)
        _ = ring.connect(fd, dest)
        fds.append(fd)
    _ = ring.wait(min_complete=conns)
    var connected = 0
    while connected < conns:
        var c = ring.next_completion()
        if not c:
            _ = ring.wait(min_complete=1)
            continue
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.CONNECT:
            connected += 1

    # Arm recv on every conn and prime the first ping.
    for i in range(conns):
        _ = ring.recv_multishot(fds[i])
    var msg = List[UInt8](length=payload_size, fill=0x42)
    for i in range(conns):
        _ = ring.send_copy(fds[i], Span(msg))

    var target = rounds * conns
    var pings = 0
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
                    if done.bid >= 0:
                        ring.recycle_buffer(done.bid)
                    continue
                var view = ring.buffer_view(done.bid, Int(done.res))
                pings += 1
                if pings < target:
                    _ = ring.send_copy(done.fd, view)
                ring.recycle_buffer(done.bid)
    var t1 = perf_counter_ns()
    var rate = Float64(target) / (Float64(t1 - t0) / 1e9)
    var mode = "sqpoll" if sqpoll else "ring  "
    print(
        "two-proc",
        mode,
        " ",
        conns,
        "conns x",
        rounds,
        "rounds @",
        payload_size,
        "B →",
        Int(rate),
        "rt/s",
    )
    for i in range(conns):
        _ = sys_close(fds[i])


def _arg(args: List[String], i: Int, fallback: String) -> String:
    return args[i] if i < len(args) else fallback


def _has(args: List[String], needle: String) -> Bool:
    for i in range(len(args)):
        if args[i] == needle:
            return True
    return False


def main() raises:
    var args = argv()
    var args_list = List[String]()
    for i in range(len(args)):
        args_list.append(String(args[i]))
    if len(args_list) < 3:
        print(
            "usage: bench_proc.mojo {server <port> <conns> [sqpoll]"
            " | client <port> <conns> <rounds> [payload] [sqpoll]}"
        )
        return
    var role = args_list[1]
    var port = UInt16(Int(args_list[2]))
    var sqpoll = _has(args_list, String("sqpoll"))
    var reuseport = _has(args_list, String("reuseport"))
    if role == "server":
        var conns = Int(_arg(args_list, 3, String("64")))
        if conns <= 0:
            conns = 64
        _run_server(port, conns, sqpoll, reuseport=reuseport)
    elif role == "client":
        var conns = Int(_arg(args_list, 3, String("64")))
        if conns <= 0:
            conns = 64
        var rounds = Int(_arg(args_list, 4, String("1000")))
        if rounds <= 0:
            rounds = 1000
        var payload = Int(_arg(args_list, 5, String("64")))
        if payload <= 0:
            payload = 64
        _run_client(port, conns, rounds, payload, sqpoll)
    else:
        print("unknown role:", role)
