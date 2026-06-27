# Long-running soak: 100k ping-pong rounds in a single Ring +
# 50k slot-recycle NOPs. Asserts:
#   * `ring.inflight` returns to 0 after every drain
#   * slot table stays bounded (recycling works)
#   * no fd leak (the kernel returns the same low fd number for a
#     probe socket before and after the run)
#
# Run on demand:
#   pixi run mojo run -I . tests/test_soak.mojo
#
# Not part of `run_tests.mojo` — too slow for CI (takes ~5s).

from std.memory import UnsafePointer
from std.time import perf_counter_ns

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


def _fresh_socket() raises -> Int32:
    var rc = sys_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    if rc < 0:
        raise Error("soak: socket " + errno_message(Int32(-rc)))
    return Int32(rc)


def _listen_on(port: UInt16) raises -> Int32:
    var lfd = _fresh_socket()
    var one = Int32(1)
    _ = sys_setsockopt(
        lfd,
        SOL_SOCKET,
        SO_REUSEADDR,
        UnsafePointer(to=one).bitcast[UInt8](),
        4,
    )
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var ip = Ipv4Address(127, 0, 0, 1)
    var alen = write_sockaddr(sa.unsafe_ptr(), SocketAddr.v4(ip, port))
    if sys_bind(lfd, sa.unsafe_ptr(), Int(alen)) != 0:
        raise Error("soak: bind")
    if sys_listen(lfd, 8) != 0:
        raise Error("soak: listen")
    return lfd


def _check(cond: Bool, msg: String) raises:
    if not cond:
        raise Error("SOAK FAIL: " + msg)


def _soak_nops() raises:
    """50k NOP submissions, drained in batches of 128. Exercises
    slot recycling — every slot in a 64-entry table gets used many
    times over."""
    var ring = Ring(128)
    var total = 50_000
    var batch = 128
    var done = 0
    while done < total:
        var n = batch if total - done >= batch else total - done
        for _ in range(n):
            _ = ring.nop()
        _ = ring.wait(min_complete=n)
        var got = 0
        while True:
            var c = ring.next_completion()
            if not c:
                break
            _ = c.take()
            got += 1
        _check(got == n, "drained != submitted")
        _check(ring.inflight == 0, "inflight nonzero after drain")
        done += n
    # The slot table grew at most up to `batch` entries (the peak
    # concurrent inflight), not to `total`. That's recycling working.
    _check(
        len(ring.slots) <= 2 * batch,
        "slot table grew without bound (recycling broken)",
    )
    print(
        "  nop soak:",
        total,
        "ops drained,",
        len(ring.slots),
        "slots peak",
    )


def _soak_echo() raises:
    """100k ping-pong rounds on a single in-process loopback pair,
    driven by one Ring. Exercises every accept/connect/send/recv/
    close path, including buffer recycling."""
    var ring = Ring(64)
    var port = UInt16(19799)
    var lfd = _listen_on(port)

    # Set up one connection.
    var cfd = _fresh_socket()
    var dest = SocketAddr.v4(Ipv4Address(127, 0, 0, 1), port)
    _ = ring.accept(lfd)
    _ = ring.connect(cfd, dest)
    _ = ring.wait(min_complete=2)
    var afd = Int32(-1)
    for _ in range(2):
        var c = ring.next_completion()
        var done = c.take()
        done.ok()
        if done.kind == CompletionKind.ACCEPT:
            afd = done.res
    _check(afd > 0, "accept failed in setup")

    var rounds = 100_000
    var t0 = perf_counter_ns()
    var msg = String("soak ping").as_bytes()
    var msg_len = len(msg)
    for i in range(rounds):
        var payload = List[UInt8](capacity=msg_len)
        payload.extend(msg)
        _ = ring.send(cfd, payload^)
        _ = ring.recv(afd, 256)
        _ = ring.wait(min_complete=2)
        var saw_send = False
        var saw_recv = False
        for _ in range(2):
            var c = ring.next_completion()
            var done = c.take()
            done.ok()
            if done.kind == CompletionKind.SEND:
                saw_send = True
            elif done.kind == CompletionKind.RECV:
                saw_recv = True
                _check(Int(done.res) == msg_len, "recv length mismatch")
        _check(saw_send and saw_recv, "missing send/recv completion")
        _check(ring.inflight == 0, "inflight nonzero between rounds")
        if (i + 1) % 25_000 == 0:
            print(
                "  echo soak:",
                i + 1,
                "/",
                rounds,
                "rounds; slots =",
                len(ring.slots),
            )
    var t1 = perf_counter_ns()
    var rate = Float64(rounds) / (Float64(t1 - t0) / 1e9)

    # Tear down through the ring.
    _ = ring.close_fd(cfd)
    _ = ring.close_fd(afd)
    _ = ring.close_fd(lfd)
    _ = ring.wait(min_complete=3)
    while True:
        var c = ring.next_completion()
        if not c:
            break
        _ = c.take()
    _check(ring.inflight == 0, "drained")
    _check(len(ring.slots) <= 16, "slot table grew during echo soak")
    print(
        "  echo soak:",
        rounds,
        "rounds @",
        Int(rate),
        "rt/s, peak slots",
        len(ring.slots),
    )


def main() raises:
    print("=== socket-mojo soak ===")
    # Baseline fd number — kernel assigns lowest free fd, so a leak
    # would push subsequent probes' fds higher.
    var pre = _fresh_socket()
    _ = sys_close(pre)
    print("baseline fd:", Int(pre))

    _soak_nops()
    _soak_echo()

    var post = _fresh_socket()
    _ = sys_close(post)
    print("post fd:    ", Int(post))
    # Small slack for the ring's own internal fd (the io_uring fd
    # itself, plus mmap'd handles). The Ring goes out of scope
    # before we sample `post` so the io_uring fd is already freed.
    _check(
        Int(post) <= Int(pre) + 2,
        "fd table grew across the soak (leak suspected)",
    )
    print("SOAK PASS")
