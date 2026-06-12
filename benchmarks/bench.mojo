# Throughput benchmarks for socket-mojo. Measures:
#   1. Connect+close rate (per-second)
#   2. Single-connection sustained TCP throughput (MiB/s) over loopback
#   3. read_exact vs read+loop path
#
# Run from outside the Mojo process; this file is launched AFTER an
# echo server is spawned on 127.0.0.1:29501 by tests/bench_helper.py.

from std.time import perf_counter_ns

from socket.tcp import TcpSocket


def _throughput_mibs(bytes_total: Int, elapsed_ns: UInt) -> Float64:
    return Float64(bytes_total) / 1048576.0 / (Float64(Int(elapsed_ns)) / 1e9)


def bench_connect_close(port: UInt16, n: Int) raises:
    var t0 = perf_counter_ns()
    for _ in range(n):
        var s = TcpSocket.connect("127.0.0.1", port, timeout_seconds=2.0)
        _ = s^.close()
    var t1 = perf_counter_ns()
    var per_op_us = Float64(Int(t1 - t0)) / 1e3 / Float64(n)
    print(
        "connect+close x ",
        n,
        ": ",
        per_op_us,
        " us/op (",
        1e6 / per_op_us,
        " ops/sec)",
        sep="",
    )


def bench_throughput(port: UInt16, *, bufsize: Int, total: Int) raises:
    """Send `total` bytes through a single echo connection, in `bufsize`
    chunks. We send then read each chunk so the kernel buffer doesn't
    overflow — the goal is steady-state sustained MiB/s."""
    var sock = TcpSocket.connect("127.0.0.1", port, timeout_seconds=30.0)
    var buf = List[UInt8](length=bufsize, fill=0xAB)
    var n_chunks = total // bufsize
    var t0 = perf_counter_ns()
    for _ in range(n_chunks):
        sock.write(buf)
        var got = sock.read_exact(bufsize)
        _ = len(got)
    var t1 = perf_counter_ns()
    var sent = n_chunks * bufsize
    print(
        "echo throughput bufsize=",
        bufsize,
        " total=",
        sent,
        " B: ",
        _throughput_mibs(sent, t1 - t0),
        " MiB/s (both directions)",
        sep="",
    )


def main() raises:
    var port = UInt16(29501)
    print("=== socket-mojo benchmarks (loopback) ===")
    bench_connect_close(port, 100)
    bench_throughput(port, bufsize=4096, total=64 * 1024 * 1024)
    bench_throughput(port, bufsize=65536, total=256 * 1024 * 1024)
    print("done.")
