# socket-mojo — performance notes

Measured 2026-06-13 on this machine (AMD 7950X3D, kernel 7.0.x,
Mojo b2). `pixi run mojo run -I . benchmarks/bench_ring.mojo`.

> Re-measured 2026-06-13 after the audit pass. The fan-out figures
> below supersede the earlier ones: the harness used to do an O(conns²)
> per-completion server/client fd classification *inside the timed
> loop*, which depressed the 256-conn number; it is now an O(1) lookup,
> so the per-connection rate reads as genuinely flat. Single-connection
> numbers are unchanged within run-to-run noise (the audit's submit-path
> tweaks — one-shot SQE clear, uninitialized recv buffers — don't move a
> loopback ping-pong measurably).

## Loopback ping-pong (single connection)

|       | blocking | epoll  | ring (multishot + pbuf) |
|------:|---------:|-------:|------------------------:|
| 64 B  | 149 k/s  | 135 k/s| 114 k/s                 |
| 16 KiB| 119 k/s  | 108 k/s|  90 k/s                 |

The Ring runs ~75% of blocking here, and that is the **expected
shape**, not a regression. A 64-byte ping-pong is the
syscall-amortization-free workload: every round forces one send and
one receive, the kernel never has anything to batch, and the
completion engine pays for SQE construction, op-table bookkeeping,
and one extra memory hop (kernel buffer -> view) that the blocking
path doesn't have. epoll lands between because it adds the
`epoll_wait` cost without recouping it on a single fd.

## Fan-out through one ring (where io_uring is supposed to shine)

|        | rate (rt/s) |
|-------:|------------:|
|   8 conns | 142 k/s |
|  64 conns | 145 k/s |
| 256 conns | 142 k/s |

Per-connection rate stays flat: one ring drives 256 simultaneous
echo flows with no measurable degradation, where the same workload
on epoll would require explicit edge-triggered draining and the
blocking model needs one thread per connection. (The earlier table
showed 256 conns sagging to 136 k/s; that dip was a benchmark artifact
— an O(conns²) fd-classification scan in the timed loop — not the
engine, and it disappears once the scan is O(1).)

## Why the absolute number isn't bigger here

Both ends live in the same process on loopback — there is no real
latency to hide, no NIC interrupts to coalesce, no zero-copy DMA to
exploit. The io_uring features that are dormant on this microbench:

- **SEND_ZC** (zero-copy send via `sendmsg(MSG_ZEROCOPY)`-equivalent):
  matters above ~16 KiB on real NICs; M3 work.
- **Registered buffers / fixed files**: drop one indirection per op;
  M3 work.
- **Syscall amortization at high load**: 1 `io_uring_enter` reaping
  hundreds of completions vs N read syscalls — invisible at 64-conn
  loopback, decisive against a thundering-herd inbound on a NIC.
- **Real network latency**: with even a millisecond of RTT, the
  blocking model's one-thread-per-conn cost explodes; the Ring's
  flat fan-out becomes a strict win.

## Where the strength is **today**, beyond raw throughput

- **Correctness**: every io_uring feature lands with live kernel
  probes and external-truth tests. Multishot, buffer rings,
  link-timeouts, cancel — all verified against the kernel and against
  a python truth peer.
- **Engine completeness**: the Ring is a real completion engine
  (op-table-with-generations, ownership-safe buffers, typed
  completions, multishot lifecycle), not a thin syscall wrapper.
- **Protocol foundation**: the first sans-io protocol (DNS) is
  already on it — query/response codec, retry, TCP fallback,
  rcode handling — and it works against a deterministic truth
  server.

## What's deliberately deferred (M3+)

These move absolute throughput, but none of them block TLS work:

1. **SEND_ZC** for large records (TLS payloads >16 KiB).
2. **Registered fd table** for hot connections.
3. **Per-thread Ring + cross-thread inbox** for thread-per-core
   servers (single-threaded fan-out already proven flat above).
4. A real network benchmark (NIC, not loopback) to actually measure
   what loopback can't.
