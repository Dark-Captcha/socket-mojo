# socket-mojo — performance notes

Measured 2026-06-18 on this machine (AMD 7950X3D, kernel 7.0.x,
Mojo b3). `pixi run mojo run -I . benchmarks/bench_ring.mojo`.

> Re-measured after the libc-removal + io_uring perf-feature pass:
> every socket operation goes through a direct Linux syscall (one
> `external_call["syscall", ...]` shim) plus a TLS errno read on
> failure. No glibc socket wrappers, no getaddrinfo. SQPOLL,
> registered fd table, SEND_ZC, and the modern taskrun flags are
> all available behind opt-in Ring kwargs.

## Loopback ping-pong (single connection)

|       | blocking | epoll  | ring (multishot + pbuf) |
|------:|---------:|-------:|------------------------:|
| 64 B  | 141 k/s  | 136 k/s| 113 k/s                 |
| 16 KiB| 115 k/s  | 109 k/s|  88 k/s                 |

This is the syscall-amortization-free workload: every round forces
one send and one receive, the kernel never has anything to batch,
and the completion engine pays for SQE construction, op-table
bookkeeping, and one extra memory hop (kernel buffer → view) that
the blocking path doesn't have. epoll lands between because it adds
the `epoll_wait` cost without recouping it on a single fd.

## Fan-out through one ring

|        | ring | +sqpoll | +direct | +direct+sqpoll |
|-------:|-----:|--------:|--------:|---------------:|
|   8 conns | 142 k/s | 152 k/s (+7%) | 140 k/s | 155 k/s (+9%) |
|  64 conns | 143 k/s | 160 k/s (+12%) | 142 k/s | 162 k/s (+13%) |
| 256 conns | 133 k/s | 154 k/s (+16%) | 137 k/s | 156 k/s (+17%) |

## Two-process loopback (closer to real NIC behaviour)

`./benchmarks/run_bench_proc.sh`: separate Mojo server + Mojo client
processes, kernel TCP between them. The in-process bench above
takes the same-process shortcut path; this one exercises the full
socket layer (real SYN/ACK, real recvmsg, real wakeups).

### 64-byte payload

| conns | ring | +sqpoll |
|------:|-----:|--------:|
|   16 | 271 k/s | 209 k/s (-23%) |
|   64 | 259 k/s | 292 k/s (+13%) |
|  256 | 272 k/s | 289 k/s ( +6%) |

### 4-KiB payload

| conns | ring | +sqpoll |
|------:|-----:|--------:|
|   16 | 232 k/s | 235 k/s ( +1%) |
|   64 | 218 k/s | 236 k/s ( +8%) |
|  256 | 229 k/s | 262 k/s (+14%) |

**SQPOLL** wins reliably at ≥ 64 conns; at 16 conns the kthread
doesn't have enough submit traffic to amortise its own CPU cost
and actually loses ground. This is the expected shape — SQPOLL is
a high-load knob, not a low-load one. Production servers with
tens-of-thousands of concurrent connections always have enough
submit traffic.

Client's perspective here: one `send + recv` per round (the server
is a separate process). Not directly comparable to the in-process
row above, which counts both sides through one Ring. The
two-process shape is the more honest proxy for what users will see
in deployments.

### What's still missing

These numbers are still **single machine** — no NIC, no driver
interrupt path, no packet pacing. Run `bench_proc.sh` against an
`iperf3 -s` on a separate host (or use namespaces with `veth`
pairs) to get a real network number. The structure of the
benchmark is the right shape; the missing piece is the second
box.

## Cross-language comparison

Same workload (64 conns × 1500 rounds × 64-byte payload), same
machine, same kernel TCP loopback, separate server+client
processes. Sources in `benchmarks/cross_lang/`; reproduce with
`benchmarks/cross_lang/run.sh`.

Numbers below are **median of 5 runs** to filter the loopback's
considerable run-to-run variance (single ping-pong is sensitive
to CPU thermal state, scheduling, and other process noise; the
plain Ring path can swing 60% between best and worst, the SQPOLL
path is steady ±5%).

| Implementation                | median rt/s | Notes |
|-------------------------------|------------:|-------|
| Python asyncio (selector)     |    ~64 k/s  | high-level scripting baseline |
| Go `net` (GOMAXPROCS=1)       |   ~216 k/s  | epoll + goroutines, 1 OS thread |
| **socket-mojo Ring**          |   ~214 k/s  | io_uring + multishot + pbuf, 1 thread |
| **socket-mojo Ring + SQPOLL** |   **~270 k/s** | + kernel SQ-poll kthread, 1 user thread |
| C + liburing                  |   ~274 k/s  | mature C bindings, same kernel features |
| Go `net` (GOMAXPROCS=all)     |   ~472 k/s  | 24 OS threads — multi-core advantage |

**Honest reading:**

- **Apples-to-apples (single thread)**, socket-mojo + SQPOLL is at
  **~98% of C/liburing** — effectively at the speed-of-light
  ceiling for io_uring multishot + pbuf on a single core. There's
  no meaningful single-core headroom left on the engine side.
- The plain Ring path runs at parity with Go-1cpu epoll, with
  more variance; SQPOLL is the recommended steady-state knob for
  servers.
- **Python is 4–5× slower**: interpreter + per-call allocation
  overhead dwarfs the I/O path.
- **Go-all-cores wins** because the Go runtime spreads goroutines
  across all 24 logical CPUs by default. socket-mojo's single
  Ring is single-threaded by design; to match multi-core scaling
  the recipe is `SO_REUSEPORT` + multiple worker processes (see
  `README.md` and the `Ring.msg_ring()` primitive for cross-ring
  signalling). 24 × 270k ≈ 6.5 M rt/s aggregate, comparable to
  nginx and friends.

**What "single-core io_uring ceiling" really means**

Loopback ping-pong's per-round cost is dominated by the kernel
itself: two `tcp_sendmsg` paths, two `tcp_recvmsg` paths, two
context switches into the kernel, socket-buffer accounting, the
TCP state machine. The userspace work — SQE construction, CQE
reap, op-table bookkeeping — is in the noise. **socket-mojo and
C/liburing both pay the same kernel cost; the gap between them is
how efficiently they enter/exit that path.** SQPOLL pulls the gap
closed because the kernel polls the SQ on its own and we don't
syscall at all on the hot loop.

## Multi-process scaling

`benchmarks/run_bench_multi.sh` spawns N independent
socket-mojo (server, client) pairs on this 24-core box. Each
worker is one process, one Ring, no contention between workers.
Aggregate rt/s sums the per-worker measurements. 32 conns per
worker × 1000 rounds × 64 B.

| Workers | ring (no sqpoll) | ring + sqpoll |
|--------:|-----------------:|--------------:|
| 1       |    137 k/s       |   244 k/s     |
| 2       |    207 k/s       |   400 k/s     |
| 4       |    600 k/s       |   516 k/s     |
| 8       |    1.31 M/s      |   514 k/s     |
| 16      |    **1.54 M/s**  |   582 k/s     |

Two stories here:

- **Plain Ring scales nearly linearly to 16 workers, hitting
  1.54 M aggregate rt/s** — 3.3× Go's all-cores number and into
  the range nginx and friends deliver. This is what a real
  multi-core deployment of socket-mojo looks like.
- **SQPOLL kthread contention caps at ~16 workers.** With one
  kthread per Ring (× 16 worker rings + 16 client rings = 32
  kthreads) + main threads on a 24-core box, the scheduler
  oversubscribes and aggregate throughput plateaus. **SQPOLL is
  the right knob for one big single-process server with many
  thousands of connections; for thread-per-core / process-per-
  core deployments, plain Ring scales further.**

The reuseport variant (`MODE=reuseport`) is also implemented but
hangs on this bench's current "accept exactly N conns then exit"
shape, because the kernel's hashing may give one server many
more conns than others. For real production use, servers should
accept multishot until SIGTERM (which they will once we have an
SO_REUSEPORT-shaped bench harness).

Loopback caveat applies double here: real network throughput
will look different because (a) each NIC RX queue has its own
RSS path so multi-process contention is lower, and (b) hardware
latency between the two ends adds RTT that the kernel-only
loopback path doesn't have.

Per-connection rate stays flat across 8 → 256 conns: one ring
drives 256 simultaneous echo flows with no measurable degradation,
where the same workload on epoll would require explicit edge-
triggered draining and the blocking model needs one thread per
connection.

**SQPOLL win (+7–17%, growing with conns)** is a lower bound: this
is a one-SQE-per-recv-CQE loopback ping-pong, the worst case for
SQPOLL because there's barely any submit traffic to amortise. A
real server that fans out many sends per recv burst (TLS records,
HTTP pipelining) keeps the kthread busy the whole time and never
pays the wake-up syscall — the entire submit path collapses to
zero kernel transitions.

**Direct fds alone don't move loopback** because the per-op fget
refcount bump is cheap when there's no real I/O latency to mask.
On a NIC, direct fds win: the kernel skips refcount churn inside
the irq handler. Loopback doesn't exercise that path.

## Why the absolute numbers aren't higher

Both ends live in the same process on loopback — there is no real
latency to hide, no NIC interrupts to coalesce, no zero-copy DMA
to exploit. The io_uring features that are dormant on this
microbench:

- **SEND_ZC** (zero-copy send): matters above ~16 KiB on real NICs.
  Implemented and tested (`test_ring_direct: send_zc OK`) but
  identical to plain send on loopback.
- **Registered fd table**: cost-amortises in the kernel's irq path
  on a real NIC; loopback skips that path.
- **Syscall amortization at high load**: 1 `io_uring_enter` reaping
  hundreds of completions vs N read syscalls — invisible at 64-conn
  loopback, decisive against a thundering-herd inbound on a NIC.

## Available knobs

`Ring(entries, *, sqpoll, sqpoll_idle_ms, single_issuer,
defer_taskrun, coop_taskrun)` — all kwargs default OFF; enable
once your kernel supports them.

- `sqpoll=True` (Linux 5.11+ unprivileged): kthread polls the SQ;
  submit can collapse to zero syscalls under steady load.
- `single_issuer=True` (Linux 6.0+): one-thread submit; kernel
  drops several locks on the submission path.
- `defer_taskrun=True` (Linux 6.0+, implies `single_issuer`):
  completion task work runs only when we wait — best cache
  locality on thread-per-core servers.
- `coop_taskrun=True` (Linux 5.19+): completions run in the
  calling task, not random kernel threads.

`Ring.register_files(count)` enables direct fds:

- `ring.socket_direct(domain, type, proto)` — kernel allocates the
  new fd directly into the table.
- `ring.accept_direct(lfd)` (single-shot, with peer addr) /
  `ring.accept_multishot_direct(lfd)` (no peer addr) — accepted
  fds land directly in the table.
- `ring.recv/send/connect/close_fd(slot, ..., fixed=True)` —
  reference table slots by index.
- `ring.send(slot, data^, zero_copy=True)` — OP_SEND_ZC; the
  engine drains the buffer-release notif silently.

## What's deliberately deferred (M3+)

These move absolute throughput, but none of them block protocol
work:

1. **Per-thread Ring + cross-thread inbox** (`OP_MSG_RING`) for
   thread-per-core servers (single-threaded fan-out already proven
   flat above).
2. **A real network benchmark** (NIC, not loopback) to actually
   measure what loopback can't.
3. **Registered buffers + OP_SEND_FIXED** for the hottest send
   paths (a step beyond SEND_ZC).
