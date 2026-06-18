# Changelog

Per-release notes for socket-mojo. Dates are commit dates;
versions are tagged in `pixi.toml`.

## v0.2.0 — 2026-06-18

The "production polish" release. Library reaches single-core
parity with C/liburing.

### Engine — zero libc

- Direct Linux syscalls via `std.sys.intrinsics.inlined_assembly`.
  The library now references **zero libc symbols** anywhere.
- Native DNS resolver: `/etc/hosts` + `/etc/resolv.conf` + RFC 1035
  over the Ring. No more `getaddrinfo`.
- Inline-asm syscall trampoline returns the kernel ABI directly
  (`-errno` on failure), no TLS `errno` slot read.

### Engine — new opcodes & flags

- `accept_direct` / `accept_multishot_direct` / `socket_direct`,
  `recv/send/connect/close_fd(fixed=True)` — registered fd table.
- `send(zero_copy=True)` — `OP_SEND_ZC` with the two-CQE protocol
  (data-in-kernel CQE surfaced; buffer-reusable notif drained
  internally).
- `Ring.msg_ring(target_fd, payload, target_res)` —
  `OP_MSG_RING` for cross-ring (and cross-thread / cross-process)
  signalling.
- `Ring(sqpoll=True, single_issuer=True, defer_taskrun=True,
  coop_taskrun=True)` — modern taskrun flags (Linux 5.19 / 6.0+).
- `TcpListener.bind(reuseport=True)` — `SO_REUSEPORT` for multi-
  process scaling.
- `Ring.send_borrowed(addr, length)` — unsafe-but-fast send that
  references caller-owned memory directly (no per-call alloc).

### Engine — correctness fixes

- `recv_with_timeout` no longer leaks the link-timeout partner
  slot; the engine drains that CQE internally.
- Generation counter widened from 16 to 24 bits (collision
  window: 65 k → 16 M slot recycles).
- `accept4(SOCK_CLOEXEC)` replaces `accept(2) + fcntl`.
- All `MutUnsafeAnyOrigin` implicit-conversion deprecation
  warnings fixed.

### Typed errors

- `socket/errors.mojo`: predicates over the stable error-string
  contract (`is_connection_refused`, `is_timed_out`,
  `is_dns_error`, `is_would_block`, ...) plus `errno_of(e)`
  extractor.

### Project layout

- LICENSE (Apache 2.0).
- `README.md` with quickstart examples (blocking client, Ring
  server, SQPOLL + direct fds, DNS, typed errors).
- `WINDOWS.md` with the full IOCP port plan.
- `examples/http_get.mojo` — real-Internet end-to-end test
  against `example.com:80`.
- `tests/test_errors.mojo` + `tests/test_ring_direct.mojo`.
- `tests/test_soak.mojo` — 150 k-op soak with fd-leak check.
- `benchmarks/bench_proc.mojo` + `run_bench_proc.sh` — two-
  process kernel-TCP loopback benchmark.
- `benchmarks/cross_lang/` — same workload in Go, Python, and
  C/liburing for honest comparison.
- Refactor to Agent-ToolKit `mojo.md v1.1.0` standards:
  - `SYS_*` constants in `SCREAMING_SNAKE`.
  - Tests follow `def run() raises -> Int:` returning failure
    count; `run_tests.mojo` aggregates and reports total.
- `.probe/` directory removed.

### Performance

Loopback two-process ping-pong, 64 conns × 1500 rounds × 64 B,
median of 5 runs:

| Implementation              | rt/s    | % of C |
|-----------------------------|--------:|-------:|
| Python asyncio              |  ~64 k  | 23 %   |
| Go `net` (GOMAXPROCS=1)     | ~216 k  | 79 %   |
| socket-mojo Ring            | ~214 k  | 78 %   |
| **socket-mojo + SQPOLL**    | **~270 k** | **98 %** |
| C + liburing                | ~274 k  | 100 %  |

Single-core io_uring ceiling effectively reached with SQPOLL.

## v0.1.0 — 2026-06-13

Initial baseline: io_uring Ring engine over libc-based syscall
wrappers. Multishot accept/recv, provided buffer rings, timers,
cancel. Sans-io DNS codec + Ring-driven resolver. Honest PERF.md.

(See git log for the M0 → M2 milestone commits leading up to
v0.2.0.)
