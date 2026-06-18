# socket-mojo — Roadmap

What's next, in honest priority order. Everything below is best-
effort and pinned to Mojo language progress; items requiring
features Mojo doesn't expose yet are called out.

## Near-term (no language blockers)

1. **Multi-process SO_REUSEPORT benchmark.** We have the
   `reuseport=True` plumbing on `TcpListener.bind`; need an actual
   measurement on this 24-core box to publish the multi-core
   number. Expected: ~24 × single-core ≈ 6 M rt/s aggregate.
2. **`IORING_REGISTER_BUFFERS` + `OP_SEND_FIXED`.** Register a
   buffer pool with the kernel up front; `OP_SEND_FIXED` references
   them by index, skipping a per-send pin. Bigger win at larger
   payloads than `OP_SEND_ZC` for steady-state servers.
3. **Real-NIC numbers.** All current measurements are loopback.
   The whole point of `SEND_ZC`, direct fds, and the modern
   taskrun flags is that they win MORE on a real NIC where the
   driver-IRQ path is the cost. Without a second host, we don't
   know the real numbers.
4. **CQE-batch advance.** Replace the per-CQE `fetch_add(1)` on
   `cq_head` with one advance-by-N at the end of a drain (matches
   liburing's `io_uring_for_each_cqe` pattern). Worth ~1–3 % on
   tight loops; harmless to the engine.
5. **Slot table pre-allocation.** `Ring(entries)` currently grows
   `slots` lazily. Pre-size at construction so the hot loop's
   first ops don't pay the `List.append` cost.

## Medium-term (small Mojo blockers)

6. **Async/await sugar (`await stream.read()`).** Lands when
   Mojo's coroutines stop being parse-only. The completion engine
   is the right substrate already; this is purely a syntax sugar
   layer on top of `Ring.next_completion()`.
7. **Thread-per-core in-process.** Needs Mojo to expose a
   C-callable function pointer (or native threading API). The
   `OP_MSG_RING` primitive is ready for it today. Until then,
   multi-process via `SO_REUSEPORT` is the recipe.
8. **Custom origin types instead of `MutAnyOrigin` discard.** A
   handful of call sites use `.as_unsafe_any_origin()` to satisfy
   `MutAnyOrigin` parameters where origin-polymorphic signatures
   would be cleaner. Wait for Mojo's origin model to settle.

## Big rocks

9. **Windows IOCP backend.** Skeleton in `socket/iocp_sys.mojo`;
   port plan in `WINDOWS.md`. Needs a Windows CI host + someone
   who knows the IOCP idioms well.
10. **macOS kqueue backend.** Separate effort from Windows;
    kqueue is readiness-based (more like epoll than IOCP) so it
    plugs into the `Poller` layer, not the `Ring`.
11. **ARM64 / aarch64 support.** Syscall numbers differ on ARM
    (and so do a few syscall ABIs — clone/clone3 in particular).
    Either inline-asm branches via `comptime if CompilationTarget`
    or a separate `_syscalls_aarch64.mojo`.

## Above this library (separate repos)

12. **tls-mojo.** TLS 1.2 / 1.3 as a sans-io state machine on
    `crypto-mojo`. Records in / plaintext out, plus handshake
    actions. socket-mojo just moves the bytes.
13. **http-mojo.** HTTP/1.1 then 2 then 3 (over QUIC, which uses
    `socket-mojo`'s UDP path). Same sans-io shape.
14. **ws-mojo, mail-mojo, dns-server-mojo.** Same pattern.

## Won't fix

- **General async runtime.** socket-mojo is the I/O engine, not a
  framework. Executors, futures, task supervision — that's a
  separate library.
- **In-process TLS.** Belongs in `tls-mojo`.
- **Multishot accept with per-completion peer addr.** Current
  kernel io_uring doesn't support this (no per-CQE sockaddr
  buffer mechanism for accept). Workaround: single-shot
  `accept_direct` (which DOES carry peer addr) re-armed by the
  user.

## How this list changes

We bump items up when they're committed; we add new ones as we
discover gaps. Anything in §11 stays there until Mojo's
toolchain crosses the line that lets us start. Items in §"Won't
fix" are explicit non-goals — they may be reconsidered if the
shape changes but they shouldn't be silently adopted.
