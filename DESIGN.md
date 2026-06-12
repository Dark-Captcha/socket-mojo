# socket-mojo — Design (v1 rethink)

> Status: accepted 2026-06-13. Supersedes the tier-1/2 plan implied by
> v0.1–v0.3. Those layers stay (see "What already exists"), but the
> foundation everything else builds on is the completion engine below.

socket-mojo is the I/O base for an entire protocol stack written in
Mojo: tls-mojo, http-mojo (1.1/2/3), ws-mojo, mail-mojo (SMTP/IMAP),
dns. One library moves bytes; every protocol above it is a pure state
machine. Same culture as crypto-mojo: zero dependencies, modern
hardware/kernel interfaces over traditional patterns, and every piece
verified against external truth.

## The three decisions that matter

### 1. io_uring is the engine, not a backend

The kernel's completion model (submit operations, reap completions) is
the modern interface — batched syscalls, multishot operations,
kernel-managed buffer pools, zero-copy sends. Designing for "readiness"
(epoll-think: wake me when readable, then I call read) and bolting
io_uring underneath wastes exactly the features that make it fast.

So the core API is **completion-shaped** from day one:

```mojo
var ring = Ring(entries=4096)
var lst = listen_tcp(ring, "0.0.0.0", 8443)     # arms multishot accept
while serving:
    ring.submit_and_wait(min_complete=1)         # one syscall per burst
    for ev in ring.completions():
        # ev: op kind + conn id + result (buffer slice / status)
        ...
```

Proven in `.probe/uring_probe.mojo`: ring setup, mmap, SQE submit and
CQE reap work from pure Mojo via raw syscalls (425/426/427) — **no
liburing**, no new dependencies. The kernel ABI is the stable
interface, the rings are just shared memory, and this machine's kernel
reports the full modern feature set (features=0x3ffff).

Engine specifics:

- **user_data discipline**: every SQE carries a packed op id
  (table index | generation | kind). Generation counters make stale
  completions harmless (the ABA problem of fd reuse).
- **Multishot first**: multishot accept, multishot recv. One
  submission, a stream of completions — the steady state of a busy
  server submits almost nothing.
- **Provided buffer rings** (`IORING_REGISTER_PBUF_RING`): the Ring
  owns pooled receive buffers; the kernel picks one per completion and
  hands us a slice; we recycle it after the protocol consumes it. No
  per-connection read buffers, no read-ahead guessing.
- **Timeouts and cancellation are operations too**: linked timeouts on
  connects, `ASYNC_CANCEL` by op id. No timer wheel bolted on the side
  (one can come later for mass cheap timeouts if profiling demands it).
- **Send path**: plain send first; `SEND_ZC` (zero-copy) for large
  writes once the base is verified.
- One Ring per thread. v1 is single-threaded; thread-per-core comes
  later via pthread FFI (each thread its own Ring — no shared state,
  no locks), which the design requires nothing from today except not
  sharing Rings.

### 2. Protocols are sans-io state machines

This is the decision that makes one base serve HTTP, WebSocket, mail,
TLS, DNS — and the direct transplant of what made crypto-mojo
trustworthy. A protocol library never touches an fd. It is a pure
machine:

```
bytes in  ──>  [ protocol state machine ]  ──>  bytes out + events
```

- tls-mojo: TLS records in, plaintext + handshake actions out. Testable
  byte-for-byte against `openssl s_client -msg` transcripts with **no
  network at all** — the audit discipline, applied to protocols.
- http-mojo: request bytes in, parsed requests + response bytes out.
  Verified against curl/h2spec transcripts.
- STARTTLS (SMTP/IMAP) falls out for free: upgrading a connection is
  swapping which state machine consumes the stream. socket-mojo never
  knew TLS existed.
- QUIC/HTTP-3 later: same shape over UDP (datagrams in/out + timers),
  which is why the UDP path gets first-class treatment, not an
  afterthought.

socket-mojo's only obligations to protocols: deliver byte slices and
connection events, accept byte slices to write, and run their timers.
That contract is the whole interface between the repos.

### 3. No async/await — yet, and on purpose

Probed (`.probe/async_status_probe.mojo`): Mojo 1.0b2 parses
`async def`/`await`, but a `Coroutine` value can't even be destroyed in
sync code and there is no executor. Building the foundation on that is
building on sand.

The explicit completion loop **is** the v1 API. It is also exactly the
substrate a future coroutine layer suspends on: when Mojo's async
matures, `await stream.read()` becomes sugar that parks a coroutine on
an op id and the Ring resumes it — no engine rewrite. We lose nothing
by waiting except syntax.

## Layer map

```
  tls-mojo · http-mojo · ws-mojo · mail-mojo        (separate repos,
        pure state machines — sans-io)               crypto-mojo under TLS)
─────────────────────────────────────────────────────────────────────
  socket/stream.mojo   TcpListener / TcpConn / UdpSock: completion-
                       style ops over the Ring; owns conn id ↔ fd map
  socket/ring.mojo     Ring: SQ/CQ management, op table, multishot,
                       buffer rings, timeouts, cancel        ← THE CORE
  socket/uring_sys.mojo raw syscalls 425/426/427, SQE/CQE layout,
                       mmap, feature detection
─────────────────────────────────────────────────────────────────────
  existing, kept as-is:
  socket/_libc.mojo    socket/bind/listen/connect/setsockopt/errno
  socket/addr.mojo     sockaddr_in/in6 packing, parsing
  socket/dns.mojo      resolver — becomes the first sans-io protocol
                       driven through the Ring (UDP + TCP fallback)
  socket/tcp.mojo,
  udp.mojo, poller.mojo blocking + epoll APIs — the simple tier for
                       scripts/tests and non-Linux fallback later
```

## Verification (the audit culture, continued)

- Every Ring feature lands with a loopback test driven against a real
  peer: the existing `tests/echo_server.py` pattern (python sockets as
  external truth), plus ncat/curl interop where it fits.
- Protocol conformance lives in the protocol repos as recorded
  transcripts of real tools (openssl, curl, dig) replayed through the
  state machines — deterministic, no sockets in CI.
- Throughput sanity: echo benchmark vs the epoll tier and vs a C
  baseline, so regressions in the engine are numbers, not vibes.
- `.probe/` stays the scratchpad: every io_uring opcode gets a probe
  proving kernel behavior before the Ring grows it.

## Milestones

- **M0 — engine core**: `uring_sys` + `Ring` with accept/recv/send/
  close (single-shot), op table + generations, errno mapping. TCP echo
  server passing the existing external-truth tests through the Ring.
- **M1 — modern path**: multishot accept + recv, provided buffer
  rings, linked timeouts, cancel, graceful shutdown. UDP send/recv.
- **M2 — first protocol proof**: dns.mojo refactored sans-io and
  driven through the Ring (timers, retries, TCP fallback) — validates
  the whole protocol contract before TLS depends on it.
- **M3 — performance tier**: SEND_ZC, registered buffers/files,
  SQPOLL evaluation, thread-per-core via pthread FFI.
- Then **tls-mojo** starts: sans-io TLS 1.2/1.3 state machine on
  crypto-mojo, tested against openssl transcripts.

## Non-goals (v1)

- Windows/macOS: Linux-first (io_uring). The blocking + epoll tiers
  are the eventual portability seam (kqueue/IOCP backends would slot
  in behind the same completion events), not a v1 concern.
- A general async runtime: no executors, no futures. The Ring is an
  I/O engine, not a framework.
- In-process TLS: that's tls-mojo's job, above this library.
