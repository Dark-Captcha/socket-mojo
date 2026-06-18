# socket-mojo

A pure-Mojo socket stack over **direct Linux syscalls** and **io_uring**.
Zero libc. No `getaddrinfo`, no `socket`/`bind`/`recv` shims, no
errno TLS — every kernel call is a raw `syscall` instruction via
inline asm, so the library links cleanly against musl, against
nothing at all (`-nostdlib`), and on a future fully-freestanding
Mojo runtime.

> **Status:** Linux/x86_64, Mojo 1.0.0b3.
> Kernel ≥ 5.4 for the io_uring core; modern perf features (SQPOLL,
> direct fds, SEND_ZC, taskrun flags) require 5.11 / 5.19 / 6.0+.

## Highlights

| | |
|---|---|
| **No libc** | Inline-asm syscall trampoline (`syscall` instruction). Zero glibc symbols anywhere. |
| **io_uring as the engine** | Completion-shaped API from day one — multishot, provided buffer rings, linked timeouts, cancel. |
| **Native DNS** | `/etc/hosts` + `/etc/resolv.conf` parsed directly, RFC 1035 codec driven over the Ring. No `getaddrinfo`. |
| **Modern features** | SQPOLL, registered fd table (`socket_direct`/`accept_direct`/`fixed=True`), SEND_ZC, SINGLE_ISSUER + DEFER_TASKRUN. |
| **Sans-io ready** | `socket-mojo` moves bytes; `tls-mojo`, `http-mojo`, `ws-mojo` etc. are pure state machines on top. |

## Install

`pixi.toml`:
```toml
[dependencies]
mojo-compiler = "==1.0.0b3.dev2026061706"
```
Clone the repo, then `pixi run test`.

## Quickstart

### Blocking TCP client

```mojo
from socket.tcp import TcpSocket

def main() raises:
    var sock = TcpSocket.connect("example.com", 80, timeout_seconds=5.0)
    sock.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n".as_bytes())
    var resp = sock.read(4096)
    print("got", len(resp), "bytes")
```

`TcpSocket.connect` resolves the host via the native DNS resolver
(literal IP → `/etc/hosts` → `/etc/resolv.conf` nameservers), tries
each address in order, and applies the timeout to the connect
syscall itself.

### Blocking TCP server

```mojo
from socket.addr import IpAddress, SocketAddr
from socket.tcp import TcpListener

def main() raises:
    var addr = SocketAddr(IpAddress.any_v4(), 8080)
    var lst = TcpListener.bind(addr, backlog=128)
    while True:
        var pair = lst.accept()
        var conn = pair[0]
        var peer = pair[1]
        print("conn from", peer.to_string())
        var buf = conn.read(4096)
        conn.write(buf)  # echo
```

### io_uring echo server (multishot + buffer ring)

```mojo
from socket.addr import IpAddress, SocketAddr
from socket.ring import KIND_ACCEPT_MULTI, KIND_RECV_MULTI, Ring
from socket.tcp import TcpListener

def main() raises:
    var ring = Ring(256, defer_taskrun=True)   # 6.0+ taskrun model
    ring.setup_buffers(entries=128, buf_size=16384, bgid=0)
    var lst = TcpListener.bind(SocketAddr(IpAddress.any_v4(), 8080))
    _ = ring.accept_multishot(lst.fd)
    while True:
        _ = ring.wait(min_complete=1)
        while True:
            var c = ring.next_completion()
            if not c:
                break
            var done = c.take()
            done.ok()
            if done.kind == KIND_ACCEPT_MULTI:
                # New connection: arm a multishot recv on it.
                _ = ring.recv_multishot(done.res)
            elif done.kind == KIND_RECV_MULTI:
                if done.res <= 0:
                    continue                # EOF or transient
                var view = ring.buffer_view(done.bid, Int(done.res))
                _ = ring.send_copy(done.fd, view)   # echo back
                ring.recycle_buffer(done.bid)
```

One armed accept + one armed recv per conn, kernel writes into a
shared buffer pool — the steady-state shape of a busy server has
**zero per-read or per-accept SQE submissions** in the hot loop.

### Even less syscalls: SQPOLL + registered fds

```mojo
var ring = Ring(
    256,
    sqpoll=True,             # kthread polls our SQ, no enter syscall
    sqpoll_idle_ms=2000,
    single_issuer=True,
    defer_taskrun=True,
)
ring.register_files(2048)    # registered fd table
ring.setup_buffers(entries=512, buf_size=16384, bgid=0)
_ = ring.accept_multishot_direct(lst.fd)  # fds land in the table
```

Each accepted connection becomes a direct fd slot. Use it with
`recv/send/connect/close_fd(slot, fixed=True)` — the kernel skips
the fget refcount bump on every op.

### Typed error handling

socket-mojo raises `Error` with a stable string format (`socket.X:
<op> <ETAG>`). `socket/errors.mojo` gives callers predicates so
they don't have to grep the message themselves.

```mojo
from socket.errors import (
    is_connection_refused,
    is_timed_out,
    is_dns_error,
    errno_of,
    ECONNREFUSED,
)
from socket.tcp import TcpSocket

def connect_with_fallback(hosts: List[String]) raises -> TcpSocket:
    for h in hosts:
        try:
            return TcpSocket.connect(h, 443, timeout_seconds=5.0)
        except e:
            if is_dns_error(e):
                continue                       # try next host
            if is_connection_refused(e) or is_timed_out(e):
                continue                       # host unreachable
            raise e^                           # something unexpected
    raise Error("no host reachable")
```

### DNS

```mojo
from socket.dns import resolve, resolve_dns
from socket.dnswire import QTYPE_AAAA
from socket.addr import IpAddress, SocketAddr

def main() raises:
    # System resolver: /etc/hosts first, then /etc/resolv.conf
    # nameservers via the Ring (UDP with retry + TCP fallback).
    var addrs = resolve("example.com")
    for i in range(len(addrs)):
        print(addrs[i].to_string())

    # Or query a specific server directly.
    var ns = SocketAddr(IpAddress.v4(1, 1, 1, 1), 53)
    var v6 = resolve_dns("example.com", server=ns, qtype=QTYPE_AAAA)
```

## API surface

```
socket/
├── addr.mojo            IpAddress, SocketAddr (pure value types)
├── tcp.mojo             TcpSocket, TcpListener (blocking)
├── udp.mojo             UdpSocket (blocking)
├── poller.mojo          Poller (epoll(7) reactor)
├── nonblocking.mojo     set_nonblocking, is_would_block, ...
├── ring.mojo            Ring — the io_uring completion engine
├── bufring.mojo         BufRing — provided buffer ring (multishot recv)
├── uring_sys.mojo       UringQueue — raw mmap'd SQ/CQ rings
├── dns.mojo             resolve() + resolve_dns() + native parsers
├── dnswire.mojo         sans-io RFC 1035 codec
└── _syscalls.mojo       direct Linux syscall trampoline + constants
```

| Layer | Use when |
|------|---------|
| `tcp.mojo` / `udp.mojo` | Scripts, tests, low-fanout clients. Blocking. |
| `poller.mojo` | Many sockets one thread, but no kernel needing 5.4+. |
| `ring.mojo` | High-throughput servers. The intended steady state. |
| `dns.mojo` | Resolve names without touching `getaddrinfo`. |

## Tests + benchmarks

```bash
# Start the python truth peers for the network tests.
python3 tests/echo_server.py 19501 &
python3 tests/echo_server.py 19502 &
python3 tests/echo_server.py 19503 &
python3 tests/dns_server.py  19553 &

pixi run test         # tests/run_tests.mojo
pixi run bench        # benchmarks/bench.mojo
mojo run -I . benchmarks/bench_ring.mojo
```

Loopback fan-out (rt/s, 7950X3D, kernel 7.0.x):

| conns | ring | +sqpoll | +direct+sqpoll |
|---:|---:|---:|---:|
|   8 | 142k | 152k | 155k |
|  64 | 143k | 160k | 162k |
| 256 | 133k | 154k | 156k |

See [`PERF.md`](PERF.md) for the full picture and [`DESIGN.md`](DESIGN.md)
for the architectural decisions.

## Scaling across CPUs

Mojo doesn't expose a C-callable function pointer yet, so we can't
plug Mojo code straight into `pthread_create`. The recipe today is
**multi-process** with `SO_REUSEPORT`: each process owns its own
`Ring`, the kernel load-balances incoming connections across them.

```mojo
var addr = SocketAddr(IpAddress.any_v4(), 8080)
var lst = TcpListener.bind(addr, backlog=512, reuseport=True)
# Each child process binds the same (addr, port) the same way.
# The kernel hashes the 4-tuple and dispatches accordingly.
```

For cross-process / cross-ring signalling without shared memory,
`OP_MSG_RING` posts a CQE on another Ring's io_uring fd (Linux 5.18+):

```mojo
var op = local_ring.msg_ring(
    other_ring.fd(),     # get via Ring.fd()
    payload=UInt64(0xDEADBEEF),  # lower 56 bits free for caller use
    target_res=0x42,
)
# `other_ring.next_completion()` will surface a KIND_MSG_INCOMING.
```

When Mojo gains a stable threading API (or a `fn` that can be passed
to `pthread_create`), the same Ring-per-thread shape will work
in-process — `OP_MSG_RING` is ready for it today.

## What socket-mojo is NOT

- **No TLS.** TLS is a pure state machine that lives one layer up
  (`tls-mojo`, separate repo). socket-mojo moves bytes; TLS records
  in / plaintext out happens in callers' code.
- **No async/await syntax yet.** The explicit completion loop is
  the v1 substrate; an `await stream.read()` sugar lands when
  Mojo's coroutines mature.
- **Linux-first.** The architecture is portable to Windows IOCP
  via the same completion-shaped API, but that backend isn't
  shipped yet.

## License

(set per your preference — repo currently has no LICENSE file.)
