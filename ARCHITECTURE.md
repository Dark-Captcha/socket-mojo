# socket-mojo — Architecture

A map of the system. Layers point downward; nothing cycles. See
`DESIGN.md` for the rationale behind the decisions, `PERF.md` for
the numbers, `ROADMAP.md` for what's next.

## Layer map

```
┌──────────────────────────────────────────────────────────────┐
│  user code                                                   │
└──────────────────────────────────────────────────────────────┘
              │                  │                  │
              ▼                  ▼                  ▼
┌─────────────────┐  ┌─────────────────┐  ┌────────────────────┐
│  tcp.mojo       │  │  udp.mojo       │  │  ring.mojo         │
│  blocking TCP   │  │  blocking UDP   │  │  completion engine │
│  v0 / tier-1    │  │  v0 / tier-1    │  │  v1 — THE CORE     │
└─────────────────┘  └─────────────────┘  └────────────────────┘
        │                    │                      │
        │                    │                      ▼
        │                    │            ┌────────────────────┐
        │                    │            │  bufring.mojo      │
        │                    │            │  provided-buffer   │
        │                    │            │  pool              │
        │                    │            └────────────────────┘
        │                    │                      │
        │                    │                      ▼
        │                    │            ┌────────────────────┐
        │                    │            │  uring_sys.mojo    │
        │                    │            │  mmap'd SQ/CQ      │
        │                    │            │  rings + opcodes   │
        │                    │            └────────────────────┘
        ▼                    ▼                      │
┌──────────────────────────────────────────────────┐│
│  poller.mojo  /  nonblocking.mojo                ││
│  epoll(7) reactor (tier-2 fallback)              ││
└──────────────────────────────────────────────────┘│
        │                                           │
        │  ┌────────────────────────────────────────┘
        ▼  ▼
┌──────────────────────────────────────────────────────────────┐
│  _syscalls.mojo                                              │
│  direct Linux syscalls via inline asm                        │
│  zero libc symbols (kernel ABI is the interface)             │
└──────────────────────────────────────────────────────────────┘
                          │
                          ▼
                    Linux kernel (≥ 5.4 / 5.11 / 6.0 for feature tiers)


┌──────────────────────────────────────────────────────────────┐
│  addr.mojo · dnswire.mojo · dns.mojo · errors.mojo           │
│  pure value types / sans-io codecs / native resolver         │
│  (no FFI; built on top of the syscall layer)                 │
└──────────────────────────────────────────────────────────────┘
```

## File-by-file

| File | Lines | Role |
|---|---:|---|
| `socket/_syscalls.mojo` | ~520 | Linux x86_64 syscall trampoline (raw `syscall` instruction via `inlined_assembly`), all NRs, all socket/file/epoll/io_uring constants, sockaddr layout helpers, errno-tag mapping. **Zero libc symbols.** |
| `socket/uring_sys.mojo` | ~330 | `UringQueue`: mmap'd SQ/CQ rings, SQE/CQE binary layout, opcode/flag constants, `push_sqe` + `enter` + `pop_cqe` primitives. SQPOLL / SINGLE_ISSUER / DEFER_TASKRUN / COOP_TASKRUN setup flags. |
| `socket/bufring.mojo` | ~130 | `BufRing`: kernel-managed provided-buffer pool for multishot recv. Register / view / recycle. |
| `socket/ring.mojo` | ~700 | `Ring`: the safe completion engine. Op-table with generations (ABA-safe), typed `Completion`s, multishot accept/recv, registered fd table (`accept_direct` / `socket_direct` / `fixed=True`), `SEND_ZC` two-CQE protocol, `OP_MSG_RING` cross-ring signalling, linked timeouts. |
| `socket/addr.mojo` | ~340 | Pure value types: `IpAddress`, `SocketAddr`. Parsing + stringification (incl. `::` compression, embedded IPv4 in v6). No FFI. |
| `socket/dnswire.mojo` | ~200 | Sans-io RFC 1035 codec: query builder, response parser. Hop-bounded compression-pointer decode, qname→CNAME chain validation, attacker-injection defense. |
| `socket/dns.mojo` | ~360 | Native resolver: literal-IP fast path → `/etc/hosts` → `/etc/resolv.conf` nameservers, DNS over the Ring (UDP retry + TCP fallback). **No `getaddrinfo`.** |
| `socket/tcp.mojo` | ~470 | Blocking `TcpSocket` / `TcpListener`. `SO_REUSEPORT` plumbed in for multi-process scaling. |
| `socket/udp.mojo` | ~190 | Blocking `UdpSocket`. |
| `socket/poller.mojo` | ~240 | `Poller`: epoll(7) reactor. Tier-2 fallback for callers that don't want io_uring or have a non-5.4+ kernel. |
| `socket/nonblocking.mojo` | ~60 | `O_NONBLOCK` toggles + `is_would_block` / `is_in_progress` predicates. |
| `socket/errors.mojo` | ~210 | Typed-error helpers over the stable error-string contract: `is_connection_refused(e)`, `is_timed_out(e)`, `errno_of(e)`, etc. |
| `socket/iocp_sys.mojo` | ~80 | **Skeleton only.** Structural placeholder for the future Windows IOCP backend; see `WINDOWS.md`. |

## Dataflow: a connection's life through the Ring

```
1.  ring.register_files(N)           # set up registered fd table
2.  ring.accept_multishot_direct(lfd)   # one armed SQE
3.  loop:
       ring.wait(min_complete=1)        # 1 io_uring_enter syscall
       for cqe in ring drained:
           if KIND_ACCEPT_MULTI_DIRECT:
               slot = cqe.res
               ring.recv_multishot(slot, fixed=True)   # arm recv
           elif KIND_RECV_MULTI:
               view = ring.buffer_view(bid, len)      # kernel-filled
               handle(view)                            # protocol-level
               ring.send_borrowed(slot, ..., fixed=True)   # echo / reply
               ring.recycle_buffer(bid)
```

With SQPOLL the syscall in step 3 disappears entirely on the hot
path — the kthread polls the SQ and posts CQEs autonomously.

## Boundaries

| | Mojo owns | Kernel owns |
|---|---|---|
| SQ ring memory | reads tail, writes SQEs | reads SQ tail, writes SQ head |
| CQ ring memory | writes CQ head | writes CQEs, writes CQ tail |
| Buffer ring | writes tail (on recycle) | reads tail (on recv buffer pick) |
| Buffer pool memory | writes via `send` paths | writes via `recv` (kernel-picked bid) |
| Op-table slots | full lifecycle (alloc, free, generation) | reads via `user_data` |
| Registered fd table | requests slots | allocates slot index, owns the file |

The op-table guarantees buffer lifetime across kernel reads: every
byte the kernel sees is owned by an op slot until that op's CQE is
reaped. Mojo's ASAP destruction therefore cannot free anything the
kernel still sees.

## Public-API surface

```mojo
# value types — pure, no FFI
from socket.addr   import IpAddress, SocketAddr, parse_ip
from socket.errors import is_connection_refused, errno_of, ECONNREFUSED, ...

# blocking — for scripts, tests, simple clients
from socket.tcp import TcpSocket, TcpListener
from socket.udp import UdpSocket

# tier-2 reactor
from socket.poller      import Poller, PollEvent
from socket.nonblocking import set_nonblocking

# tier-1 engine — production servers
from socket.ring   import Ring, Completion, OpId, KIND_*  # full op kind enum
from socket.dns    import resolve, resolve_dns
from socket.dnswire import dns_build_query, dns_parse_response, QTYPE_A, QTYPE_AAAA
```

Everything below `_` is private (`_syscalls.mojo` is implementation
detail, not API).

## What's NOT in this library by design

- TLS. Lives one layer up in `tls-mojo` as a sans-io state machine.
- HTTP / WebSocket. Same pattern: separate sans-io repos.
- Async/await syntax. Waiting on Mojo 1.0 coroutines; the explicit
  completion loop is the substrate.
- Windows. Skeleton in `socket/iocp_sys.mojo`; full port plan in
  `WINDOWS.md`.

## Kernel-feature requirements

| Feature | Linux ≥ |
|---|---:|
| Ring core (SQE/CQE, multishot, pbuf rings) | 5.4 |
| `OP_SEND_ZC` | 5.19 |
| `IORING_SETUP_COOP_TASKRUN` | 5.19 |
| `IORING_SETUP_SQPOLL` (unprivileged) | 5.11 |
| `IORING_SETUP_SINGLE_ISSUER` + `DEFER_TASKRUN` | 6.0 |
| `OP_MSG_RING` | 5.18 |
| `accept4` + `getrandom` syscalls | 3.17 |

Tested on kernel 7.0.x. Older kernels work for the subset of
features they support; the Ring constructor surfaces `-EINVAL`
clearly if you request an unsupported flag.
