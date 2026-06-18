# Windows port plan

socket-mojo's `Ring` is completion-shaped from day one. That maps
directly onto Windows IOCP, which is the same idea with different
names. This document is the port plan; the actual implementation
lives in `socket/iocp_sys.mojo` (currently a skeleton).

## Shape parity

| io_uring (Linux)              | IOCP (Windows)                                 |
| ----------------------------- | ---------------------------------------------- |
| `io_uring_setup`              | `CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, N)` |
| `io_uring_enter` (reap)       | `GetQueuedCompletionStatusEx`                 |
| SQE submission (op-specific)  | `WSARecv` / `WSASend` / `AcceptEx` / `ConnectEx` |
| CQE                           | OVERLAPPED-completed entry                    |
| `IOSQE_FIXED_FILE`            | n/a — `HANDLE` already a kernel slot          |
| Multishot recv                | `WSARecv` re-issued on each completion        |
| Provided buffer ring          | Caller passes a buffer per op (no kernel pool)|
| `IORING_OP_MSG_RING`          | `PostQueuedCompletionStatus`                  |
| `IORING_OP_SEND_ZC`           | `WSASend(MSG_PARTIAL | ...)` / `TransmitPackets` |

## What needs to happen

1. **Backend trait.** Split `UringQueue`-specific methods into a
   `CompletionBackend` trait that both `UringQueue` (Linux) and
   `IocpQueue` (Windows) implement.

2. **Compile-time dispatch.** `socket/ring.mojo` picks the backend
   via `comptime if CompilationTarget.is_linux() / .is_windows()`
   (the standards file's recommended pattern).

3. **`socket/iocp_sys.mojo`.** Implement:
   - `IocpQueue.__init__`: `CreateIoCompletionPort` + initial-state.
   - `push_sqe`: dispatch on opcode → `WSARecv` / `WSASend` / etc.
     Each call passes an `OVERLAPPED*` whose address acts as the
     `user_data` we reap later.
   - `enter`: `GetQueuedCompletionStatusEx` reading up to N
     completions.
   - Per-op `OVERLAPPED` lifecycle (probably embedded in the
     existing op slot allocated by `ring.mojo`).

4. **Function pointer dance.** Some Win32 extension functions
   (`ConnectEx`, `AcceptEx`, `DisconnectEx`, `TransmitPackets`) are
   not exported by name; they're looked up at runtime via
   `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER, ...)`. Cache the
   pointers in the `IocpQueue` struct.

5. **Error mapping.** `WSAGetLastError()` returns codes from a
   different number space than POSIX errno. Build a translation
   table in `_syscalls.mojo` (or split into a `_winapi.mojo`).

6. **DNS.** On Windows there's no `/etc/resolv.conf`; instead, query
   nameservers via `GetAdaptersAddresses` or the IPHLPAPI. The
   sans-io `dnswire.mojo` codec stays unchanged — only `dns.mojo`'s
   nameserver discovery needs a `comptime if`.

7. **Tests.** `tests/run_tests.mojo` already aggregates per-feature
   runs; the Windows CI just needs python echo / DNS truth peers
   (the test scripts are pure Python and work cross-platform).

## What stays the same

- `socket/addr.mojo` — pure value types, zero FFI.
- `socket/dnswire.mojo` — sans-io codec, zero FFI.
- `socket/ring.mojo` — the public `Ring` API. Callers never know
  which backend is underneath.
- `socket/tcp.mojo` / `udp.mojo` — public types stay; their FFI
  imports switch to `_winapi` on Windows.
- All tests for `addr`, `dns_wire`, `ring` (engine semantics) —
  cross-platform once the backend exists.

## Non-goals

- **macOS via kqueue** is a separate effort. kqueue is
  *readiness*-based (closer to epoll than IOCP), so it needs the
  Poller layer, not the Ring. Probably worth its own backend.

## Status

Linux backend: production-shaped, all tests pass.
Windows backend: skeleton (`socket/iocp_sys.mojo` raises
`not implemented`). PRs welcome.
