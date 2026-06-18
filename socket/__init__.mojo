# socket-mojo: a pure-Mojo socket stack over direct Linux syscalls
# and io_uring.
#
# No libc-specific symbols: every kernel interaction goes through
# socket/_syscalls.mojo, which calls the kernel via the `syscall`
# instruction (currently through libc's variadic `syscall(3)` shim —
# five lines of register loading we'd otherwise inline as asm). No
# errno TLS slot. No getaddrinfo / glibc resolver. No liburing.
#
# Layers (Linux-first; portable to Windows IOCP later via the same
# completion-shaped API on a Windows backend):
#
#   socket/addr.mojo      pure value types (IpAddress, SocketAddr)
#   socket/dnswire.mojo   sans-io RFC 1035 codec
#   socket/dns.mojo       /etc/hosts + /etc/resolv.conf + DNS via Ring
#   socket/tcp.mojo       blocking TcpSocket / TcpListener
#   socket/udp.mojo       blocking UdpSocket
#   socket/poller.mojo    epoll(7) reactor (tier-2 fallback)
#   socket/nonblocking.mojo  O_NONBLOCK helpers
#   socket/uring_sys.mojo io_uring raw layer (mmap'd rings, SQEs/CQEs)
#   socket/bufring.mojo   provided-buffer rings (multishot recv pool)
#   socket/ring.mojo      Ring: safe completion engine — THE CORE
