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
#   socket/addr/          pure value types (Ipv4Address, Ipv6Address,
#                         AddressFamily, SocketAddr) — v4/v6 split by type
#   socket/dnswire.mojo   sans-io RFC 1035 codec
#   socket/dns.mojo       /etc/hosts + /etc/resolv.conf + DNS via Ring
#   socket/tcp.mojo       blocking TcpSocket / TcpListener
#   socket/udp.mojo       blocking UdpSocket
#   socket/poller.mojo    epoll(7) reactor (tier-2 fallback)
#   socket/nonblocking.mojo  O_NONBLOCK helpers
#   socket/uring_sys.mojo io_uring raw layer (mmap'd rings, SQEs/CQEs)
#   socket/bufring.mojo   provided-buffer rings (multishot recv pool)
#   socket/ring.mojo      Ring: safe completion engine — THE CORE


# --- value types ---------------------------------------------------
from socket.addr import (
    AddressFamily,
    Ipv4Address,
    Ipv6Address,
    SocketAddr,
    parse_ip,
    parse_ipv4,
    parse_ipv6,
    read_sockaddr,
    write_sockaddr,
)

# --- blocking sockets ---------------------------------------------
from socket.tcp import TcpListener, TcpSocket
from socket.udp import UdpSocket

# --- DNS ----------------------------------------------------------
from socket.dns import resolve, resolve_dns
from socket.dnswire import (
    DnsAnswer,
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_CNAME,
    dns_build_query,
    dns_parse_response,
)

# --- epoll reactor ------------------------------------------------
from socket.nonblocking import set_nonblocking
from socket.poller import PollEvent, Poller

# --- io_uring engine ----------------------------------------------
from socket.ring import Completion, CompletionKind, OpId, Ring

# --- typed-error predicates ---------------------------------------
from socket.errors import (
    errno_of,
    is_address_in_use,
    is_bad_fd,
    is_broken_pipe,
    is_canceled,
    is_connection_aborted,
    is_connection_refused,
    is_connection_reset,
    is_dns_error,
    is_host_unreachable,
    is_in_progress,
    is_timed_out,
    is_would_block,
)
