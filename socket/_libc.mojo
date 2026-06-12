# Thin wrappers around the libc syscalls socket-mojo needs.
#
# Every public socket call delegates here; this is the only file that
# touches `external_call`. Each wrapper returns the raw libc return
# value (typically -1 on failure with errno set), letting the upper
# layer translate that into a typed Error.

from std.ffi import external_call
from std.memory import UnsafePointer

# Linux x86-64 syscall constants (these are the values used by glibc's
# <sys/socket.h>). All of socket-mojo's higher-level code reads them
# from this single source of truth.

comptime AF_INET = 2
comptime AF_INET6 = 10
comptime AF_UNSPEC = 0

comptime SOCK_STREAM = 1
comptime SOCK_DGRAM = 2

comptime IPPROTO_TCP = 6
comptime IPPROTO_UDP = 17

comptime SOL_SOCKET = 1
comptime SO_REUSEADDR = 2
comptime SO_RCVTIMEO = 20
comptime SO_SNDTIMEO = 21
comptime SO_KEEPALIVE = 9
comptime SO_ERROR = 4
comptime SO_RCVBUF = 8
comptime SO_SNDBUF = 7
comptime IPPROTO_TCP_LEVEL = 6
comptime TCP_NODELAY = 1
comptime TCP_CORK = 3
comptime TCP_QUICKACK = 12

comptime SHUT_RD = 0
comptime SHUT_WR = 1
comptime SHUT_RDWR = 2

# send/recv flags
comptime MSG_NOSIGNAL = 0x4000  # don't raise SIGPIPE when peer closes
comptime MSG_WAITALL = 0x100  # block until full count received
comptime MSG_DONTWAIT = 0x40  # non-blocking single call
comptime MSG_PEEK = 0x2  # read without consuming

# fcntl(2)
comptime F_GETFL = 3
comptime F_SETFL = 4
comptime O_NONBLOCK = 0x800

# epoll(7) — Linux only; the BSD equivalent (kqueue) is a separate backend.
comptime EPOLL_CTL_ADD = 1
comptime EPOLL_CTL_DEL = 2
comptime EPOLL_CTL_MOD = 3

comptime EPOLLIN = 0x001
comptime EPOLLPRI = 0x002
comptime EPOLLOUT = 0x004
comptime EPOLLERR = 0x008
comptime EPOLLHUP = 0x010
comptime EPOLLRDHUP = 0x2000
comptime EPOLLEXCLUSIVE = 0x10000000  # 1 << 28
comptime EPOLLWAKEUP = 0x20000000  # 1 << 29
comptime EPOLLONESHOT = 0x40000000  # 1 << 30
comptime EPOLLET = 0x80000000  # 1 << 31

# `struct epoll_event` is packed on x86-64: u32 events at offset 0, then
# a `union epoll_data_t` (u64) at offset 4. Total size 12 bytes per event.
comptime EPOLL_EVENT_SIZE = 12

# `struct sockaddr_in` is 16 bytes; `struct sockaddr_in6` is 28 bytes.
# We always pass a 28-byte buffer to be safe — the kernel reads only as
# many bytes as the family demands.
comptime SOCKADDR_STORAGE_SIZE = 28


def errno() -> Int32:
    """Returns errno from the calling thread's TLS slot."""
    var p = external_call[
        "__errno_location", UnsafePointer[Int32, MutAnyOrigin]
    ]()
    return p[]


def socket(domain: Int32, sock_type: Int32, protocol: Int32) -> Int32:
    return external_call["socket", Int32](domain, sock_type, protocol)


def close(fd: Int32) -> Int32:
    return external_call["close", Int32](fd)


def connect(
    fd: Int32, addr_ptr: UnsafePointer[UInt8, _], addr_len: UInt32
) -> Int32:
    return external_call["connect", Int32](fd, addr_ptr, addr_len)


def bind(
    fd: Int32, addr_ptr: UnsafePointer[UInt8, _], addr_len: UInt32
) -> Int32:
    return external_call["bind", Int32](fd, addr_ptr, addr_len)


def listen(fd: Int32, backlog: Int32) -> Int32:
    return external_call["listen", Int32](fd, backlog)


def accept(
    fd: Int32,
    addr_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    addr_len_ptr: UnsafePointer[UInt32, MutAnyOrigin],
) -> Int32:
    return external_call["accept", Int32](fd, addr_ptr, addr_len_ptr)


def send(fd: Int32, buf: UnsafePointer[UInt8, _], n: Int, flags: Int32) -> Int:
    return external_call["send", Int](fd, buf, n, flags)


def writev(fd: Int32, iov_ptr: UnsafePointer[UInt8, _], iovcnt: Int32) -> Int:
    """Vectored write: a single syscall sending multiple non-contiguous
    buffers (one Linux `struct iovec` per buffer). The kernel
    concatenates them on the wire — the TLS layer uses this to send a
    record header + encrypted body in one go."""
    return external_call["writev", Int](fd, iov_ptr, iovcnt)


def fcntl_get_flags(fd: Int32) -> Int32:
    return external_call["fcntl", Int32](fd, Int32(F_GETFL), Int32(0))


def fcntl_set_flags(fd: Int32, flags: Int32) -> Int32:
    return external_call["fcntl", Int32](fd, Int32(F_SETFL), flags)


def epoll_create1(flags: Int32) -> Int32:
    return external_call["epoll_create1", Int32](flags)


def epoll_ctl(
    epfd: Int32, op: Int32, fd: Int32, event_ptr: UnsafePointer[UInt8, _]
) -> Int32:
    return external_call["epoll_ctl", Int32](epfd, op, fd, event_ptr)


def epoll_wait(
    epfd: Int32,
    events_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    max_events: Int32,
    timeout_ms: Int32,
) -> Int32:
    return external_call["epoll_wait", Int32](
        epfd, events_ptr, max_events, timeout_ms
    )


def socketpair_unix(
    out_pair: UnsafePointer[UInt8, MutAnyOrigin],
) -> Int32:
    """Create a pair of connected AF_UNIX SOCK_STREAM sockets. Used by
    tests as a self-contained two-ended channel that does not need a
    network port. `out_pair` is a 2-int buffer (8 bytes); the two fds
    land in fd_pair[0] (sender) and fd_pair[1] (receiver)."""
    return external_call["socketpair", Int32](
        Int32(1),  # AF_UNIX
        Int32(1),  # SOCK_STREAM
        Int32(0),
        out_pair,
    )


def readv(
    fd: Int32, iov_ptr: UnsafePointer[UInt8, MutAnyOrigin], iovcnt: Int32
) -> Int:
    return external_call["readv", Int](fd, iov_ptr, iovcnt)


def recv(
    fd: Int32, buf: UnsafePointer[UInt8, MutAnyOrigin], n: Int, flags: Int32
) -> Int:
    return external_call["recv", Int](fd, buf, n, flags)


def sendto(
    fd: Int32,
    buf: UnsafePointer[UInt8, _],
    n: Int,
    flags: Int32,
    addr_ptr: UnsafePointer[UInt8, _],
    addr_len: UInt32,
) -> Int:
    return external_call["sendto", Int](fd, buf, n, flags, addr_ptr, addr_len)


def recvfrom(
    fd: Int32,
    buf: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    flags: Int32,
    addr_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    addr_len_ptr: UnsafePointer[UInt32, MutAnyOrigin],
) -> Int:
    return external_call["recvfrom", Int](
        fd, buf, n, flags, addr_ptr, addr_len_ptr
    )


def setsockopt(
    fd: Int32,
    level: Int32,
    name: Int32,
    val_ptr: UnsafePointer[UInt8, _],
    val_len: UInt32,
) -> Int32:
    return external_call["setsockopt", Int32](fd, level, name, val_ptr, val_len)


def shutdown(fd: Int32, how: Int32) -> Int32:
    return external_call["shutdown", Int32](fd, how)


# --- Helpers ---------------------------------------------------------


def errno_message(code: Int32) -> String:
    """Map common errnos to a stable string prefix used in raised
    Errors. Callers can pattern-match on the prefix (e.g.
    `'ECONNREFUSED'`)."""
    if code == 11:
        return "EAGAIN"
    if code == 13:
        return "EACCES"
    if code == 22:
        return "EINVAL"
    if code == 24:
        return "EMFILE"
    if code == 32:
        return "EPIPE"
    if code == 98:
        return "EADDRINUSE"
    if code == 99:
        return "EADDRNOTAVAIL"
    if code == 100:
        return "ENETDOWN"
    if code == 101:
        return "ENETUNREACH"
    if code == 103:
        return "ECONNABORTED"
    if code == 104:
        return "ECONNRESET"
    if code == 107:
        return "ENOTCONN"
    if code == 110:
        return "ETIMEDOUT"
    if code == 111:
        return "ECONNREFUSED"
    if code == 112:
        return "EHOSTDOWN"
    if code == 113:
        return "EHOSTUNREACH"
    if code == 9:
        return "EBADF"
    if code == 4:
        return "EINTR"
    return "errno=" + String(Int(code))


def write_sockaddr(
    out_buf: UnsafePointer[UInt8, MutAnyOrigin],
    ip_is_v6: Bool,
    octets: InlineArray[UInt8, 16],
    port: UInt16,
) -> UInt32:
    """Serialize an (ip, port) into the libc `struct sockaddr_in[6]`
    layout. Returns the byte length the kernel expects (16 or 28)."""
    # Zero the entire 28-byte buffer first.
    for i in range(SOCKADDR_STORAGE_SIZE):
        out_buf[i] = 0
    if not ip_is_v6:
        # struct sockaddr_in:
        #   [0..2]   sin_family = AF_INET (host order; LE on x86 → 0x02 0x00)
        #   [2..4]   sin_port (network = big-endian)
        #   [4..8]   sin_addr (network)
        #   [8..16]  zero padding
        out_buf[0] = UInt8(AF_INET)
        out_buf[1] = 0
        out_buf[2] = UInt8((port >> 8) & 0xFF)
        out_buf[3] = UInt8(port & 0xFF)
        out_buf[4] = octets[0]
        out_buf[5] = octets[1]
        out_buf[6] = octets[2]
        out_buf[7] = octets[3]
        return 16
    # struct sockaddr_in6:
    #   [0..2]   sin6_family = AF_INET6 (LE)
    #   [2..4]   sin6_port (BE)
    #   [4..8]   sin6_flowinfo
    #   [8..24]  sin6_addr (16 bytes, network)
    #   [24..28] sin6_scope_id
    out_buf[0] = UInt8(AF_INET6)
    out_buf[1] = 0
    out_buf[2] = UInt8((port >> 8) & 0xFF)
    out_buf[3] = UInt8(port & 0xFF)
    for i in range(16):
        out_buf[8 + i] = octets[i]
    return 28


def read_sockaddr(
    buf: UnsafePointer[UInt8, _],
) -> Tuple[Bool, InlineArray[UInt8, 16], UInt16]:
    """Inverse of write_sockaddr."""
    var family = buf[0]
    var port = (UInt16(buf[2]) << 8) | UInt16(buf[3])
    var octets = InlineArray[UInt8, 16](fill=0)
    if family == UInt8(AF_INET6):
        for i in range(16):
            octets[i] = buf[8 + i]
        return (True, octets, port)
    octets[0] = buf[4]
    octets[1] = buf[5]
    octets[2] = buf[6]
    octets[3] = buf[7]
    return (False, octets, port)
