# Direct Linux x86_64 syscalls. The only libc surface this layer
# keeps is two shims: glibc's variadic `syscall(3)` (five lines of
# register-loading plus the `syscall` instruction) and
# `__errno_location` (one TLS-slot pointer). No glibc socket
# wrappers, no glibc resolver, no nss.
#
# The `syscall()` trampoline normalises libc's failure convention
# (return -1, set errno) into the kernel ABI's convention (return
# -errno directly), so every wrapper returns `Int` with success in
# `rc >= 0` and failure in `-4095 <= rc <= -1` — the actual errno.
# Callers check `rc < 0` and pass `Int32(-rc)` to `errno_message`
# for a stable error tag.
#
# When Mojo's inline-asm story stabilises this trampoline collapses
# to a single `syscall` instruction with no libc symbols at all and
# nothing else in the library needs to change.

from std.ffi import external_call
from std.memory import UnsafePointer


# --- syscall trampoline -----------------------------------------------

@always_inline
def _errno() -> Int32:
    return external_call[
        "__errno_location", UnsafePointer[Int32, MutAnyOrigin]
    ]()[]


@always_inline
def syscall(
    n: Int,
    a: Int = 0,
    b: Int = 0,
    c: Int = 0,
    d: Int = 0,
    e: Int = 0,
    f: Int = 0,
) -> Int:
    """Returns the kernel return value: positive on success, -errno on
    failure (range -4095..-1). Internally bridges libc's syscall(3) +
    errno convention to the kernel ABI."""
    var rc = external_call["syscall", Int](n, a, b, c, d, e, f)
    if rc == -1:
        return -Int(_errno())
    return rc


# --- Linux x86_64 syscall numbers (stable across kernel versions) -----

comptime SYS_read = 0
comptime SYS_write = 1
comptime SYS_close = 3
comptime SYS_mmap = 9
comptime SYS_munmap = 11
comptime SYS_readv = 19
comptime SYS_writev = 20
comptime SYS_socket = 41
comptime SYS_connect = 42
comptime SYS_accept = 43
comptime SYS_sendto = 44
comptime SYS_recvfrom = 45
comptime SYS_shutdown = 48
comptime SYS_bind = 49
comptime SYS_listen = 50
comptime SYS_getsockname = 51
comptime SYS_socketpair = 53
comptime SYS_setsockopt = 54
comptime SYS_fcntl = 72
comptime SYS_epoll_ctl = 233
comptime SYS_openat = 257
comptime SYS_accept4 = 288
comptime SYS_epoll_pwait = 281
comptime SYS_epoll_create1 = 291
comptime SYS_getrandom = 318
comptime SYS_io_uring_setup = 425
comptime SYS_io_uring_enter = 426
comptime SYS_io_uring_register = 427


# --- socket API constants (Linux UAPI) --------------------------------

comptime AF_UNIX = 1
comptime AF_INET = 2
comptime AF_INET6 = 10
comptime AF_UNSPEC = 0

comptime SOCK_STREAM = 1
comptime SOCK_DGRAM = 2
comptime SOCK_NONBLOCK = 0x800
comptime SOCK_CLOEXEC = 0x80000

comptime IPPROTO_UDP = 17
comptime IPPROTO_TCP_LEVEL = 6

comptime SOL_SOCKET = 1
comptime SO_REUSEADDR = 2
comptime SO_KEEPALIVE = 9
comptime SO_ERROR = 4
comptime SO_RCVBUF = 8
comptime SO_SNDBUF = 7
comptime SO_RCVTIMEO = 20
comptime SO_SNDTIMEO = 21

comptime TCP_NODELAY = 1
comptime TCP_CORK = 3
comptime TCP_QUICKACK = 12

comptime SHUT_RD = 0
comptime SHUT_WR = 1
comptime SHUT_RDWR = 2

# send/recv flags
comptime MSG_NOSIGNAL = 0x4000
comptime MSG_WAITALL = 0x100
comptime MSG_DONTWAIT = 0x40
comptime MSG_PEEK = 0x2

# fcntl(2)
comptime F_GETFL = 3
comptime F_SETFL = 4
comptime O_NONBLOCK = 0x800
comptime O_CLOEXEC = 0x80000
comptime O_RDONLY = 0
comptime AT_FDCWD = -100  # openat with this as the dirfd → cwd-relative

# epoll(7)
comptime EPOLL_CTL_ADD = 1
comptime EPOLL_CTL_DEL = 2
comptime EPOLL_CTL_MOD = 3

comptime EPOLLIN = 0x001
comptime EPOLLPRI = 0x002
comptime EPOLLOUT = 0x004
comptime EPOLLERR = 0x008
comptime EPOLLHUP = 0x010
comptime EPOLLRDHUP = 0x2000
comptime EPOLLEXCLUSIVE = 0x10000000
comptime EPOLLWAKEUP = 0x20000000
comptime EPOLLONESHOT = 0x40000000
comptime EPOLLET = 0x80000000

# struct epoll_event is packed on x86_64: events u32, data u64 → 12B.
comptime EPOLL_EVENT_SIZE = 12

# mmap(2)
comptime PROT_READ = 1
comptime PROT_WRITE = 2
comptime MAP_SHARED = 0x01
comptime MAP_PRIVATE = 0x02
comptime MAP_ANONYMOUS = 0x20
comptime MAP_POPULATE = 0x8000

# sockaddr_in (16 B) ∪ sockaddr_in6 (28 B). Always pass 28 — the
# kernel reads only what the family demands.
comptime SOCKADDR_STORAGE_SIZE = 28


# --- syscall wrappers -------------------------------------------------

@always_inline
def sys_socket(domain: Int, type_: Int, protocol: Int) -> Int:
    """SOCK_CLOEXEC is OR'd into type_ by callers that need it; this
    wrapper passes everything through verbatim."""
    return syscall(SYS_socket, domain, type_, protocol)


@always_inline
def sys_close(fd: Int32) -> Int:
    return syscall(SYS_close, Int(fd))


@always_inline
def sys_bind(
    fd: Int32, addr: UnsafePointer[UInt8, _], addr_len: Int
) -> Int:
    return syscall(SYS_bind, Int(fd), Int(addr), addr_len)


@always_inline
def sys_listen(fd: Int32, backlog: Int) -> Int:
    return syscall(SYS_listen, Int(fd), backlog)


@always_inline
def sys_connect(
    fd: Int32, addr: UnsafePointer[UInt8, _], addr_len: Int
) -> Int:
    return syscall(SYS_connect, Int(fd), Int(addr), addr_len)


@always_inline
def sys_accept4(
    fd: Int32,
    addr: UnsafePointer[UInt8, MutAnyOrigin],
    addr_len: UnsafePointer[UInt32, MutAnyOrigin],
    flags: Int,
) -> Int:
    """accept4(2): atomically apply SOCK_CLOEXEC / SOCK_NONBLOCK to
    the accepted fd. Avoids the race between accept(2) and a follow-
    up fcntl that the plain accept(2) creates."""
    return syscall(SYS_accept4, Int(fd), Int(addr), Int(addr_len), flags)


@always_inline
def sys_getsockname(
    fd: Int32,
    addr: UnsafePointer[UInt8, MutAnyOrigin],
    addr_len: UnsafePointer[UInt32, MutAnyOrigin],
) -> Int:
    return syscall(SYS_getsockname, Int(fd), Int(addr), Int(addr_len))


@always_inline
def sys_send(
    fd: Int32, buf: UnsafePointer[UInt8, _], n: Int, flags: Int
) -> Int:
    """Linux exposes `send` as `sendto` with NULL addr — there is no
    separate `send` syscall on x86_64."""
    return syscall(SYS_sendto, Int(fd), Int(buf), n, flags, 0, 0)


@always_inline
def sys_recv(
    fd: Int32,
    buf: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    flags: Int,
) -> Int:
    return syscall(SYS_recvfrom, Int(fd), Int(buf), n, flags, 0, 0)


@always_inline
def sys_sendto(
    fd: Int32,
    buf: UnsafePointer[UInt8, _],
    n: Int,
    flags: Int,
    addr: UnsafePointer[UInt8, _],
    addr_len: Int,
) -> Int:
    return syscall(
        SYS_sendto, Int(fd), Int(buf), n, flags, Int(addr), addr_len
    )


@always_inline
def sys_recvfrom(
    fd: Int32,
    buf: UnsafePointer[UInt8, MutAnyOrigin],
    n: Int,
    flags: Int,
    addr: UnsafePointer[UInt8, MutAnyOrigin],
    addr_len: UnsafePointer[UInt32, MutAnyOrigin],
) -> Int:
    return syscall(
        SYS_recvfrom, Int(fd), Int(buf), n, flags, Int(addr), Int(addr_len)
    )


@always_inline
def sys_writev(
    fd: Int32, iov: UnsafePointer[UInt8, _], iovcnt: Int
) -> Int:
    return syscall(SYS_writev, Int(fd), Int(iov), iovcnt)


@always_inline
def sys_readv(
    fd: Int32, iov: UnsafePointer[UInt8, MutAnyOrigin], iovcnt: Int
) -> Int:
    return syscall(SYS_readv, Int(fd), Int(iov), iovcnt)


@always_inline
def sys_setsockopt(
    fd: Int32,
    level: Int,
    name: Int,
    val: UnsafePointer[UInt8, _],
    val_len: Int,
) -> Int:
    return syscall(
        SYS_setsockopt, Int(fd), level, name, Int(val), val_len
    )


@always_inline
def sys_shutdown(fd: Int32, how: Int) -> Int:
    return syscall(SYS_shutdown, Int(fd), how)


@always_inline
def sys_fcntl_getfl(fd: Int32) -> Int:
    return syscall(SYS_fcntl, Int(fd), F_GETFL, 0)


@always_inline
def sys_fcntl_setfl(fd: Int32, flags: Int) -> Int:
    return syscall(SYS_fcntl, Int(fd), F_SETFL, flags)


@always_inline
def sys_epoll_create1(flags: Int) -> Int:
    return syscall(SYS_epoll_create1, flags)


@always_inline
def sys_epoll_ctl(
    epfd: Int32, op: Int, fd: Int32, event: UnsafePointer[UInt8, _]
) -> Int:
    return syscall(SYS_epoll_ctl, Int(epfd), op, Int(fd), Int(event))


@always_inline
def sys_epoll_pwait(
    epfd: Int32,
    events: UnsafePointer[UInt8, MutAnyOrigin],
    max_events: Int,
    timeout_ms: Int,
) -> Int:
    """epoll_wait was retired in favour of epoll_pwait (same shape with
    an extra sigmask). Pass NULL for the sigmask and 8 for sigsetsize
    (the size of a kernel sigset_t on x86_64) to get vanilla epoll_wait
    semantics."""
    return syscall(
        SYS_epoll_pwait,
        Int(epfd),
        Int(events),
        max_events,
        timeout_ms,
        0,
        8,
    )


@always_inline
def sys_socketpair(
    domain: Int,
    type_: Int,
    protocol: Int,
    out_pair: UnsafePointer[UInt8, MutAnyOrigin],
) -> Int:
    return syscall(
        SYS_socketpair, domain, type_, protocol, Int(out_pair)
    )


@always_inline
def sys_mmap(
    addr: Int,
    length: Int,
    prot: Int,
    flags: Int,
    fd: Int32,
    offset: Int,
) -> Int:
    """Returns the mapped address (as an Int) or `-errno` in the
    failure range. Use `is_syscall_error(rc)` to distinguish."""
    return syscall(SYS_mmap, addr, length, prot, flags, Int(fd), offset)


def sys_mmap_or_raise(
    length: Int, prot: Int, flags: Int, fd: Int32, offset: Int
) raises -> UnsafePointer[UInt8, MutAnyOrigin]:
    """Type-friendly mmap that returns an UnsafePointer or raises.
    `addr` is always 0 (let the kernel pick); the success range never
    includes 0 (Linux never maps page 0), so the resulting pointer is
    always valid."""
    var rc = sys_mmap(0, length, prot, flags, fd, offset)
    if is_syscall_error(rc):
        raise Error("mmap: " + errno_message(Int32(-rc)))
    return UnsafePointer[UInt8, MutAnyOrigin](unsafe_from_address=rc)


@always_inline
def sys_munmap(addr: UnsafePointer[UInt8, _], length: Int) -> Int:
    return syscall(SYS_munmap, Int(addr), length)


@always_inline
def sys_openat(
    dirfd: Int, path: UnsafePointer[UInt8, _], flags: Int, mode: Int = 0
) -> Int:
    return syscall(SYS_openat, dirfd, Int(path), flags, mode)


@always_inline
def sys_read(
    fd: Int32, buf: UnsafePointer[UInt8, MutAnyOrigin], n: Int
) -> Int:
    return syscall(SYS_read, Int(fd), Int(buf), n)


@always_inline
def sys_getrandom(
    buf: UnsafePointer[UInt8, MutAnyOrigin], n: Int, flags: Int
) -> Int:
    return syscall(SYS_getrandom, Int(buf), n, flags)


# --- error helpers ----------------------------------------------------

@always_inline
def is_syscall_error(rc: Int) -> Bool:
    """A syscall return is an error iff it falls in the -errno window.
    Linux uses -4095..-1; nothing else (including mmap pointers) ever
    lands there on x86_64."""
    return rc < 0 and rc >= -4095


def errno_message(code: Int32) -> String:
    """Stable string prefix for the common errnos. Callers raise
    `socket.<module>: <op> <tag>` and downstream code pattern-matches
    on the tag."""
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
    if code == 115:
        return "EINPROGRESS"
    if code == 125:
        return "ECANCELED"
    if code == 105:
        return "ENOBUFS"
    if code == 2:
        return "ENOENT"
    return "errno=" + String(Int(code))


# --- sockaddr layout helpers ------------------------------------------

def write_sockaddr(
    out_buf: UnsafePointer[UInt8, MutAnyOrigin],
    ip_is_v6: Bool,
    octets: InlineArray[UInt8, 16],
    port: UInt16,
) -> UInt32:
    """Serialise an (ip, port) into the kernel's `sockaddr_in[6]`
    layout. Returns the byte length the kernel expects (16 or 28)."""
    for i in range(SOCKADDR_STORAGE_SIZE):
        out_buf[i] = 0
    if not ip_is_v6:
        # struct sockaddr_in:
        #   [0..2]   sin_family (host order; LE on x86 → 0x02 0x00)
        #   [2..4]   sin_port   (network = big-endian)
        #   [4..8]   sin_addr   (network)
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
    #   [0..2]   sin6_family
    #   [2..4]   sin6_port      (BE)
    #   [4..8]   sin6_flowinfo
    #   [8..24]  sin6_addr      (16 B, network)
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
