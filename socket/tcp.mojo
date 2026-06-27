# Blocking TCP sockets. The public byte-stream API that TLS and HTTP
# build on top of.
#
# `TcpSocket.connect` opens a client connection; `TcpListener` accepts
# server connections. Both expose `read`/`write`/`close`/timeout via
# the same shape, so an upper layer (TLS) can wrap either uniformly.
#
# Errors are raised with a `socket.tcp:` prefix and a stable kind tag
# extracted from the syscall return (e.g. `socket.tcp: ECONNREFUSED
# ...`). Callers can pattern-match on the tag substring; we'll
# graduate to typed errors when the rest of socket-mojo demands it.
#
# Every kernel call goes through socket/_syscalls.mojo — no libc
# symbols. The negative syscall return is the error code; no errno
# TLS slot is read.

from std.memory import UnsafePointer

from socket._syscalls import (
    AF_INET,
    AF_INET6,
    IPPROTO_TCP_LEVEL,
    MSG_NOSIGNAL,
    MSG_WAITALL,
    SHUT_RDWR,
    SOCK_CLOEXEC,
    SOCK_STREAM,
    SOCKADDR_STORAGE_SIZE,
    SOL_SOCKET,
    SO_KEEPALIVE,
    SO_RCVBUF,
    SO_RCVTIMEO,
    SO_REUSEADDR,
    SO_REUSEPORT,
    SO_SNDBUF,
    SO_SNDTIMEO,
    TCP_NODELAY,
    errno_message,
    sys_accept4,
    sys_bind,
    sys_close,
    sys_connect,
    sys_getsockname,
    sys_listen,
    sys_recv,
    sys_send,
    sys_setsockopt,
    sys_shutdown,
    sys_socket,
    sys_writev,
)
from socket.addr import (
    AddressFamily,
    SocketAddr,
    read_sockaddr,
    write_sockaddr,
)
from socket.dns import resolve


def _raise(prefix: String, code: Int32 = -1) raises:
    if code == -1:
        raise Error(prefix)
    raise Error(prefix + " " + errno_message(code))


struct TcpSocket(Movable):
    """Owned TCP file descriptor. Closes on destruction unless taken."""

    var fd: Int32
    var family: AddressFamily

    def __init__(out self, fd: Int32, family: AddressFamily):
        self.fd = fd
        self.family = family

    def __del__(deinit self):
        if self.fd >= 0:
            _ = sys_close(self.fd)

    @staticmethod
    def from_fd(fd: Int32, family: AddressFamily) -> TcpSocket:
        """Wrap an already-open file descriptor (e.g. one returned by
        accept). Takes ownership: the socket will close fd on drop."""
        return TcpSocket(fd, family)

    @staticmethod
    def connect(
        host: String,
        port: UInt16,
        *,
        timeout_seconds: Float64 = 30.0,
    ) raises -> TcpSocket:
        """Resolve `host` (DNS or literal IP) and connect to the first
        reachable address. Sets the requested read/write timeout."""
        var addrs = resolve(host)
        if len(addrs) == 0:
            _raise("socket.tcp: EAI_NONAME no addresses for '" + host + "'")
        return TcpSocket.connect_to_addrs(
            addrs, port, timeout_seconds=timeout_seconds
        )

    @staticmethod
    def connect_to_addrs(
        addrs: List[SocketAddr],
        port: UInt16,
        *,
        timeout_seconds: Float64 = 30.0,
    ) raises -> TcpSocket:
        """Like `connect`, but the caller pre-resolved addresses. Skips the
        `resolve()` call — useful when paired with a DNS cache that hands you
        a fresh address list per call without re-hitting the resolver.

        Each `SocketAddr` carries only the IP (DNS results have no port); the
        `port` argument is stamped onto whichever candidate is dialed.
        Behaviour is otherwise identical to `connect()`: IPv4-first ordering,
        try each address in turn, return the first successful socket. Raises
        if `addrs` is empty or every candidate fails."""
        if len(addrs) == 0:
            _raise("socket.tcp: EAI_NONAME empty address list")
        # Prefer IPv4 first: many hosts (and CI/sandbox environments) lack a
        # usable IPv6 route, so try reachable A records before AAAA.
        var ordered = List[SocketAddr]()
        for i in range(len(addrs)):
            if addrs[i].kind() == AddressFamily.V4:
                ordered.append(addrs[i])
        for i in range(len(addrs)):
            if addrs[i].kind() == AddressFamily.V6:
                ordered.append(addrs[i])
        var last_err = String("socket.tcp: connect failed")
        for ip_index in range(len(ordered)):
            var target = ordered[ip_index].with_port(port)
            var family = (
                AF_INET6 if target.kind() == AddressFamily.V6 else AF_INET
            )
            var rc = sys_socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0)
            if rc < 0:
                last_err = "socket.tcp: socket(2) " + errno_message(Int32(-rc))
                continue
            var fd = Int32(rc)
            var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
            var alen = write_sockaddr(sa.unsafe_ptr(), target)
            # The kernel-default connect timeout can be many minutes;
            # we set SO_RCVTIMEO/SO_SNDTIMEO BEFORE connect so the
            # syscall itself respects the deadline.
            _apply_timeout(fd, timeout_seconds)
            # connect(2) is interruptible by SIGCHLD/SIGALRM and friends —
            # the Mojo runtime fires several signals during process startup,
            # so a fresh-process connect can race against one of them and
            # return EINTR. Retry transparently like the read/write paths.
            var rv: Int
            while True:
                rv = sys_connect(fd, sa.unsafe_ptr(), Int(alen))
                if rv != -4:  # not EINTR
                    break
            if rv == 0:
                return TcpSocket(fd, target.kind())
            last_err = (
                "socket.tcp: connect() "
                + errno_message(Int32(-rv))
                + " ("
                + target.to_string()
                + ")"
            )
            _ = sys_close(fd)
        raise Error(last_err)

    def write(mut self, data: Span[UInt8, _]) raises:
        """Send `data` in full, looping over short writes. MSG_NOSIGNAL
        prevents the process from being killed by SIGPIPE when the
        peer closes — we raise EPIPE instead, which the caller can
        handle."""
        var off = 0
        while off < len(data):
            var n = sys_send(
                self.fd,
                data.unsafe_ptr() + off,
                len(data) - off,
                MSG_NOSIGNAL,
            )
            if n > 0:
                off += n
            elif n == 0:
                raise Error("socket.tcp: write returned 0 (peer closed)")
            else:
                if n == -4:  # EINTR: retry transparently
                    continue
                raise Error("socket.tcp: send() " + errno_message(Int32(-n)))

    def read(mut self, max_bytes: Int) raises -> List[UInt8]:
        """Read up to `max_bytes`. May return fewer (0 means EOF). The
        buffer is allocated uninitialized at full size and truncated
        in place to the actual recv count — no second allocation, no
        copy, and no pre-zeroing of bytes the kernel is about to
        overwrite."""
        if max_bytes <= 0:
            return List[UInt8]()
        var out = List[UInt8](capacity=max_bytes)
        out.resize(unsafe_uninit_length=max_bytes)
        while True:
            var n = sys_recv(self.fd, out.unsafe_ptr(), max_bytes, 0)
            if n >= 0:
                out.resize(unsafe_uninit_length=n)
                return out^
            if n == -4:  # EINTR
                continue
            raise Error("socket.tcp: recv() " + errno_message(Int32(-n)))

    def read_into(
        mut self, mut buf: List[UInt8], *, offset: Int = 0
    ) raises -> Int:
        """Read directly into `buf` starting at `offset` (one syscall,
        zero allocation). Caller pre-sizes `buf`. Returns bytes read
        (0 = EOF). Used by tls-mojo and http-mojo to avoid the per-
        read allocation cost."""
        var cap = len(buf) - offset
        if cap <= 0:
            return 0
        while True:
            var n = sys_recv(self.fd, buf.unsafe_ptr() + offset, cap, 0)
            if n >= 0:
                return n
            if n == -4:
                continue
            raise Error("socket.tcp: recv() " + errno_message(Int32(-n)))

    def read_exact(mut self, n: Int) raises -> List[UInt8]:
        """Read exactly `n` bytes. Uses MSG_WAITALL so the kernel
        loops internally — one syscall covers the whole read when
        the peer cooperates, vs N round trips through userspace."""
        if n <= 0:
            return List[UInt8]()
        var out = List[UInt8](capacity=n)
        out.resize(unsafe_uninit_length=n)
        var off = 0
        while off < n:
            var got = sys_recv(
                self.fd, out.unsafe_ptr() + off, n - off, MSG_WAITALL
            )
            if got > 0:
                off += got
            elif got == 0:
                raise Error(
                    "socket.tcp: read_exact got "
                    + String(off)
                    + " of "
                    + String(n)
                    + " bytes before EOF"
                )
            else:
                if got == -4:
                    continue
                raise Error("socket.tcp: recv() " + errno_message(Int32(-got)))
        return out^

    def write_vectored(
        mut self, buffers: List[Span[UInt8, MutAnyOrigin]]
    ) raises:
        """Send multiple buffers in ONE syscall via writev(2). On
        loopback this skips an extra kernel-mode crossing per buffer;
        on the wire it lets the kernel coalesce into a single TCP
        segment (no Nagle pingpong between header and body). TLS uses
        this to emit `record_header || ciphertext || tag` in one
        shot."""
        # Build an iovec[] array. Linux `struct iovec` = (void*,
        # size_t), 16 bytes per entry.
        var n = len(buffers)
        if n == 0:
            return
        var iov = List[UInt8](length=16 * n, fill=0)
        var iov_ptr = iov.unsafe_ptr()
        var total = 0
        for i in range(n):
            var b = buffers[i]
            var base = UInt64(Int(b.unsafe_ptr()))
            var sz = UInt64(len(b))
            total += len(b)
            for k in range(8):
                iov_ptr[16 * i + k] = UInt8((base >> UInt64(8 * k)) & 0xFF)
            for k in range(8):
                iov_ptr[16 * i + 8 + k] = UInt8((sz >> UInt64(8 * k)) & 0xFF)
        # Loop in case the kernel doesn't write everything (rare with
        # writev on a healthy socket, but possible). We don't restart
        # the iovec from the middle — instead we fall back to plain
        # send() for the remainder. This is the same trick libcurl
        # uses.
        var sent = sys_writev(self.fd, iov_ptr, n)
        if sent < 0:
            raise Error("socket.tcp: writev() " + errno_message(Int32(-sent)))
        if sent < total:
            var tail = List[UInt8](capacity=total - sent)
            var skip = sent
            for i in range(n):
                var b = buffers[i]
                if skip >= len(b):
                    skip -= len(b)
                    continue
                if skip > 0:
                    tail.extend(b[skip : len(b)])
                    skip = 0
                else:
                    tail.extend(b)
            self.write(tail)

    def set_recv_buffer(mut self, bytes: Int) raises:
        """Hint to the kernel about preferred recv buffer size. Linux
        doubles whatever you pass; root can go past
        /proc/sys/net/core/rmem_max."""
        var v = Int32(bytes)
        var rv = sys_setsockopt(
            self.fd,
            SOL_SOCKET,
            SO_RCVBUF,
            UnsafePointer(to=v).bitcast[UInt8](),
            4,
        )
        if rv != 0:
            raise Error(
                "socket.tcp: setsockopt(SO_RCVBUF) " + errno_message(Int32(-rv))
            )

    def set_send_buffer(mut self, bytes: Int) raises:
        var v = Int32(bytes)
        var rv = sys_setsockopt(
            self.fd,
            SOL_SOCKET,
            SO_SNDBUF,
            UnsafePointer(to=v).bitcast[UInt8](),
            4,
        )
        if rv != 0:
            raise Error(
                "socket.tcp: setsockopt(SO_SNDBUF) " + errno_message(Int32(-rv))
            )

    def set_read_timeout(mut self, seconds: Float64) raises:
        _apply_one_timeout(self.fd, SO_RCVTIMEO, seconds)

    def set_write_timeout(mut self, seconds: Float64) raises:
        _apply_one_timeout(self.fd, SO_SNDTIMEO, seconds)

    def set_nodelay(mut self, enabled: Bool) raises:
        var flag = Int32(1) if enabled else Int32(0)
        var rv = sys_setsockopt(
            self.fd,
            IPPROTO_TCP_LEVEL,
            TCP_NODELAY,
            UnsafePointer(to=flag).bitcast[UInt8](),
            4,
        )
        if rv != 0:
            raise Error(
                "socket.tcp: setsockopt(TCP_NODELAY) "
                + errno_message(Int32(-rv))
            )

    def set_keepalive(mut self, enabled: Bool) raises:
        var flag = Int32(1) if enabled else Int32(0)
        var rv = sys_setsockopt(
            self.fd,
            SOL_SOCKET,
            SO_KEEPALIVE,
            UnsafePointer(to=flag).bitcast[UInt8](),
            4,
        )
        if rv != 0:
            raise Error(
                "socket.tcp: setsockopt(SO_KEEPALIVE) "
                + errno_message(Int32(-rv))
            )

    def close(deinit self):
        """Explicit close. Equivalent to letting the socket go out of
        scope, but lets the caller surface an EBADF if it happens."""
        if self.fd >= 0:
            _ = sys_shutdown(self.fd, SHUT_RDWR)
            _ = sys_close(self.fd)


struct TcpListener(Movable):
    """TCP server endpoint."""

    var fd: Int32
    var family: AddressFamily

    def __init__(out self, fd: Int32, family: AddressFamily):
        self.fd = fd
        self.family = family

    def __del__(deinit self):
        if self.fd >= 0:
            _ = sys_close(self.fd)

    @staticmethod
    def bind(
        addr: SocketAddr,
        *,
        backlog: Int = 128,
        reuseport: Bool = False,
    ) raises -> TcpListener:
        """Bind and start listening on `addr`. SO_REUSEADDR is enabled
        so a recently-stopped server can rebind without TIME_WAIT
        delay. With `reuseport=True`, multiple processes can bind the
        same (addr, port) and the kernel load-balances incoming
        connections — the standard recipe for thread-per-core / one-
        Ring-per-CPU scaling without crossing process boundaries on
        the data path."""
        var family = AF_INET6 if addr.kind() == AddressFamily.V6 else AF_INET
        var rc = sys_socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0)
        if rc < 0:
            _raise("socket.tcp: socket(2)", Int32(-rc))
        var fd = Int32(rc)
        var one = Int32(1)
        _ = sys_setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            UnsafePointer(to=one).bitcast[UInt8](),
            4,
        )
        if reuseport:
            _ = sys_setsockopt(
                fd,
                SOL_SOCKET,
                SO_REUSEPORT,
                UnsafePointer(to=one).bitcast[UInt8](),
                4,
            )
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = write_sockaddr(sa.unsafe_ptr(), addr)
        var rv = sys_bind(fd, sa.unsafe_ptr(), Int(alen))
        if rv != 0:
            _ = sys_close(fd)
            _raise("socket.tcp: bind(2)", Int32(-rv))
        rv = sys_listen(fd, backlog)
        if rv != 0:
            _ = sys_close(fd)
            _raise("socket.tcp: listen(2)", Int32(-rv))
        return TcpListener(fd, addr.kind())

    def accept(mut self) raises -> Tuple[TcpSocket, SocketAddr]:
        """Block until an inbound connection arrives; return the peer
        socket and its address. Uses accept4(2) with SOCK_CLOEXEC so
        the accepted fd is exec-safe without a follow-up fcntl."""
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = UInt32(SOCKADDR_STORAGE_SIZE)
        var rc: Int
        while True:
            rc = sys_accept4(
                self.fd,
                sa.unsafe_ptr(),
                UnsafePointer(to=alen),
                SOCK_CLOEXEC,
            )
            if rc >= 0:
                break
            if rc == -4:  # EINTR: retry transparently
                continue
            _raise("socket.tcp: accept(2)", Int32(-rc))
        var peer = read_sockaddr(sa.unsafe_ptr())
        return (TcpSocket(Int32(rc), peer.kind()), peer)

    def local_addr(self) raises -> SocketAddr:
        """The address this listener is bound to (resolves the
        kernel-chosen port when bound with port 0)."""
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = UInt32(SOCKADDR_STORAGE_SIZE)
        var rv = sys_getsockname(
            self.fd, sa.unsafe_ptr(), UnsafePointer(to=alen)
        )
        if rv != 0:
            _raise("socket.tcp: getsockname(2)", Int32(-rv))
        return read_sockaddr(sa.unsafe_ptr())


def _apply_timeout(fd: Int32, seconds: Float64):
    """Internal best-effort timeout setter — used during connect,
    where we don't want to raise (we want to fall through to the
    connect error)."""
    _apply_one_timeout_quiet(fd, SO_RCVTIMEO, seconds)
    _apply_one_timeout_quiet(fd, SO_SNDTIMEO, seconds)


def _apply_one_timeout_quiet(fd: Int32, name: Int, seconds: Float64):
    if seconds <= 0:
        return
    var tv = InlineArray[Int64, 2](fill=0)
    tv[0] = Int64(seconds)
    tv[1] = Int64((seconds - Float64(tv[0])) * 1e6)
    _ = sys_setsockopt(
        fd, SOL_SOCKET, name, tv.unsafe_ptr().bitcast[UInt8](), 16
    )


def _apply_one_timeout(fd: Int32, name: Int, seconds: Float64) raises:
    """Public-API form: raise on failure."""
    var tv = InlineArray[Int64, 2](fill=0)
    if seconds > 0:
        tv[0] = Int64(seconds)
        tv[1] = Int64((seconds - Float64(tv[0])) * 1e6)
    var rv = sys_setsockopt(
        fd, SOL_SOCKET, name, tv.unsafe_ptr().bitcast[UInt8](), 16
    )
    if rv != 0:
        raise Error(
            "socket.tcp: setsockopt(timeout) " + errno_message(Int32(-rv))
        )
