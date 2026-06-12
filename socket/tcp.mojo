# Blocking TCP sockets. The public byte-stream API that TLS and HTTP
# build on top of.
#
# `TcpSocket.connect` opens a client connection; `TcpListener` accepts
# server connections. Both expose `read`/`write`/`close`/timeout via the
# same shape, so an upper layer (TLS) can wrap either uniformly.
#
# Errors are raised with a `socket.tcp:` prefix and a stable kind tag
# extracted from errno (e.g. `socket.tcp: ECONNREFUSED ...`). Callers
# can pattern-match on the tag substring; we'll graduate to typed
# errors when the rest of socket-mojo demands it.

from std.memory import UnsafePointer

from socket._libc import (
    AF_INET,
    AF_INET6,
    IPPROTO_TCP_LEVEL,
    MSG_NOSIGNAL,
    MSG_WAITALL,
    SHUT_RDWR,
    SOCK_STREAM,
    SOCKADDR_STORAGE_SIZE,
    SOL_SOCKET,
    SO_KEEPALIVE,
    SO_RCVBUF,
    SO_RCVTIMEO,
    SO_REUSEADDR,
    SO_SNDBUF,
    SO_SNDTIMEO,
    TCP_NODELAY,
    accept,
    bind,
    close,
    connect,
    errno,
    errno_message,
    listen,
    read_sockaddr,
    readv,
    recv,
    send,
    setsockopt,
    shutdown,
    socket as libc_socket,
    write_sockaddr,
    writev,
)
from socket.addr import IpAddress, SocketAddr
from socket.dns import resolve


def _raise(prefix: String, code: Int32 = -1) raises:
    if code == -1:
        raise Error(prefix)
    raise Error(prefix + " " + errno_message(code))


struct TcpSocket(Movable):
    """Owned TCP file descriptor. Closes on destruction unless taken."""

    var fd: Int32
    var is_v6: Bool

    def __init__(out self, fd: Int32, is_v6: Bool):
        self.fd = fd
        self.is_v6 = is_v6

    def __del__(deinit self):
        if self.fd >= 0:
            _ = close(self.fd)

    @staticmethod
    def from_fd(fd: Int32, is_v6: Bool) -> TcpSocket:
        """Wrap an already-open file descriptor (e.g. one returned by
        accept). Takes ownership: the socket will close fd on drop."""
        return TcpSocket(fd, is_v6)

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
        var last_err = String("socket.tcp: connect failed")
        for ip_index in range(len(addrs)):
            var ip = addrs[ip_index]
            var family = AF_INET6 if ip.is_v6 else AF_INET
            var fd = libc_socket(Int32(family), Int32(SOCK_STREAM), Int32(0))
            if fd < 0:
                last_err = "socket.tcp: socket(2) " + errno_message(errno())
                continue
            var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
            var alen = write_sockaddr(sa.unsafe_ptr(), ip.is_v6, ip.octets, port)
            # The kernel-default connect timeout can be many minutes; we
            # set SO_RCVTIMEO/SO_SNDTIMEO BEFORE connect so the syscall
            # itself respects the deadline.
            _apply_timeout(fd, timeout_seconds)
            var rv = connect(fd, sa.unsafe_ptr(), alen)
            if rv == 0:
                return TcpSocket(fd, ip.is_v6)
            last_err = (
                "socket.tcp: connect() "
                + errno_message(errno())
                + " ("
                + ip.to_string()
                + ":"
                + String(Int(port))
                + ")"
            )
            _ = close(fd)
        raise Error(last_err)

    def write(mut self, data: Span[UInt8, _]) raises:
        """Send `data` in full, looping over short writes. MSG_NOSIGNAL
        prevents the process from being killed by SIGPIPE when the peer
        closes — we raise EPIPE instead, which the caller can handle."""
        var off = 0
        while off < len(data):
            var n = send(
                self.fd,
                data.unsafe_ptr() + off,
                len(data) - off,
                Int32(MSG_NOSIGNAL),
            )
            if n > 0:
                off += n
            elif n == 0:
                raise Error("socket.tcp: write returned 0 (peer closed)")
            else:
                var e = errno()
                if e == 4:  # EINTR: retry transparently
                    continue
                raise Error("socket.tcp: send() " + errno_message(e))

    def read(mut self, max_bytes: Int) raises -> List[UInt8]:
        """Read up to `max_bytes`. May return fewer (0 means EOF).
        Zero-copy: a single List is allocated at full size and resized
        down to the actual byte count via the `length` mutator path."""
        if max_bytes <= 0:
            return List[UInt8]()
        var out = List[UInt8](length=max_bytes, fill=0)
        while True:
            var n = recv(self.fd, out.unsafe_ptr(), max_bytes, Int32(0))
            if n >= 0:
                # Truncate the List in-place to the actual recv size.
                # No copy: just shrink len; the trailing capacity is
                # released when the List drops or grows past it.
                out.resize(unsafe_uninit_length=n)
                return out^
            var e = errno()
            if e == 4:  # EINTR
                continue
            raise Error("socket.tcp: recv() " + errno_message(e))

    def read_into(mut self, mut buf: List[UInt8], *, offset: Int = 0) raises -> Int:
        """Read directly into `buf` starting at `offset` (one syscall,
        zero allocation). Caller pre-sizes `buf`. Returns bytes read
        (0 = EOF). Used by tls-mojo and http-mojo to avoid the per-
        read allocation cost."""
        var cap = len(buf) - offset
        if cap <= 0:
            return 0
        while True:
            var n = recv(self.fd, buf.unsafe_ptr() + offset, cap, Int32(0))
            if n >= 0:
                return n
            var e = errno()
            if e == 4:
                continue
            raise Error("socket.tcp: recv() " + errno_message(e))

    def read_exact(mut self, n: Int) raises -> List[UInt8]:
        """Read exactly `n` bytes. Uses MSG_WAITALL so the kernel loops
        internally — one syscall covers the whole read when the peer
        cooperates, vs N round trips through userspace."""
        if n <= 0:
            return List[UInt8]()
        var out = List[UInt8](length=n, fill=0)
        var off = 0
        while off < n:
            var got = recv(
                self.fd, out.unsafe_ptr() + off, n - off, Int32(MSG_WAITALL)
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
                var e = errno()
                if e == 4:
                    continue
                raise Error("socket.tcp: recv() " + errno_message(e))
        return out^

    def write_vectored(mut self, buffers: List[Span[UInt8, MutAnyOrigin]]) raises:
        """Send multiple buffers in ONE syscall via writev(2). On
        loopback this skips an extra kernel-mode crossing per buffer;
        on the wire it lets the kernel coalesce into a single TCP
        segment (no Nagle pingpong between header and body). TLS uses
        this to emit `record_header || ciphertext || tag` in one shot.
        """
        # Build an iovec[] array. Linux `struct iovec` = (void*, size_t),
        # 16 bytes per entry.
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
        # send() for the remainder. This is the same trick libcurl uses.
        var sent = writev(self.fd, iov_ptr, Int32(n))
        if sent < 0:
            raise Error("socket.tcp: writev() " + errno_message(errno()))
        if sent < total:
            # Compose the unsent tail into a flat buffer and send normally.
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
        doubles whatever you pass; root can go past /proc/sys/net/core/
        rmem_max."""
        var v = Int32(bytes)
        var rv = setsockopt(
            self.fd,
            Int32(SOL_SOCKET),
            Int32(SO_RCVBUF),
            UnsafePointer(to=v).bitcast[UInt8](),
            UInt32(4),
        )
        if rv != 0:
            raise Error("socket.tcp: setsockopt(SO_RCVBUF) " + errno_message(errno()))

    def set_send_buffer(mut self, bytes: Int) raises:
        var v = Int32(bytes)
        var rv = setsockopt(
            self.fd,
            Int32(SOL_SOCKET),
            Int32(SO_SNDBUF),
            UnsafePointer(to=v).bitcast[UInt8](),
            UInt32(4),
        )
        if rv != 0:
            raise Error("socket.tcp: setsockopt(SO_SNDBUF) " + errno_message(errno()))

    def set_read_timeout(mut self, seconds: Float64) raises:
        _apply_one_timeout(self.fd, SO_RCVTIMEO, seconds)

    def set_write_timeout(mut self, seconds: Float64) raises:
        _apply_one_timeout(self.fd, SO_SNDTIMEO, seconds)

    def set_nodelay(mut self, enabled: Bool) raises:
        var flag = Int32(1) if enabled else Int32(0)
        var rv = setsockopt(
            self.fd,
            Int32(IPPROTO_TCP_LEVEL),
            Int32(TCP_NODELAY),
            UnsafePointer(to=flag).bitcast[UInt8](),
            UInt32(4),
        )
        if rv != 0:
            raise Error("socket.tcp: setsockopt(TCP_NODELAY) " + errno_message(errno()))

    def set_keepalive(mut self, enabled: Bool) raises:
        var flag = Int32(1) if enabled else Int32(0)
        var rv = setsockopt(
            self.fd,
            Int32(SOL_SOCKET),
            Int32(SO_KEEPALIVE),
            UnsafePointer(to=flag).bitcast[UInt8](),
            UInt32(4),
        )
        if rv != 0:
            raise Error(
                "socket.tcp: setsockopt(SO_KEEPALIVE) " + errno_message(errno())
            )

    def close(deinit self):
        """Explicit close. Equivalent to letting the socket go out of
        scope, but lets the caller surface an EBADF if it happens."""
        if self.fd >= 0:
            _ = shutdown(self.fd, Int32(SHUT_RDWR))
            _ = close(self.fd)


struct TcpListener(Movable):
    """TCP server endpoint."""

    var fd: Int32
    var is_v6: Bool

    def __init__(out self, fd: Int32, is_v6: Bool):
        self.fd = fd
        self.is_v6 = is_v6

    def __del__(deinit self):
        if self.fd >= 0:
            _ = close(self.fd)

    @staticmethod
    def bind(addr: SocketAddr, *, backlog: Int = 128) raises -> TcpListener:
        """Bind and start listening on `addr`. SO_REUSEADDR is enabled
        so a recently-stopped server can rebind without TIME_WAIT
        delay."""
        var family = AF_INET6 if addr.ip.is_v6 else AF_INET
        var fd = libc_socket(Int32(family), Int32(SOCK_STREAM), Int32(0))
        if fd < 0:
            _raise("socket.tcp: socket(2)", errno())
        var one = Int32(1)
        _ = setsockopt(
            fd,
            Int32(SOL_SOCKET),
            Int32(SO_REUSEADDR),
            UnsafePointer(to=one).bitcast[UInt8](),
            UInt32(4),
        )
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = write_sockaddr(
            sa.unsafe_ptr(), addr.ip.is_v6, addr.ip.octets, addr.port
        )
        var rv = bind(fd, sa.unsafe_ptr(), alen)
        if rv != 0:
            var e = errno()
            _ = close(fd)
            _raise("socket.tcp: bind(2)", e)
        rv = listen(fd, Int32(backlog))
        if rv != 0:
            var e = errno()
            _ = close(fd)
            _raise("socket.tcp: listen(2)", e)
        return TcpListener(fd, addr.ip.is_v6)

    def accept(mut self) raises -> Tuple[TcpSocket, SocketAddr]:
        """Block until an inbound connection arrives; return the peer
        socket and its address."""
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = UInt32(SOCKADDR_STORAGE_SIZE)
        var afd = accept(
            self.fd,
            sa.unsafe_ptr(),
            UnsafePointer(to=alen),
        )
        if afd < 0:
            _raise("socket.tcp: accept(2)", errno())
        var is_v6: Bool
        var octets: InlineArray[UInt8, 16]
        var port: UInt16
        is_v6, octets, port = read_sockaddr(sa.unsafe_ptr())
        return (
            TcpSocket(afd, is_v6),
            SocketAddr(IpAddress(is_v6, octets), port),
        )

    def local_addr(self) raises -> SocketAddr:
        # getsockname is a separate syscall; we omit it from v0 because
        # the listener was constructed FROM a known address. Callers
        # bind explicitly; the auto-port case will be added when needed.
        raise Error("socket.tcp: local_addr() not yet implemented")


def _apply_timeout(fd: Int32, seconds: Float64):
    """Internal best-effort timeout setter — used during connect, where
    we don't want to raise (we want to fall through to the connect
    error)."""
    _apply_one_timeout_quiet(fd, SO_RCVTIMEO, seconds)
    _apply_one_timeout_quiet(fd, SO_SNDTIMEO, seconds)


def _apply_one_timeout_quiet(fd: Int32, name: Int, seconds: Float64):
    if seconds <= 0:
        return
    var tv = InlineArray[Int64, 2](fill=0)
    tv[0] = Int64(seconds)
    tv[1] = Int64((seconds - Float64(tv[0])) * 1e6)
    _ = setsockopt(
        fd,
        Int32(SOL_SOCKET),
        Int32(name),
        tv.unsafe_ptr().bitcast[UInt8](),
        UInt32(16),
    )


def _apply_one_timeout(fd: Int32, name: Int, seconds: Float64) raises:
    """Public-API form: raise on failure."""
    var tv = InlineArray[Int64, 2](fill=0)
    if seconds > 0:
        tv[0] = Int64(seconds)
        tv[1] = Int64((seconds - Float64(tv[0])) * 1e6)
    var rv = setsockopt(
        fd,
        Int32(SOL_SOCKET),
        Int32(name),
        tv.unsafe_ptr().bitcast[UInt8](),
        UInt32(16),
    )
    if rv != 0:
        raise Error("socket.tcp: setsockopt(timeout) " + errno_message(errno()))
