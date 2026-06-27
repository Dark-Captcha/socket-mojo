# Blocking UDP sockets. Same byte-stream shape as TcpSocket but
# connectionless: each `send_to` / `recv_from` carries a peer address.
#
# QUIC (HTTP/3) will use this once we get there. For HTTP/3 you do
# NOT layer TLS over UDP — QUIC embeds the TLS 1.3 handshake into its
# own packets; this layer just gives QUIC the wire.

from std.memory import UnsafePointer

from socket._syscalls import (
    AF_INET,
    AF_INET6,
    SOCK_CLOEXEC,
    SOCK_DGRAM,
    SOCKADDR_STORAGE_SIZE,
    SOL_SOCKET,
    SO_RCVTIMEO,
    SO_REUSEADDR,
    SO_SNDTIMEO,
    errno_message,
    sys_bind,
    sys_close,
    sys_connect,
    sys_recvfrom,
    sys_sendto,
    sys_setsockopt,
    sys_socket,
)
from socket.addr import (
    AddressFamily,
    SocketAddr,
    read_sockaddr,
    write_sockaddr,
)


struct UdpSocket(Movable):
    """Owned UDP file descriptor."""

    var fd: Int32
    var family: AddressFamily

    def __init__(out self, fd: Int32, family: AddressFamily):
        self.fd = fd
        self.family = family

    def __del__(deinit self):
        if self.fd >= 0:
            _ = sys_close(self.fd)

    @staticmethod
    def bind(addr: SocketAddr) raises -> UdpSocket:
        """Bind to a local address. Use port 0 to let the kernel pick.
        SO_REUSEADDR is enabled (idempotent in UDP)."""
        var family = AF_INET6 if addr.kind() == AddressFamily.V6 else AF_INET
        var rc = sys_socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0)
        if rc < 0:
            raise Error("socket.udp: socket(2) " + errno_message(Int32(-rc)))
        var fd = Int32(rc)
        var one = Int32(1)
        _ = sys_setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            UnsafePointer(to=one).bitcast[UInt8](),
            4,
        )
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = write_sockaddr(sa.unsafe_ptr(), addr)
        var rv = sys_bind(fd, sa.unsafe_ptr(), Int(alen))
        if rv != 0:
            _ = sys_close(fd)
            raise Error("socket.udp: bind(2) " + errno_message(Int32(-rv)))
        return UdpSocket(fd, addr.kind())

    @staticmethod
    def open(*, ipv6: Bool = False) raises -> UdpSocket:
        """Create an unbound UDP socket. Use this when you only ever
        send (the kernel will pick a source port on first send)."""
        var family = AF_INET6 if ipv6 else AF_INET
        var rc = sys_socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0)
        if rc < 0:
            raise Error("socket.udp: socket(2) " + errno_message(Int32(-rc)))
        return UdpSocket(
            Int32(rc), AddressFamily.V6 if ipv6 else AddressFamily.V4
        )

    def connect_peer(mut self, peer: SocketAddr) raises:
        """Connect a UDP socket to a fixed peer. After this, the
        kernel filters incoming datagrams to that peer, and you can
        use plain send/recv if you prefer (we still expose
        send_to/recv_from for symmetry)."""
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = write_sockaddr(sa.unsafe_ptr(), peer)
        var rv: Int
        while True:
            rv = sys_connect(self.fd, sa.unsafe_ptr(), Int(alen))
            if rv != -4:  # not EINTR
                break
        if rv != 0:
            raise Error("socket.udp: connect(2) " + errno_message(Int32(-rv)))

    def send_to(mut self, data: Span[UInt8, _], peer: SocketAddr) raises -> Int:
        """Send one datagram. Returns the number of bytes the kernel
        accepted (almost always == len(data); UDP doesn't fragment in
        userland)."""
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = write_sockaddr(sa.unsafe_ptr(), peer)
        var n: Int
        while True:
            n = sys_sendto(
                self.fd,
                data.unsafe_ptr(),
                len(data),
                0,
                sa.unsafe_ptr(),
                Int(alen),
            )
            if n >= 0:
                break
            if n == -4:  # EINTR: retry transparently
                continue
            raise Error("socket.udp: sendto(2) " + errno_message(Int32(-n)))
        return n

    def recv_from(
        mut self, max_bytes: Int
    ) raises -> Tuple[List[UInt8], SocketAddr]:
        """Receive one datagram. Bytes exceeding `max_bytes` are
        truncated and discarded by the kernel; QUIC will pre-size.
        Single allocation: recv into a full-size buffer, then truncate
        in place (same idiom as TcpSocket.read) — no second alloc, no
        per-byte copy."""
        var buf = List[UInt8](capacity=max_bytes)
        buf.resize(unsafe_uninit_length=max_bytes)
        var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
        var alen = UInt32(SOCKADDR_STORAGE_SIZE)
        var n: Int
        while True:
            n = sys_recvfrom(
                self.fd,
                buf.unsafe_ptr(),
                max_bytes,
                0,
                sa.unsafe_ptr(),
                UnsafePointer(to=alen),
            )
            if n >= 0:
                break
            if n == -4:  # EINTR: retry transparently
                continue
            raise Error("socket.udp: recvfrom(2) " + errno_message(Int32(-n)))
        buf.resize(unsafe_uninit_length=n)
        return (buf^, read_sockaddr(sa.unsafe_ptr()))

    def set_read_timeout(mut self, seconds: Float64) raises:
        _set_one_timeout(self.fd, SO_RCVTIMEO, seconds)

    def set_write_timeout(mut self, seconds: Float64) raises:
        _set_one_timeout(self.fd, SO_SNDTIMEO, seconds)


def _set_one_timeout(fd: Int32, name: Int, seconds: Float64) raises:
    var tv = InlineArray[Int64, 2](fill=0)
    if seconds > 0:
        tv[0] = Int64(seconds)
        tv[1] = Int64((seconds - Float64(tv[0])) * 1e6)
    var rv = sys_setsockopt(
        fd, SOL_SOCKET, name, tv.unsafe_ptr().bitcast[UInt8](), 16
    )
    if rv != 0:
        raise Error(
            "socket.udp: setsockopt(timeout) " + errno_message(Int32(-rv))
        )
