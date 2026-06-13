# DNS resolution via libc `getaddrinfo`. Synchronous and blocking, like
# every other v0 entry point. The function follows the system resolver
# (`/etc/resolv.conf` on Linux), so it inherits whatever DNS-over-TLS /
# resolved / mDNS configuration is in place.
#
# For literal IP strings (`127.0.0.1`, `::1`) we short-circuit and skip
# the resolver entirely.
#
# Pointer handling note: this Mojo nightly's `UnsafePointer` is non-
# nullable, so we never construct one from `nullptr`. Foreign pointers
# the C ABI hands back through out-params land in an 8-byte InlineArray
# slot; we read them as a `UInt64` and only convert to an
# UnsafePointer-shaped UInt when handing them straight back to libc
# (`freeaddrinfo`). The byte-by-byte poke into `struct addrinfo` works
# because we only ever read it.

from std.ffi import external_call

from socket._libc import AF_INET, AF_INET6, SOCK_STREAM
from socket.addr import IpAddress, parse_ip


# struct addrinfo on Linux glibc (48 bytes; offsets matter):
#   [0..4]   ai_flags     int
#   [4..8]   ai_family    int
#   [8..12]  ai_socktype  int
#   [12..16] ai_protocol  int
#   [16..20] ai_addrlen   socklen_t (uint32)
#   [20..24] padding
#   [24..32] ai_addr      sockaddr*
#   [32..40] ai_canonname char*
#   [40..48] ai_next      addrinfo*


@always_inline
def _load_u64_le(buf: InlineArray[UInt8, 8]) -> UInt64:
    var w = UInt64(0)
    for i in range(8):
        w |= UInt64(buf[i]) << UInt64(8 * i)
    return w


@always_inline
def _read_u8_at_addr(addr: UInt64, offset: Int) -> UInt8:
    """Treat `addr` as a raw foreign pointer and read one byte at
    `addr + offset`. Used to walk the libc-allocated addrinfo linked
    list without ever constructing an UnsafePointer through `nullptr`.
    """
    # We bridge through libc memcpy: copy 1 byte from (addr+offset) into
    # a local stack slot. This avoids any UnsafePointer construction
    # for the unknown remote address.
    var slot = InlineArray[UInt8, 1](fill=0)
    _ = external_call["memcpy", UInt](
        slot.unsafe_ptr(),
        UInt(Int(addr) + offset),
        UInt(1),
    )
    return slot[0]


@always_inline
def _read_u32_at_addr(addr: UInt64, offset: Int) -> UInt32:
    var slot = InlineArray[UInt8, 4](fill=0)
    _ = external_call["memcpy", UInt](
        slot.unsafe_ptr(),
        UInt(Int(addr) + offset),
        UInt(4),
    )
    return (
        UInt32(slot[0])
        | (UInt32(slot[1]) << 8)
        | (UInt32(slot[2]) << 16)
        | (UInt32(slot[3]) << 24)
    )


@always_inline
def _read_u64_at_addr(addr: UInt64, offset: Int) -> UInt64:
    var slot = InlineArray[UInt8, 8](fill=0)
    _ = external_call["memcpy", UInt](
        slot.unsafe_ptr(),
        UInt(Int(addr) + offset),
        UInt(8),
    )
    return _load_u64_le(slot)


def resolve(host: String) raises -> List[IpAddress]:
    """Resolve `host` to a list of IP addresses. Literal IPs short-
    circuit. Raises with prefix `socket.dns:` on failure."""
    # Literal-IP fast path.
    try:
        var literal = parse_ip(host)
        var out = List[IpAddress]()
        out.append(literal)
        return out^
    except:
        pass

    # NUL-terminated host name for libc.
    var host_c = List[UInt8](capacity=host.byte_length() + 1)
    host_c.extend(host.as_bytes())
    host_c.append(0)

    var hints = InlineArray[UInt8, 48](fill=0)
    # ai_family = AF_UNSPEC (0), ai_socktype = SOCK_STREAM (1)
    hints[8] = UInt8(SOCK_STREAM)

    # `res` is an `out` pointer-to-pointer; stash the 8-byte foreign
    # pointer libc writes here in an InlineArray.
    var res_slot = InlineArray[UInt8, 8](fill=0)
    var rv = external_call["getaddrinfo", Int32](
        host_c.unsafe_ptr(),
        UInt(0),  # service = NULL
        hints.unsafe_ptr(),
        res_slot.unsafe_ptr(),
    )
    if rv != 0:
        raise Error(
            "socket.dns: getaddrinfo('"
            + host
            + "') failed with code "
            + String(Int(rv))
        )
    var head = _load_u64_le(res_slot)
    var out = List[IpAddress]()
    var node = head
    while node != 0:
        var family = _read_u32_at_addr(node, 4)
        var addr_ptr = _read_u64_at_addr(node, 24)  # ai_addr
        if family == UInt32(AF_INET):
            # sockaddr_in: family(2) | port(2) | inaddr(4) | pad(8)
            var b0 = _read_u8_at_addr(addr_ptr, 4)
            var b1 = _read_u8_at_addr(addr_ptr, 5)
            var b2 = _read_u8_at_addr(addr_ptr, 6)
            var b3 = _read_u8_at_addr(addr_ptr, 7)
            out.append(IpAddress.v4(b0, b1, b2, b3))
        elif family == UInt32(AF_INET6):
            # sockaddr_in6: family(2) | port(2) | flowinfo(4) | addr(16) | scope(4)
            var bytes16 = InlineArray[UInt8, 16](fill=0)
            for i in range(16):
                bytes16[i] = _read_u8_at_addr(addr_ptr, 8 + i)
            out.append(IpAddress(True, bytes16))
        # else: skip unknown families (AF_PACKET, etc.)
        node = _read_u64_at_addr(node, 40)  # ai_next
    _ = external_call["freeaddrinfo", NoneType](UInt(Int(head)))
    return out^


# --- Ring-driven resolver (RFC 1035 over the io_uring engine) -----------
#
# The sans-io codec lives in socket/dnswire.mojo; this drives it: UDP
# with a deadline and one retry (fresh transaction id each attempt),
# then TCP fallback when the server truncates. Uses a private Ring so
# its completions never interleave with a caller's.

from socket._libc import (
    SOCK_DGRAM,
    close as _libc_close,
    connect as _libc_connect,
    errno as _errno,
    errno_message as _errno_message,
    socket as _libc_socket,
    write_sockaddr as _write_sockaddr,
    SOCKADDR_STORAGE_SIZE as _SS_SIZE,
)
from socket.addr import SocketAddr
from socket.dnswire import (
    QTYPE_A,
    dns_build_query,
    dns_parse_response,
)
from socket.ring import KIND_RECV, KIND_SEND, Completion, Ring


def _random_txid() raises -> UInt16:
    # transaction ids must be unpredictable (spoofing resistance)
    var b = InlineArray[UInt8, 2](fill=0)
    var n = external_call["getrandom", Int](b.unsafe_ptr(), 2, UInt32(0))
    if n != 2:
        raise Error("socket.dns: getrandom failed")
    return (UInt16(b[0]) << 8) | UInt16(b[1])


def _connected_socket(server: SocketAddr, socktype: Int32) raises -> Int32:
    var family = Int32(AF_INET6 if server.ip.is_v6 else AF_INET)
    var fd = _libc_socket(family, socktype, Int32(0))
    if fd < 0:
        raise Error("socket.dns: socket() " + _errno_message(_errno()))
    var sa = InlineArray[UInt8, _SS_SIZE](fill=0)
    var alen = _write_sockaddr(
        sa.unsafe_ptr(), server.ip.is_v6, server.ip.octets, server.port
    )
    # UDP connect is local bookkeeping; TCP connect through the ring
    # would also work, but a blocking loopback/LAN connect keeps the
    # resolver's completion handling single-purpose.
    if _libc_connect(fd, sa.unsafe_ptr(), alen) != 0:
        var msg = _errno_message(_errno())
        _ = _libc_close(fd)
        raise Error("socket.dns: connect() " + msg)
    return fd


def _await_recv(mut ring: Ring) raises -> Completion:
    """Drives the private ring until the recv completes; send acks and
    timeout partners are validated and dropped."""
    while True:
        _ = ring.wait(min_complete=1)
        while True:
            var c = ring.next_completion()
            if not c:
                break
            var done = c.take()
            if done.kind == KIND_RECV:
                return done^
            if done.kind == KIND_SEND:
                done.ok()
            # timeout partners and close acks: nothing to check


def _drain(mut ring: Ring) raises:
    """Reap and discard any remaining completions on a private ring."""
    while True:
        var c = ring.next_completion()
        if not c:
            break
        _ = c.take()


def _query_udp(
    server: SocketAddr, query: Span[UInt8, _], timeout_ms: Int
) raises -> List[UInt8]:
    var ring = Ring(16)
    # _connected_socket returns a raw fd nothing owns; reclaim it on every
    # exit (the ring only owns its own io_uring fd).
    var fd = _connected_socket(server, Int32(SOCK_DGRAM))
    try:
        _ = ring.send_copy(fd, query)
        _ = ring.recv_with_timeout(fd, 2048, Int64(timeout_ms) * 1_000_000)
        var got = _await_recv(ring)
        if got.res == -125:  # ECANCELED: the deadline fired first
            raise Error("socket.dns: query timed out")
        got.ok()
        var payload = got.take_buffer()
        _ = ring.close_fd(fd)
        _ = ring.wait(min_complete=1)
        _drain(ring)
        return payload^
    except e:
        _ = _libc_close(fd)
        raise e^


def _query_tcp(
    server: SocketAddr, query: Span[UInt8, _], timeout_ms: Int
) raises -> List[UInt8]:
    var ring = Ring(16)
    # _connected_socket returns a raw fd nothing owns; reclaim it on every exit.
    var fd = _connected_socket(server, Int32(SOCK_STREAM))
    try:
        # RFC 1035 4.2.2: two-byte big-endian length prefix
        var framed = List[UInt8](capacity=len(query) + 2)
        framed.append(UInt8(len(query) >> 8))
        framed.append(UInt8(len(query) & 0xFF))
        framed.extend(query)
        _ = ring.send(fd, framed^)
        var acc = List[UInt8]()
        var want = -1
        var deadline_each = Int64(timeout_ms) * 1_000_000
        while want < 0 or len(acc) < want + 2:
            _ = ring.recv_with_timeout(fd, 4096, deadline_each)
            var got = _await_recv(ring)
            if got.res == -125:
                raise Error("socket.dns: tcp query timed out")
            got.ok()
            if got.res == 0:
                raise Error("socket.dns: tcp connection closed early")
            var chunk = got.take_buffer()
            acc.extend(Span(chunk))
            if want < 0 and len(acc) >= 2:
                want = (Int(acc[0]) << 8) | Int(acc[1])
        _ = ring.close_fd(fd)
        _ = ring.wait(min_complete=1)
        _drain(ring)
        var body = List[UInt8](capacity=want)
        body.extend(Span(acc)[2 : 2 + want])
        return body^
    except e:
        _ = _libc_close(fd)
        raise e^


def resolve_dns(
    host: String,
    *,
    server: SocketAddr,
    qtype: UInt16 = QTYPE_A,
    timeout_ms: Int = 2000,
    retries: Int = 2,
) raises -> List[IpAddress]:
    """Resolves `host` against an explicit DNS server through the
    io_uring engine.

    UDP with per-attempt deadline and fresh transaction ids, TCP
    fallback on truncation. NXDOMAIN and other server errors raise; an
    empty answer returns an empty list. (resolve(), above, remains the
    system-configured getaddrinfo path.)
    """
    try:
        var literal = parse_ip(host)
        var out = List[IpAddress]()
        out.append(literal)
        return out^
    except:
        pass
    for attempt in range(retries):
        var txid = _random_txid()
        var query = dns_build_query(txid, host, qtype)
        var raw: List[UInt8]
        try:
            raw = _query_udp(server, Span(query), timeout_ms)
        except:
            # timeout or transport failure: retry with a fresh txid
            if attempt + 1 == retries:
                raise Error(
                    "socket.dns: no response from server for '"
                    + host
                    + "' after "
                    + String(retries)
                    + " attempts"
                )
            continue
        var ans = dns_parse_response(Span(raw), txid, qtype, host)
        if ans.truncated:
            var raw2 = _query_tcp(server, Span(query), timeout_ms)
            ans = dns_parse_response(Span(raw2), txid, qtype, host)
        if ans.rcode != 0:
            # server-reported errors are final, no retry
            raise Error(
                "socket.dns: server error rcode="
                + String(Int(ans.rcode))
                + " for '"
                + host
                + "'"
            )
        return ans.addresses.copy()
    raise Error("socket.dns: unreachable")
