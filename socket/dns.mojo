# Native DNS resolver. No getaddrinfo, no glibc nss, no system
# resolver consultation through libc. Reads /etc/hosts and /etc/
# resolv.conf directly via openat(2)/read(2), and drives the
# RFC 1035 codec (dnswire.mojo) over io_uring for the network half.
#
# Lookup order in `resolve(host)`:
#   1. literal IP   → return immediately
#   2. /etc/hosts   → return matching aliases (system override)
#   3. /etc/resolv.conf nameservers → UDP query with retry + TCP
#      fallback on TC. Queries A then AAAA against the first
#      nameserver that responds; rcode != 0 (NXDOMAIN, etc.) is
#      terminal — we don't retry other nameservers in that case.

from socket._syscalls import (
    AF_INET,
    AF_INET6,
    AT_FDCWD,
    O_CLOEXEC,
    O_RDONLY,
    SOCK_CLOEXEC,
    SOCK_DGRAM,
    SOCK_STREAM,
    SOCKADDR_STORAGE_SIZE,
    errno_message,
    sys_close,
    sys_connect,
    sys_getrandom,
    sys_openat,
    sys_read,
    sys_socket,
)
from socket.addr import (
    AddressFamily,
    Ipv4Address,
    SocketAddr,
    parse_ip,
    write_sockaddr,
)
from socket.dnswire import (
    DnsAnswer,
    QTYPE_A,
    QTYPE_AAAA,
    dns_build_query,
    dns_parse_response,
)
from socket.ring import Completion, CompletionKind, Ring


# --- file reading helpers --------------------------------------------


def _read_file_bytes(path: String) raises -> List[UInt8]:
    """Read a whole small text file. Used for /etc/hosts and
    /etc/resolv.conf — neither is large enough to merit streaming."""
    var path_c = List[UInt8](capacity=path.byte_length() + 1)
    path_c.extend(path.as_bytes())
    path_c.append(0)
    var rc = sys_openat(AT_FDCWD, path_c.unsafe_ptr(), O_RDONLY | O_CLOEXEC)
    if rc < 0:
        raise Error(
            "socket.dns: open " + path + " " + errno_message(Int32(-rc))
        )
    var fd = Int32(rc)
    var out = List[UInt8]()
    var buf = List[UInt8](capacity=4096)
    buf.resize(unsafe_uninit_length=4096)
    while True:
        var n = sys_read(fd, buf.unsafe_ptr(), 4096)
        if n < 0:
            _ = sys_close(fd)
            raise Error(
                "socket.dns: read " + path + " " + errno_message(Int32(-n))
            )
        if n == 0:
            break
        out.extend(Span(buf)[0:n])
    _ = sys_close(fd)
    return out^


# --- tiny line/token parser ------------------------------------------


@always_inline
def _lower(b: UInt8) -> UInt8:
    if b >= UInt8(ord("A")) and b <= UInt8(ord("Z")):
        return b + 32
    return b


def _ci_equals(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if _lower(a[i]) != _lower(b[i]):
            return False
    return True


def _slice_to_str(text: Span[UInt8, _], start: Int, end: Int) -> String:
    var buf = List[UInt8](capacity=end - start)
    for i in range(start, end):
        buf.append(text[i])
    return String(unsafe_from_utf8=buf)


def _tokenize_line(line: Span[UInt8, _]) -> List[Int]:
    """Whitespace-separated tokens. Returns a flat list of
    [start0, end0, start1, end1, ...]. Stops at the first '#' comment
    marker; empty/comment-only lines yield an empty list."""
    var out = List[Int]()
    var end = len(line)
    for i in range(len(line)):
        if line[i] == UInt8(ord("#")):
            end = i
            break
    var i = 0
    while i < end:
        while i < end and (
            line[i] == UInt8(ord(" ")) or line[i] == UInt8(ord("\t"))
        ):
            i += 1
        if i >= end:
            break
        var start = i
        while i < end and not (
            line[i] == UInt8(ord(" ")) or line[i] == UInt8(ord("\t"))
        ):
            i += 1
        out.append(start)
        out.append(i)
    return out^


# --- /etc/hosts ------------------------------------------------------


def _lookup_hosts(host: String) -> List[SocketAddr]:
    """Walk /etc/hosts looking for `host`. Returns matching IPs (port 0)
    in file order; empty if the file is missing or no match. ASCII
    case-insensitive."""
    var out = List[SocketAddr]()
    var text: List[UInt8]
    try:
        text = _read_file_bytes(String("/etc/hosts"))
    except:
        return out^
    var host_bytes = host.as_bytes()
    var span = Span(text)
    var n = len(span)
    var line_start = 0
    for i in range(n):
        if span[i] != UInt8(ord("\n")):
            continue
        _hosts_match_line(span, line_start, i, host_bytes, out)
        line_start = i + 1
    if line_start < n:
        _hosts_match_line(span, line_start, n, host_bytes, out)
    return out^


def _hosts_match_line(
    span: Span[UInt8, _],
    line_start: Int,
    line_end: Int,
    host_bytes: Span[UInt8, _],
    mut out: List[SocketAddr],
):
    var line = span[line_start:line_end]
    var toks = _tokenize_line(line)
    if len(toks) < 4:  # need at least IP + one name
        return
    var ip_str = _slice_to_str(line, toks[0], toks[1])
    var ip: SocketAddr
    try:
        ip = parse_ip(ip_str)
    except:
        return
    var ti = 2
    while ti < len(toks):
        var name = line[toks[ti] : toks[ti + 1]]
        if _ci_equals(name, host_bytes):
            out.append(ip)
            return
        ti += 2


# --- /etc/resolv.conf ------------------------------------------------


def _read_nameservers() -> List[SocketAddr]:
    """Parse `nameserver <ip>` directives. Returns the configured
    nameservers (port 53). Empty list if the file is missing."""
    var out = List[SocketAddr]()
    var text: List[UInt8]
    try:
        text = _read_file_bytes(String("/etc/resolv.conf"))
    except:
        return out^
    var span = Span(text)
    var n = len(span)
    var line_start = 0
    for i in range(n):
        if span[i] != UInt8(ord("\n")):
            continue
        _resolv_collect_line(span, line_start, i, out)
        line_start = i + 1
    if line_start < n:
        _resolv_collect_line(span, line_start, n, out)
    return out^


def _resolv_collect_line(
    span: Span[UInt8, _],
    line_start: Int,
    line_end: Int,
    mut out: List[SocketAddr],
):
    var line = span[line_start:line_end]
    var toks = _tokenize_line(line)
    if len(toks) < 4:
        return
    var first = line[toks[0] : toks[1]]
    var keyword_str = String("nameserver")
    if not _ci_equals(first, keyword_str.as_bytes()):
        return
    var ip_str = _slice_to_str(line, toks[2], toks[3])
    try:
        var addr = parse_ip(ip_str)
        out.append(addr.with_port(53))
    except:
        pass


# --- DNS over io_uring -----------------------------------------------


def _random_txid() raises -> UInt16:
    # transaction ids must be unpredictable (spoofing resistance)
    var b = InlineArray[UInt8, 2](fill=0)
    var n = sys_getrandom(b.unsafe_ptr(), 2, 0)
    if n != 2:
        raise Error("socket.dns: getrandom failed")
    return (UInt16(b[0]) << 8) | UInt16(b[1])


def _connected_socket(server: SocketAddr, socktype: Int) raises -> Int32:
    """Open a fresh fd connected to `server`. The fd is OWNED by the
    caller (the Ring only owns its io_uring fd)."""
    var family = AF_INET6 if server.kind() == AddressFamily.V6 else AF_INET
    var rc = sys_socket(family, socktype | SOCK_CLOEXEC, 0)
    if rc < 0:
        raise Error("socket.dns: socket() " + errno_message(Int32(-rc)))
    var fd = Int32(rc)
    var sa = InlineArray[UInt8, SOCKADDR_STORAGE_SIZE](fill=0)
    var alen = write_sockaddr(sa.unsafe_ptr(), server)
    var crc: Int
    while True:
        crc = sys_connect(fd, sa.unsafe_ptr(), Int(alen))
        if crc != -4:  # not EINTR
            break
    if crc != 0:
        var msg = errno_message(Int32(-crc))
        _ = sys_close(fd)
        raise Error("socket.dns: connect() " + msg)
    return fd


def _await_recv(mut ring: Ring) raises -> Completion:
    """Drives a private ring until the recv completes; send acks and
    timeout partners are validated and dropped."""
    while True:
        _ = ring.wait(min_complete=1)
        while True:
            var c = ring.next_completion()
            if not c:
                break
            var done = c.take()
            if done.kind == CompletionKind.RECV:
                return done^
            if done.kind == CompletionKind.SEND:
                done.ok()
            # timeout partners and close acks: nothing to check


def _drain(mut ring: Ring) raises:
    while True:
        var c = ring.next_completion()
        if not c:
            break
        _ = c.take()


def _query_udp(
    server: SocketAddr, query: Span[UInt8, _], timeout_ms: Int
) raises -> List[UInt8]:
    var ring = Ring(16)
    var fd = _connected_socket(server, SOCK_DGRAM)
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
        _ = sys_close(fd)
        raise e^


def _query_tcp(
    server: SocketAddr, query: Span[UInt8, _], timeout_ms: Int
) raises -> List[UInt8]:
    var ring = Ring(16)
    var fd = _connected_socket(server, SOCK_STREAM)
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
        _ = sys_close(fd)
        raise e^


def _resolve_answer(
    host: String,
    *,
    server: SocketAddr,
    qtype: UInt16,
    timeout_ms: Int = 2000,
    retries: Int = 2,
) raises -> DnsAnswer:
    """Internal: query a single nameserver and return the parsed
    DnsAnswer (carrying rcode + addresses). Raises only on transport
    failure or malformed responses; rcode != 0 (NXDOMAIN, SERVFAIL,
    ...) is reflected in the returned answer."""
    for attempt in range(retries):
        var txid = _random_txid()
        var query = dns_build_query(txid, host, qtype)
        var raw: List[UInt8]
        try:
            raw = _query_udp(server, Span(query), timeout_ms)
        except:
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
        return ans^
    raise Error("socket.dns: unreachable")


def resolve_dns(
    host: String,
    *,
    server: SocketAddr,
    qtype: UInt16 = QTYPE_A,
    timeout_ms: Int = 2000,
    retries: Int = 2,
) raises -> List[SocketAddr]:
    """Query `server` directly for `host` of `qtype` (A or AAAA).
    UDP with per-attempt deadline and fresh transaction ids; TCP
    fallback on truncation. NXDOMAIN and other server errors raise.
    Addresses come back as `SocketAddr` (port 0)."""
    try:
        var literal = parse_ip(host)
        var out = List[SocketAddr]()
        out.append(literal)
        return out^
    except:
        pass
    var ans = _resolve_answer(
        host,
        server=server,
        qtype=qtype,
        timeout_ms=timeout_ms,
        retries=retries,
    )
    if ans.rcode != 0:
        raise Error(
            "socket.dns: server error rcode="
            + String(Int(ans.rcode))
            + " for '"
            + host
            + "'"
        )
    return ans.addresses.copy()


# --- public entry point ----------------------------------------------


def resolve(host: String) raises -> List[SocketAddr]:
    """Resolve `host` to a list of addresses (A records first, then
    AAAA), each a port-0 `SocketAddr`. The full lookup chain: literal-IP
    fast path → /etc/hosts override → DNS query against each `nameserver`
    in /etc/resolv.conf. No glibc resolver, no getaddrinfo, no nss."""
    try:
        var literal = parse_ip(host)
        var out = List[SocketAddr]()
        out.append(literal)
        return out^
    except:
        pass
    var hosts_match = _lookup_hosts(host)
    if len(hosts_match) > 0:
        return hosts_match^
    var nameservers = _read_nameservers()
    if len(nameservers) == 0:
        # No /etc/resolv.conf and no /etc/hosts hit — assume a local
        # resolver on loopback (systemd-resolved binds 127.0.0.53,
        # but the conventional fallback is 127.0.0.1:53).
        nameservers.append(SocketAddr.v4(Ipv4Address(127, 0, 0, 1), 53))
    var got_answer = False
    var rcode: UInt8 = 0
    var addrs = List[SocketAddr]()
    for ni in range(len(nameservers)):
        var ns = nameservers[ni]
        var ans_a: DnsAnswer
        try:
            ans_a = _resolve_answer(host, server=ns, qtype=QTYPE_A)
        except:
            continue  # transport failure: try next ns
        got_answer = True
        rcode = ans_a.rcode
        if rcode != 0:
            break  # the server has a definitive opinion — no retry
        for i in range(len(ans_a.addresses)):
            addrs.append(ans_a.addresses[i])
        # AAAA is optional; absence is normal.
        try:
            var ans_aaaa = _resolve_answer(host, server=ns, qtype=QTYPE_AAAA)
            if ans_aaaa.rcode == 0:
                for i in range(len(ans_aaaa.addresses)):
                    addrs.append(ans_aaaa.addresses[i])
        except:
            pass
        return addrs^
    if got_answer:
        raise Error(
            "socket.dns: server error rcode="
            + String(Int(rcode))
            + " for '"
            + host
            + "'"
        )
    raise Error("socket.dns: no nameservers reachable for '" + host + "'")
