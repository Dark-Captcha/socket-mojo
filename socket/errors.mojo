# Typed-error helpers. socket-mojo raises `Error("socket.<module>:
# <op> <TAG>")` where TAG is a named errno (`ECONNREFUSED`,
# `ETIMEDOUT`, ...) or the literal `errno=N` fallback for codes
# without a named tag. This module gives callers a clean API for
# branching on the kind without writing brittle string searches.
#
# The string format is the public contract. The named-tag set is
# fixed; new errnos that show up are formatted as `errno=N` so a
# new code never gets a tag a downstream parser doesn't recognise.
#
# Usage:
#
#   try:
#       var sock = TcpSocket.connect("example.com", 80)
#   except e:
#       if is_connection_refused(e):
#           # peer not listening — try the next address
#           continue
#       if is_timed_out(e):
#           # honour the user's deadline
#           ...
#       raise e^

from socket._syscalls import (
    SO_RCVTIMEO,
    SO_SNDTIMEO,
    errno_message,
)


# --- error-kind constants (Linux errno values) ----------------------

comptime EPERM = 1
comptime ENOENT = 2
comptime EINTR = 4
comptime EBADF = 9
comptime EAGAIN = 11
comptime EWOULDBLOCK = 11  # same value as EAGAIN on Linux
comptime EACCES = 13
comptime EINVAL = 22
comptime EMFILE = 24
comptime EPIPE = 32
comptime EADDRINUSE = 98
comptime EADDRNOTAVAIL = 99
comptime ENETDOWN = 100
comptime ENETUNREACH = 101
comptime ECONNABORTED = 103
comptime ECONNRESET = 104
comptime ENOBUFS = 105
comptime ENOTCONN = 107
comptime ETIMEDOUT = 110
comptime ECONNREFUSED = 111
comptime EHOSTDOWN = 112
comptime EHOSTUNREACH = 113
comptime EINPROGRESS = 115
comptime ECANCELED = 125


# --- predicates -----------------------------------------------------

def _has_tag(e: Error, tag: String) -> Bool:
    return String(e).find(tag) >= 0


def is_connection_refused(e: Error) -> Bool:
    """Peer host/process exists but isn't listening on the port."""
    return _has_tag(e, "ECONNREFUSED")


def is_connection_reset(e: Error) -> Bool:
    """Peer closed the socket with RST (abrupt close)."""
    return _has_tag(e, "ECONNRESET")


def is_connection_aborted(e: Error) -> Bool:
    """Local stack aborted the connection (typically after a long
    timeout or kernel resource pressure)."""
    return _has_tag(e, "ECONNABORTED")


def is_broken_pipe(e: Error) -> Bool:
    """Wrote to a socket whose peer has closed. With MSG_NOSIGNAL
    (the default in socket-mojo), this is what surfaces instead of
    a SIGPIPE."""
    return _has_tag(e, "EPIPE")


def is_timed_out(e: Error) -> Bool:
    """Socket-level timeout fired (SO_RCVTIMEO / SO_SNDTIMEO, or
    the kernel's TCP keepalive judging the peer dead)."""
    return _has_tag(e, "ETIMEDOUT")


def is_would_block(e: Error) -> Bool:
    """Non-blocking socket would have blocked; retry later. Same
    code as EWOULDBLOCK on Linux."""
    return _has_tag(e, "EAGAIN") or _has_tag(e, "EWOULDBLOCK")


def is_in_progress(e: Error) -> Bool:
    """connect(2) returned EINPROGRESS on a non-blocking socket.
    Wait for the fd to become writable, then check SO_ERROR for the
    final outcome."""
    return _has_tag(e, "EINPROGRESS")


def is_canceled(e: Error) -> Bool:
    """An io_uring linked timeout fired, or the user explicitly
    cancelled the op."""
    return _has_tag(e, "ECANCELED")


def is_host_unreachable(e: Error) -> Bool:
    return _has_tag(e, "EHOSTUNREACH") or _has_tag(e, "ENETUNREACH")


def is_address_in_use(e: Error) -> Bool:
    """Trying to bind a port that's already in use without
    SO_REUSEADDR (or SO_REUSEPORT) set."""
    return _has_tag(e, "EADDRINUSE")


def is_bad_fd(e: Error) -> Bool:
    return _has_tag(e, "EBADF")


def is_dns_error(e: Error) -> Bool:
    """A `socket.dns:` failure (NXDOMAIN, transport, parser)."""
    return String(e).find("socket.dns:") >= 0


# --- general extraction ---------------------------------------------

def errno_of(e: Error) -> Int32:
    """Best-effort errno extraction. Returns the matching numeric
    code for a named tag (`ECONNREFUSED` → 111), or parses the
    `errno=N` fallback. Returns 0 if neither pattern is present —
    e.g. for DNS errors, transport-layer-only failures, or any
    error not tagged with a POSIX kind."""
    var msg = String(e)
    # Try the named tags first.
    if msg.find("ECONNREFUSED") >= 0:
        return Int32(ECONNREFUSED)
    if msg.find("ECONNRESET") >= 0:
        return Int32(ECONNRESET)
    if msg.find("ECONNABORTED") >= 0:
        return Int32(ECONNABORTED)
    if msg.find("EPIPE") >= 0:
        return Int32(EPIPE)
    if msg.find("ETIMEDOUT") >= 0:
        return Int32(ETIMEDOUT)
    if msg.find("EAGAIN") >= 0:
        return Int32(EAGAIN)
    if msg.find("EWOULDBLOCK") >= 0:
        return Int32(EWOULDBLOCK)
    if msg.find("EINPROGRESS") >= 0:
        return Int32(EINPROGRESS)
    if msg.find("ECANCELED") >= 0:
        return Int32(ECANCELED)
    if msg.find("EHOSTUNREACH") >= 0:
        return Int32(EHOSTUNREACH)
    if msg.find("EHOSTDOWN") >= 0:
        return Int32(EHOSTDOWN)
    if msg.find("ENETUNREACH") >= 0:
        return Int32(ENETUNREACH)
    if msg.find("ENETDOWN") >= 0:
        return Int32(ENETDOWN)
    if msg.find("EADDRINUSE") >= 0:
        return Int32(EADDRINUSE)
    if msg.find("EADDRNOTAVAIL") >= 0:
        return Int32(EADDRNOTAVAIL)
    if msg.find("EBADF") >= 0:
        return Int32(EBADF)
    if msg.find("EACCES") >= 0:
        return Int32(EACCES)
    if msg.find("EMFILE") >= 0:
        return Int32(EMFILE)
    if msg.find("EINVAL") >= 0:
        return Int32(EINVAL)
    if msg.find("ENOBUFS") >= 0:
        return Int32(ENOBUFS)
    if msg.find("ENOTCONN") >= 0:
        return Int32(ENOTCONN)
    if msg.find("EINTR") >= 0:
        return Int32(EINTR)
    if msg.find("ENOENT") >= 0:
        return Int32(ENOENT)
    if msg.find("EPERM") >= 0:
        return Int32(EPERM)
    # Fallback: parse `errno=N` for codes without a named tag.
    var marker = String("errno=")
    var pos = msg.find(marker)
    if pos < 0:
        return Int32(0)
    var rest = String(msg[byte = pos + marker.byte_length() : msg.byte_length()])
    var rest_bytes = rest.as_bytes()
    var end = 0
    while end < len(rest_bytes):
        var c = rest_bytes[end]
        if c < UInt8(ord("0")) or c > UInt8(ord("9")):
            break
        end += 1
    if end == 0:
        return Int32(0)
    # Hand-parse the digit run so the function stays non-raising
    # (Int(String) can raise on overflow / garbage).
    var value = 0
    for i in range(end):
        value = value * 10 + Int(rest_bytes[i] - UInt8(ord("0")))
    return Int32(value)
