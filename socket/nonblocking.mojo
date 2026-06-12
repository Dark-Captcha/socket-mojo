# Non-blocking helpers for TcpSocket / UdpSocket. The byte-stream
# methods (read/write/recv_from/send_to) remain the same, but on a
# non-blocking socket they raise `EAGAIN` (or `EINPROGRESS` for
# connect) instead of waiting indefinitely. Callers register the fd
# with a Poller (see socket/poller.mojo) and only re-attempt the
# I/O when epoll reports the fd ready.
#
# This lets one Mojo thread service thousands of concurrent
# connections (the tier-2 concurrency story in socket-mojo's plan).

from socket._libc import (
    F_GETFL,
    F_SETFL,
    O_NONBLOCK,
    errno,
    errno_message,
    fcntl_get_flags,
    fcntl_set_flags,
)


def set_nonblocking(fd: Int32, enabled: Bool = True) raises:
    """Toggle O_NONBLOCK on the file descriptor. After this, read/
    write/recv_from raise EAGAIN when no progress is possible."""
    var flags = fcntl_get_flags(fd)
    if flags == -1:
        raise Error(
            "socket.nonblocking: fcntl(F_GETFL) " + errno_message(errno())
        )
    var new_flags = (flags | Int32(O_NONBLOCK)) if enabled else (
        flags & ~Int32(O_NONBLOCK)
    )
    if new_flags == flags:
        return
    var rv = fcntl_set_flags(fd, new_flags)
    if rv != 0:
        raise Error(
            "socket.nonblocking: fcntl(F_SETFL) " + errno_message(errno())
        )


def is_would_block(message: String) -> Bool:
    """True if a raised `Error` carries the EAGAIN / EWOULDBLOCK
    marker that socket-mojo emits on non-blocking I/O retries."""
    if message.find("EAGAIN") >= 0:
        return True
    if message.find("EWOULDBLOCK") >= 0:
        return True
    return False


def is_in_progress(message: String) -> Bool:
    """True if a raised `Error` carries EINPROGRESS — the connect()
    return that means "TCP SYN sent, waiting for SYN-ACK". A caller
    should register the fd for writable readiness and then check
    SO_ERROR for the final status."""
    return message.find("EINPROGRESS") >= 0
