# epoll(7) reactor. Tier-2 of the socket-mojo concurrency plan: one
# thread, many non-blocking sockets, single epoll_wait syscall per
# event burst.
#
# Usage shape:
#   var poller = Poller.open()
#   poller.register(sock.fd, readable=True, writable=False)
#   loop:
#     for event in poller.wait(timeout_ms=100):
#       if event.is_readable: ... sock.read() ...
#       if event.is_writable: ... sock.write() ...
#       if event.is_error:    ... drop ...
#
# Edge-triggered (`edge=True`) gives one notification per state
# change, which is faster but requires draining each fd to EAGAIN
# before resuming the loop. Level-triggered (the default) wakes you
# again on the next iteration if data is still pending.

from std.memory import UnsafePointer

from socket._libc import (
    EPOLLERR,
    EPOLLET,
    EPOLLHUP,
    EPOLLIN,
    EPOLLONESHOT,
    EPOLLOUT,
    EPOLLRDHUP,
    EPOLL_CTL_ADD,
    EPOLL_CTL_DEL,
    EPOLL_CTL_MOD,
    EPOLL_EVENT_SIZE,
    close,
    epoll_create1,
    epoll_ctl,
    epoll_wait,
    errno,
    errno_message,
)


struct PollEvent(Copyable, ImplicitlyCopyable, Movable):
    """One ready socket reported by Poller.wait()."""

    var fd: Int32
    var raw_events: UInt32

    def __init__(out self, fd: Int32, raw_events: UInt32):
        self.fd = fd
        self.raw_events = raw_events

    def is_readable(self) -> Bool:
        return (self.raw_events & UInt32(EPOLLIN)) != 0

    def is_writable(self) -> Bool:
        return (self.raw_events & UInt32(EPOLLOUT)) != 0

    def is_error(self) -> Bool:
        return (self.raw_events & UInt32(EPOLLERR)) != 0

    def is_hangup(self) -> Bool:
        return (self.raw_events & UInt32(EPOLLHUP)) != 0

    def peer_closed_write(self) -> Bool:
        """RDHUP — peer half-close. Useful to drain remaining bytes
        before tearing the connection down."""
        return (self.raw_events & UInt32(EPOLLRDHUP)) != 0


def _write_event(
    out_ptr: UnsafePointer[UInt8, MutAnyOrigin],
    events: UInt32,
    fd: Int32,
):
    """Serialize a `struct epoll_event` (packed on x86-64): u32 events
    at offset 0, then the data union (u64) at offset 4. We stash the
    fd in the low 32 bits of data so the wait loop can recover it."""
    for k in range(EPOLL_EVENT_SIZE):
        out_ptr[k] = 0
    out_ptr[0] = UInt8(events & 0xFF)
    out_ptr[1] = UInt8((events >> 8) & 0xFF)
    out_ptr[2] = UInt8((events >> 16) & 0xFF)
    out_ptr[3] = UInt8((events >> 24) & 0xFF)
    var ufd = UInt32(fd)
    out_ptr[4] = UInt8(ufd & 0xFF)
    out_ptr[5] = UInt8((ufd >> 8) & 0xFF)
    out_ptr[6] = UInt8((ufd >> 16) & 0xFF)
    out_ptr[7] = UInt8((ufd >> 24) & 0xFF)


def _read_event(buf: UnsafePointer[UInt8, _], offset: Int) -> PollEvent:
    var ev = (
        UInt32(buf[offset])
        | (UInt32(buf[offset + 1]) << 8)
        | (UInt32(buf[offset + 2]) << 16)
        | (UInt32(buf[offset + 3]) << 24)
    )
    var ufd = (
        UInt32(buf[offset + 4])
        | (UInt32(buf[offset + 5]) << 8)
        | (UInt32(buf[offset + 6]) << 16)
        | (UInt32(buf[offset + 7]) << 24)
    )
    return PollEvent(Int32(ufd), ev)


struct Poller(Movable):
    """Owned epoll instance."""

    var epfd: Int32

    def __init__(out self, epfd: Int32):
        self.epfd = epfd

    def __del__(deinit self):
        if self.epfd >= 0:
            _ = close(self.epfd)

    @staticmethod
    def open() raises -> Poller:
        var fd = epoll_create1(Int32(0))
        if fd < 0:
            raise Error(
                "socket.poller: epoll_create1 " + errno_message(errno())
            )
        return Poller(fd)

    def _ctl(
        mut self,
        op: Int32,
        fd: Int32,
        *,
        readable: Bool,
        writable: Bool,
        edge: Bool,
        oneshot: Bool,
        rdhup: Bool,
    ) raises:
        var events = UInt32(0)
        if readable:
            events |= UInt32(EPOLLIN)
        if writable:
            events |= UInt32(EPOLLOUT)
        if rdhup:
            events |= UInt32(EPOLLRDHUP)
        if edge:
            events |= UInt32(EPOLLET)
        if oneshot:
            events |= UInt32(EPOLLONESHOT)
        var ev = InlineArray[UInt8, EPOLL_EVENT_SIZE](fill=0)
        _write_event(ev.unsafe_ptr(), events, fd)
        var rv = epoll_ctl(self.epfd, op, fd, ev.unsafe_ptr())
        if rv != 0:
            raise Error("socket.poller: epoll_ctl " + errno_message(errno()))

    def register(
        mut self,
        fd: Int32,
        *,
        readable: Bool = True,
        writable: Bool = False,
        edge: Bool = False,
        oneshot: Bool = False,
        rdhup: Bool = True,
    ) raises:
        """Start watching `fd`. RDHUP is on by default so callers learn
        about peer half-closes promptly."""
        self._ctl(
            Int32(EPOLL_CTL_ADD),
            fd,
            readable=readable,
            writable=writable,
            edge=edge,
            oneshot=oneshot,
            rdhup=rdhup,
        )

    def modify(
        mut self,
        fd: Int32,
        *,
        readable: Bool,
        writable: Bool,
        edge: Bool = False,
        oneshot: Bool = False,
        rdhup: Bool = True,
    ) raises:
        """Change the event mask on an already-registered fd. Useful
        for a TLS handshake that needs `writable` during the SYN and
        `readable` once established."""
        self._ctl(
            Int32(EPOLL_CTL_MOD),
            fd,
            readable=readable,
            writable=writable,
            edge=edge,
            oneshot=oneshot,
            rdhup=rdhup,
        )

    def unregister(mut self, fd: Int32) raises:
        # epoll_ctl(EPOLL_CTL_DEL) ignores the event argument; pass a
        # zeroed buffer.
        var ev = InlineArray[UInt8, EPOLL_EVENT_SIZE](fill=0)
        var rv = epoll_ctl(self.epfd, Int32(EPOLL_CTL_DEL), fd, ev.unsafe_ptr())
        if rv != 0:
            raise Error(
                "socket.poller: epoll_ctl(DEL) " + errno_message(errno())
            )

    def wait(
        mut self, *, max_events: Int = 64, timeout_ms: Int = -1
    ) raises -> List[PollEvent]:
        """Block until at least one fd is ready (or `timeout_ms`
        elapses). Returns an empty list on timeout. `timeout_ms = -1`
        means wait indefinitely. `timeout_ms = 0` is a non-blocking
        poll."""
        var buf = List[UInt8](length=EPOLL_EVENT_SIZE * max_events, fill=0)
        var n = epoll_wait(
            self.epfd, buf.unsafe_ptr(), Int32(max_events), Int32(timeout_ms)
        )
        if n < 0:
            var e = errno()
            if e == 4:  # EINTR — treat as a timeout-with-no-events
                return List[PollEvent]()
            raise Error("socket.poller: epoll_wait " + errno_message(e))
        var n_int = Int(n)
        var out = List[PollEvent](capacity=n_int)
        for i in range(n_int):
            out.append(_read_event(buf.unsafe_ptr(), i * EPOLL_EVENT_SIZE))
        return out^
