# In-process epoll test using socketpair(2). Avoids Python helpers
# and the tuple-move ergonomics around accept() — proves the Poller +
# non-blocking + read/write path through a single thread.

from std.memory import UnsafePointer

from socket._syscalls import (
    AF_UNIX,
    MSG_DONTWAIT,
    SOCK_STREAM,
    sys_close,
    sys_recv,
    sys_send,
    sys_socketpair,
)
from socket.nonblocking import is_would_block, set_nonblocking
from socket.poller import Poller
from tests.helpers import check


def run() raises:
    # Create a connected pair (a/b are two ends of one channel).
    var pair = InlineArray[Int32, 2](fill=-1)
    var rv = sys_socketpair(
        AF_UNIX, SOCK_STREAM, 0, pair.unsafe_ptr().bitcast[UInt8]()
    )
    check(rv == 0, "socketpair created")
    var a = pair[0]
    var b = pair[1]

    # Make `b` non-blocking and register it for readable events.
    set_nonblocking(b, True)
    var poller = Poller.open()
    poller.register(b, readable=True)

    # Initially nothing has been written; poll(0) should return
    # nothing.
    var events0 = poller.wait(max_events=4, timeout_ms=0)
    check(len(events0) == 0, "no events when no data available")

    # Write through `a`. send() defaults to blocking.
    var msg = "epoll!".as_bytes()
    var nsent = sys_send(a, msg.unsafe_ptr(), len(msg), 0)
    check(nsent == 6, "send 6 bytes through socketpair[0]")

    # Now wait — should report `b` is readable within ~100 ms.
    var events1 = poller.wait(max_events=4, timeout_ms=500)
    check(len(events1) == 1, "exactly one event ready")
    var e = events1[0]
    check(e.fd == b, "the right fd fired")
    check(e.is_readable(), "fd is readable")

    # Non-blocking recv: should return 6 bytes immediately, then EAGAIN.
    var rbuf = List[UInt8](length=128, fill=0)
    var got = sys_recv(b, rbuf.unsafe_ptr(), 128, 0)
    check(got == 6, "recv returned 6")
    var as_string = String("")
    for i in range(6):
        as_string += chr(Int(rbuf[i]))
    check(as_string == "epoll!", "recv contents")
    var again = sys_recv(b, rbuf.unsafe_ptr(), 128, MSG_DONTWAIT)
    check(again == -11, "second recv would block (EAGAIN)")

    # modify: switch the registration to writable only, then verify
    # epoll reports it as writable immediately (the socket has room).
    poller.modify(b, readable=False, writable=True)
    var events2 = poller.wait(max_events=4, timeout_ms=200)
    check(len(events2) == 1, "writable event fires")
    check(events2[0].is_writable(), "fd is writable")

    poller.unregister(b)
    _ = sys_close(a)
    _ = sys_close(b)
    print("test_poller: OK")


def main() raises:
    run()
