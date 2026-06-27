# socket/errors.mojo predicate + errno extraction tests. Drives
# real failures through the public API and checks that the typed
# helpers classify them correctly.

from socket.errors import (
    ECONNREFUSED,
    EHOSTUNREACH,
    ENETUNREACH,
    errno_of,
    is_bad_fd,
    is_broken_pipe,
    is_connection_refused,
    is_dns_error,
    is_host_unreachable,
    is_timed_out,
)
from socket.tcp import TcpSocket
from tests.helpers import check


def _expect_error(msg: String) raises -> Error:
    """Force-construct an Error with the given message — used to
    test the predicates without having to provoke every failure."""
    return Error(msg)


def _test_predicates_via_message() raises -> Int:
    var f = 0
    var e1 = _expect_error(
        String("socket.tcp: connect() ECONNREFUSED (127.0.0.1:1)")
    )
    f += check(is_connection_refused(e1), "predicate: ECONNREFUSED")
    f += check(not is_timed_out(e1), "predicate: rejects unrelated tag")
    f += check(
        errno_of(e1) == Int32(ECONNREFUSED),
        "errno_of: ECONNREFUSED → 111",
    )

    var e2 = _expect_error(String("socket.tcp: send() EPIPE"))
    f += check(is_broken_pipe(e2), "predicate: EPIPE")

    var e3 = _expect_error(String("socket.tcp: recv() ETIMEDOUT"))
    f += check(is_timed_out(e3), "predicate: ETIMEDOUT")

    var e4 = _expect_error(String("socket.udp: connect() EHOSTUNREACH"))
    f += check(is_host_unreachable(e4), "predicate: EHOSTUNREACH")

    var e5 = _expect_error(
        String("socket.dns: server error rcode=3 for 'nx.test'")
    )
    f += check(is_dns_error(e5), "predicate: DNS error")
    f += check(
        errno_of(e5) == Int32(0), "errno_of: DNS error has no posix code"
    )

    var e6 = _expect_error(String("socket.tcp: send() EBADF"))
    f += check(is_bad_fd(e6), "predicate: EBADF")

    # Fallback path: `errno=N` for unnamed codes.
    var e7 = _expect_error(String("socket.foo: bar errno=84"))
    f += check(errno_of(e7) == Int32(84), "errno_of: parses errno=N fallback")
    return f


def _test_predicates_against_real_failure() raises -> Int:
    var f = 0
    # Connect to a port nothing is listening on; expect ECONNREFUSED.
    var caught = False
    try:
        var _sock = TcpSocket.connect("127.0.0.1", 1, timeout_seconds=1.0)
    except e:
        caught = True
        f += check(
            is_connection_refused(e),
            "live ECONNREFUSED detected via predicate",
        )
        f += check(
            errno_of(e) == Int32(ECONNREFUSED),
            "live ECONNREFUSED → 111",
        )
    f += check(caught, "connecting to 127.0.0.1:1 must fail")
    return f


def run() raises -> Int:
    var f = 0
    f += _test_predicates_via_message()
    f += _test_predicates_against_real_failure()
    if f == 0:
        print("test_errors: OK")
    return f


def main() raises:
    var fails = run()
    if fails > 0:
        raise Error("test_errors: " + String(fails) + " failures")
