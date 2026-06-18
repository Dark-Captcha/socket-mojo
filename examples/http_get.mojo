# Real-world end-to-end example: fetch http://example.com/ over
# the actual Internet. Exercises every layer of socket-mojo end-to-
# end: DNS resolution (native /etc/hosts → /etc/resolv.conf → RFC
# 1035 over the Ring), TCP connect with a timeout, write + read.
# No loopback, no python truth peer — just a real public server.
#
# Run:
#   pixi run mojo run -I . examples/http_get.mojo
#
# Expected output: a few KiB of HTML, prefixed by the HTTP status
# line. If you're offline, you'll get a `socket.dns` or
# `socket.tcp` error — that's the library doing its job.

from socket.tcp import TcpSocket


def _first_line(buf: List[UInt8]) -> String:
    var out = List[UInt8]()
    for i in range(len(buf)):
        if buf[i] == UInt8(ord("\r")) or buf[i] == UInt8(ord("\n")):
            break
        out.append(buf[i])
    return String(unsafe_from_utf8=out)


def main() raises:
    var host = String("example.com")
    print("→ resolving", host, "...")
    print("→ connecting to", host, ":80 ...")
    var sock = TcpSocket.connect(host, 80, timeout_seconds=10.0)

    var req = (
        String("GET / HTTP/1.0\r\n")
        + "Host: example.com\r\n"
        + "User-Agent: socket-mojo/0.2.0\r\n"
        + "Connection: close\r\n"
        + "\r\n"
    )
    sock.write(req.as_bytes())

    # example.com fits in a few KiB. Read in chunks until EOF.
    var body = List[UInt8]()
    while True:
        var chunk = sock.read(4096)
        if len(chunk) == 0:
            break
        body.extend(Span(chunk))
        if len(body) >= 65536:
            break  # safety cap
    # Letting `sock` go out of scope here closes the fd via __del__.

    print("← got", len(body), "bytes")
    print("← status:", _first_line(body))
