# Baseline performance probe for v0.1. Measures:
# - Time to do 1000 connect/close cycles to a localhost listener
# - Time to push 1 MiB through an established TCP echo socket
# - Time to push 100 MiB
from std.time import perf_counter_ns
from socket.tcp import TcpSocket, TcpListener
from socket.addr import IpAddress, SocketAddr

def main() raises:
    var port = UInt16(29501)
    var listener = TcpListener.bind(SocketAddr(IpAddress.loopback_v4(), port))
    # In-process echo: accept ONE connection, drain everything it sends,
    # respond with the same byte count, then close. We pre-spawn the
    # bench-side BEFORE running the timed loop.
    print("listener ready on port", port)

    # We'll do an in-process echo via threads...  but Mojo doesn't have
    # easy threading yet. Instead, run the python echo helper from a
    # shell wrapper outside this probe.

