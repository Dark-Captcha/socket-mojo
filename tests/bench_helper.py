#!/usr/bin/env python3
"""High-throughput echo server for benchmarks. Keeps the connection
open and echoes until the client closes; tuned with TCP_NODELAY and
larger buffers so the throughput we measure reflects the Mojo client,
not Python's socket layer.
"""

import socket
import sys


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 29501
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    srv.settimeout(30)
    print(f"bench echo on 127.0.0.1:{port}", flush=True)
    n_conns = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    try:
        for _ in range(n_conns):
            conn, _peer = srv.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with conn:
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    conn.sendall(chunk)
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
