#!/usr/bin/env python3
"""Tiny TCP echo server used by tests/test_tcp.mojo.

Listens on 127.0.0.1:PORT (default 19501), accepts ONE connection,
echoes back whatever it receives, then exits. Idempotent: the
SO_REUSEADDR flag lets us re-bind immediately after a previous run.
"""

import socket
import sys


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19501
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(10)
    print(f"echo server listening on 127.0.0.1:{port}", flush=True)
    try:
        conn, _peer = srv.accept()
        with conn:
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                # Echo immediately so we don't deadlock if the client
                # waits for a reply before closing its write side.
                conn.sendall(chunk)
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
