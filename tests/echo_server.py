#!/usr/bin/env python3
"""Tiny TCP echo server used by tests/test_tcp.mojo.

Listens on 127.0.0.1:PORT (default 19501) and echoes everything back
to every connecting client until killed. Threaded so multiple test
runs (or a slow Mojo build) don't trip a single-connection limit.
The previous incarnation served exactly one connection and timed out
after 10s — both behaviours broke if Mojo's compile took longer.
Idempotent: SO_REUSEADDR lets us re-bind immediately.
"""

import socket
import sys
import threading


def _handle(conn: socket.socket) -> None:
    with conn:
        while True:
            try:
                chunk = conn.recv(4096)
            except Exception:
                return
            if not chunk:
                return
            try:
                conn.sendall(chunk)
            except Exception:
                return


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19501
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    print(f"echo server listening on 127.0.0.1:{port}", flush=True)
    try:
        while True:
            conn, _peer = srv.accept()
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
