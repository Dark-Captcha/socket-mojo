#!/usr/bin/env python3
"""Companion client for tests/test_poller.mojo. Connects to the
loopback listener at 127.0.0.1:29701, sends "hello reactor", reads
the same back, exits.
"""

import socket
import sys
import time


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 29701
    # The Mojo side calls listener.bind synchronously then starts the
    # reactor; we wait a moment to make sure it's listening.
    for _ in range(50):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.05)
    else:
        print("FAIL: could not connect", file=sys.stderr)
        return 1
    with s:
        s.sendall(b"hello reactor")
        s.settimeout(5)
        buf = b""
        while len(buf) < 13:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        if buf == b"hello reactor":
            print("ok", flush=True)
            return 0
        print(f"FAIL: got {buf!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
