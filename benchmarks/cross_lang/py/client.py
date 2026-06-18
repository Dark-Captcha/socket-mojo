#!/usr/bin/env python3
# Python asyncio echo client. N coroutines, each doing `rounds`
# ping-pong cycles. Default selector event loop.

import asyncio
import sys
import time


async def conn_worker(reader, writer, msg, rounds):
    for _ in range(rounds):
        writer.write(msg)
        await writer.drain()
        # Read exactly len(msg) bytes (the echo).
        got = 0
        n = len(msg)
        while got < n:
            chunk = await reader.read(n - got)
            if not chunk:
                return
            got += len(chunk)


async def main():
    if len(sys.argv) < 5:
        print("usage: client.py <port> <conns> <rounds> <payload>", file=sys.stderr)
        sys.exit(2)
    port = int(sys.argv[1])
    conns = int(sys.argv[2])
    rounds = int(sys.argv[3])
    payload = int(sys.argv[4])
    msg = b"\x42" * payload

    # Open all connections first.
    pairs = []
    for _ in range(conns):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        pairs.append((r, w))

    t0 = time.perf_counter()
    await asyncio.gather(
        *(conn_worker(r, w, msg, rounds) for r, w in pairs)
    )
    elapsed = time.perf_counter() - t0

    rate = (rounds * conns) / elapsed
    print(f"py: {conns} conns x {rounds} rounds @ {payload} B → {int(rate)} rt/s")

    for _, w in pairs:
        w.close()
    for _, w in pairs:
        try:
            await w.wait_closed()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
