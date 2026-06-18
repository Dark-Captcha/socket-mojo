#!/usr/bin/env python3
# Python asyncio echo server. Default selector loop (epoll on Linux).

import asyncio
import sys


async def handle(reader, writer):
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                return
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main():
    if len(sys.argv) < 3:
        print("usage: server.py <port> <conns>", file=sys.stderr)
        sys.exit(2)
    port = int(sys.argv[1])
    conns = int(sys.argv[2])

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    # Run for as long as the client keeps the connections open.
    # The client closes them when it finishes the timed loop.
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
