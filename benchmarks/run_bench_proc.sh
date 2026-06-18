#!/usr/bin/env bash
# Two-process loopback benchmark driver. Spawns the Ring-based echo
# server in the background, then runs the client which times itself
# and prints rt/s. The kernel TCP stack mediates between the two
# processes — closer to NIC-style overhead than the in-process
# bench_ring.mojo's same-process loopback.

set -euo pipefail

cd "$(dirname "$0")/.."

PORT=${PORT:-19888}
CONNS=${CONNS:-64}
ROUNDS=${ROUNDS:-2000}

# Server in background.
pixi run mojo run -I . benchmarks/bench_proc.mojo server "$PORT" "$CONNS" &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true" EXIT

# Wait a moment for the server to bind.
sleep 1

# Client foreground — prints rate when done.
pixi run mojo run -I . benchmarks/bench_proc.mojo client "$PORT" "$CONNS" "$ROUNDS"

# Server should exit on its own once all conns close; give it a moment.
wait "$SERVER_PID" 2>/dev/null || true
