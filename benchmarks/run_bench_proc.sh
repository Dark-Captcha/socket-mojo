#!/usr/bin/env bash
# Two-process loopback benchmark driver. Spawns the Ring-based echo
# server, then runs the client. The kernel TCP stack mediates
# between the two processes — closer to NIC-style overhead than the
# in-process bench_ring.mojo's same-process loopback.
#
# Without arguments: runs a small matrix (3 conn counts × 2 payload
# sizes × {ring, ring+sqpoll}). With CONNS / ROUNDS / PAYLOAD env
# vars: runs a single scenario.

set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-19888}

run_one() {
    local conns=$1 rounds=$2 payload=$3 mode=$4
    local port=$((PORT + RANDOM % 100))
    pixi run mojo run -I . benchmarks/bench_proc.mojo \
        server "$port" "$conns" "$mode" >/dev/null 2>&1 &
    local srv=$!
    sleep 1
    pixi run mojo run -I . benchmarks/bench_proc.mojo \
        client "$port" "$conns" "$rounds" "$payload" "$mode" 2>&1 |
        grep -E '^two-proc'
    wait "$srv" 2>/dev/null || true
}

if [[ "${CONNS:-}" != "" || "${ROUNDS:-}" != "" || "${PAYLOAD:-}" != "" ]]; then
    run_one "${CONNS:-64}" "${ROUNDS:-2000}" "${PAYLOAD:-64}" ""
    exit 0
fi

echo "=== two-process loopback echo (single machine, real kernel TCP) ==="
for payload in 64 4096; do
    for conns in 16 64 256; do
        run_one "$conns" 1500 "$payload" ""
        run_one "$conns" 1500 "$payload" "sqpoll"
    done
done
