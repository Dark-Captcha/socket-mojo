#!/usr/bin/env bash
# Cross-language echo-ping-pong benchmark. Runs the same workload
# (CONNS × ROUNDS × PAYLOAD) against same-language server+client
# pairs for socket-mojo, Go (net stdlib), Python (asyncio), and C
# (liburing). Single machine, real two-process kernel TCP.
#
# Defaults: 64 conns × 1500 rounds × 64 B (matches PERF.md's
# in-process and two-process figures).

set -euo pipefail
cd "$(dirname "$0")"

CONNS=${CONNS:-64}
ROUNDS=${ROUNDS:-1500}
PAYLOAD=${PAYLOAD:-64}
BASE_PORT=${BASE_PORT:-29000}

run_pair() {
    local lang=$1 server=$2 client=$3
    local port=$((BASE_PORT + RANDOM % 500))
    eval "$server" "$port" "$CONNS" >/dev/null 2>&1 &
    local srv=$!
    sleep 0.5
    eval "$client" "$port" "$CONNS" "$ROUNDS" "$PAYLOAD"
    # Server exits once all conns close — give it a beat then reap.
    sleep 0.2
    kill "$srv" 2>/dev/null || true
    wait "$srv" 2>/dev/null || true
}

cd "$(dirname "$0")/../.."  # repo root

echo "=== cross-lang echo bench: $CONNS conns × $ROUNDS rounds × $PAYLOAD B ==="

# socket-mojo via the existing two-process bench (defer_taskrun).
{
    pixi run mojo run -I . benchmarks/bench_proc.mojo \
        server $((BASE_PORT + 1)) "$CONNS" >/dev/null 2>&1 &
    srv=$!; sleep 1
    pixi run mojo run -I . benchmarks/bench_proc.mojo \
        client $((BASE_PORT + 1)) "$CONNS" "$ROUNDS" "$PAYLOAD" 2>&1 |
        grep '^two-proc' | sed 's/^/socket-mojo  /'
    sleep 0.2; kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
}

# socket-mojo + SQPOLL.
{
    pixi run mojo run -I . benchmarks/bench_proc.mojo \
        server $((BASE_PORT + 2)) "$CONNS" sqpoll >/dev/null 2>&1 &
    srv=$!; sleep 1
    pixi run mojo run -I . benchmarks/bench_proc.mojo \
        client $((BASE_PORT + 2)) "$CONNS" "$ROUNDS" "$PAYLOAD" sqpoll 2>&1 |
        grep '^two-proc' | sed 's/^/socket-mojo  /'
    sleep 0.2; kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
}

cd benchmarks/cross_lang

# Build/run Go. First single-thread (fair vs socket-mojo's single
# Ring), then all-cores (Go's natural deployment) for context.
(cd go && go build -o /tmp/_socketmojo_go_server server.go && \
        go build -o /tmp/_socketmojo_go_client client.go)
GOMAXPROCS=1 run_pair "go-1cpu" /tmp/_socketmojo_go_server /tmp/_socketmojo_go_client
GOMAXPROCS="$(nproc)" run_pair "go-all" /tmp/_socketmojo_go_server /tmp/_socketmojo_go_client

# Python.
run_pair py "python3 py/server.py" "python3 py/client.py"

# Build/run C (liburing).
(cd c && cc -O2 -o /tmp/_socketmojo_c_server server.c -luring && \
        cc -O2 -o /tmp/_socketmojo_c_client client.c -luring)
run_pair c /tmp/_socketmojo_c_server /tmp/_socketmojo_c_client
