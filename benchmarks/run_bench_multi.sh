#!/usr/bin/env bash
# Multi-process scaling benchmark: spawn N independent socket-mojo
# (server, client) pairs and report aggregate throughput. This is
# the production-shaped use case for socket-mojo on a multi-core
# box — each process owns its own Ring (no contention between
# workers), the kernel TCP stack mediates the data.
#
# Two modes:
#   * "independent" (default): each pair has its own port. The
#     fastest path; pairs don't share any kernel state beyond the
#     CPU. Best demonstration of scaling.
#   * "reuseport": all servers bind the same port with SO_REUSEPORT;
#     clients dial that one port and the kernel routes them.
#     Closer to a real frontend deployment but adds kernel
#     load-balancing overhead.
#
# Usage:
#   ./benchmarks/run_bench_multi.sh                       # 8 pairs, default
#   N=24 MODE=independent ./benchmarks/run_bench_multi.sh
#   N=24 MODE=reuseport   ./benchmarks/run_bench_multi.sh
#   N=8 EXTRA=sqpoll      ./benchmarks/run_bench_multi.sh

set -euo pipefail
cd "$(dirname "$0")/.."

N=${N:-8}
CONNS=${CONNS:-32}
ROUNDS=${ROUNDS:-1000}
PAYLOAD=${PAYLOAD:-64}
EXTRA=${EXTRA:-}            # "sqpoll" to engage SQPOLL on every worker
MODE=${MODE:-independent}   # "independent" | "reuseport"
BASE_PORT=${BASE_PORT:-45000}

OUT=$(mktemp)
trap 'rm -f $OUT; jobs -p | xargs -r kill 2>/dev/null' EXIT

if [[ "$MODE" == "reuseport" ]]; then
    PORT=$((BASE_PORT + 1))
    # Start N servers on the SAME port; SO_REUSEPORT lets the
    # kernel hash incoming connections across them.
    for i in $(seq 1 "$N"); do
        pixi run mojo run -I . benchmarks/bench_proc.mojo \
            server "$PORT" "$CONNS" $EXTRA reuseport >/dev/null 2>&1 &
    done
    sleep 1.5
    for i in $(seq 1 "$N"); do
        ( pixi run mojo run -I . benchmarks/bench_proc.mojo \
            client "$PORT" "$CONNS" "$ROUNDS" "$PAYLOAD" $EXTRA 2>&1 |
            grep '^two-proc' >> "$OUT" ) &
    done
    wait
else
    # Independent: each pair gets its own port.
    for i in $(seq 1 "$N"); do
        PORT=$((BASE_PORT + i * 2))
        pixi run mojo run -I . benchmarks/bench_proc.mojo \
            server "$PORT" "$CONNS" $EXTRA >/dev/null 2>&1 &
    done
    sleep 1.5
    for i in $(seq 1 "$N"); do
        PORT=$((BASE_PORT + i * 2))
        ( pixi run mojo run -I . benchmarks/bench_proc.mojo \
            client "$PORT" "$CONNS" "$ROUNDS" "$PAYLOAD" $EXTRA 2>&1 |
            grep '^two-proc' >> "$OUT" ) &
    done
    wait
fi

echo "=== socket-mojo $MODE: $N workers × $CONNS conns × $ROUNDS rounds × $PAYLOAD B (EXTRA=$EXTRA) ==="
cat "$OUT" | sed 's/^/  /'
echo
total=$(awk '/^two-proc/ { for (i=1; i<=NF; i++) if ($i ~ /^[0-9]+$/ && $(i+1) == "rt/s") s += $i } END { print s }' "$OUT")
echo "  TOTAL aggregate: $total rt/s"
