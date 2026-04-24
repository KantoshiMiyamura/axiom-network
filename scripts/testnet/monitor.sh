#!/bin/bash
# Axiom testnet monitor.
#
# Polls all nodes at a fixed interval and writes a CSV of:
#   ts, node, height, tip_hash, peers, mempool_count, orphan_count_est
#
# Also emits a running divergence report on stderr when any two nodes
# disagree on the tip hash at the same height (a fork), and detects
# reorgs by watching for height-decreasing tip transitions.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/testnet-topology.env"

INTERVAL=${1:-10}
DURATION=${2:-0}       # 0 = forever
OUT_CSV="${3:-$SCRIPT_DIR/logs/metrics.csv}"
FORK_LOG="$SCRIPT_DIR/logs/forks.log"
REORG_LOG="$SCRIPT_DIR/logs/reorgs.log"
mkdir -p "$(dirname "$OUT_CSV")"

RPCS=("$RPC_0" "$RPC_1" "$RPC_2" "$RPC_3")

echo "ts,node,height,tip_hash,peers,orphans,mempool_count" >"$OUT_CSV"
: >"$FORK_LOG"
: >"$REORG_LOG"

declare -A LAST_HEIGHT
declare -A LAST_TIP
START=$(date +%s)

while true; do
    NOW=$(date +%s)
    if [ "$DURATION" -gt 0 ] && [ $((NOW - START)) -ge "$DURATION" ]; then
        break
    fi

    declare -A TIP_AT_HEIGHT
    declare -A NODE_AT_TIP

    for i in 0 1 2 3; do
        RPC="${RPCS[$i]}"
        TIP_JSON=$(curl -s --max-time 3 "http://$RPC/tip" 2>/dev/null || echo "{}")
        HEIGHT=$(echo "$TIP_JSON" | python -c "import json,sys;d=json.loads(sys.stdin.read() or '{}'); print(d.get('best_height',''))" 2>/dev/null || echo "")
        TIP=$(echo "$TIP_JSON" | python -c "import json,sys;d=json.loads(sys.stdin.read() or '{}'); print(d.get('best_block_hash',''))" 2>/dev/null || echo "")
        PEERS=$(echo "$TIP_JSON" | python -c "import json,sys;d=json.loads(sys.stdin.read() or '{}'); print(d.get('peers',''))" 2>/dev/null || echo "")
        ORPHANS=$(echo "$TIP_JSON" | python -c "import json,sys;d=json.loads(sys.stdin.read() or '{}'); print(d.get('orphan_count',''))" 2>/dev/null || echo "")
        MEMCOUNT=$(curl -s --max-time 3 "http://$RPC/mempool" 2>/dev/null | python -c "import json,sys;d=json.loads(sys.stdin.read() or '{}'); print(d.get('count',''))" 2>/dev/null || echo "")

        echo "$NOW,n${i},${HEIGHT},${TIP},${PEERS},${ORPHANS},${MEMCOUNT}" >>"$OUT_CSV"

        # Reorg detection: tip hash at same or lower height changed.
        PREV_H=${LAST_HEIGHT[$i]:-}
        PREV_T=${LAST_TIP[$i]:-}
        if [ -n "$PREV_H" ] && [ -n "$HEIGHT" ] && [ -n "$TIP" ]; then
            if [ "$HEIGHT" -lt "$PREV_H" ]; then
                echo "$NOW n${i} REORG height_dropped $PREV_H -> $HEIGHT" | tee -a "$REORG_LOG" >&2
            elif [ "$HEIGHT" = "$PREV_H" ] && [ "$TIP" != "$PREV_T" ]; then
                echo "$NOW n${i} REORG tip_switched_at_height $HEIGHT $PREV_T -> $TIP" | tee -a "$REORG_LOG" >&2
            fi
        fi
        LAST_HEIGHT[$i]=$HEIGHT
        LAST_TIP[$i]=$TIP

        # Fork detection: two nodes at the same height with different tips.
        if [ -n "$HEIGHT" ] && [ -n "$TIP" ]; then
            KEY="$HEIGHT"
            EXISTING="${TIP_AT_HEIGHT[$KEY]:-}"
            if [ -z "$EXISTING" ]; then
                TIP_AT_HEIGHT[$KEY]="$TIP"
                NODE_AT_TIP[$KEY]="n${i}"
            elif [ "$EXISTING" != "$TIP" ]; then
                echo "$NOW FORK height=$HEIGHT ${NODE_AT_TIP[$KEY]}=$EXISTING n${i}=$TIP" | tee -a "$FORK_LOG" >&2
            fi
        fi
    done

    unset TIP_AT_HEIGHT NODE_AT_TIP
    declare -A TIP_AT_HEIGHT
    declare -A NODE_AT_TIP

    sleep "$INTERVAL"
done

echo "Monitor stopped. Output: $OUT_CSV"
