#!/bin/bash
# Axiom Network — 4-node local testnet launcher.
#
# Spawns four axiom-node processes bound to distinct RPC/P2P ports and
# data directories on 127.0.0.1, wired as a full mesh via --peer. The
# topology mirrors what a real 4-server deployment would look like;
# swap 127.0.0.1 for real host IPs in testnet-topology.env when deploying.
#
# Usage:
#   scripts/testnet/launch-local.sh start   # start all nodes
#   scripts/testnet/launch-local.sh stop    # kill all nodes
#   scripts/testnet/launch-local.sh status  # show PIDs + heights
#
# All logs go to scripts/testnet/logs/nodeN.log.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="$PROJECT_ROOT/target/release/axiom-node.exe"
[ -f "$BIN" ] || BIN="$PROJECT_ROOT/target/release/axiom-node"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/testnet-topology.env"

DATA_ROOT="${AXIOM_TESTNET_DATA_ROOT:-/tmp/axiom-testnet}"
LOG_DIR="$SCRIPT_DIR/logs"
PID_DIR="$SCRIPT_DIR/pids"
mkdir -p "$DATA_ROOT" "$LOG_DIR" "$PID_DIR"

# Addresses: mine to a test address per node. These are deterministic
# hex pubkey-hashes, NOT real wallets. Nothing is spendable from them in
# this topology — this is a block-production test harness.
MINER_0="0000000000000000000000000000000000000000000000000000000000000001"
MINER_1="0000000000000000000000000000000000000000000000000000000000000002"

peer_list() {
    # Return --peer args for every node except $1.
    local self=$1
    local out=""
    for i in 0 1 2 3; do
        if [ "$i" != "$self" ]; then
            local var="P2P_${i}"
            out="$out --peer ${!var}"
        fi
    done
    echo "$out"
}

start_one() {
    local idx=$1
    local rpc_var="RPC_${idx}"
    local p2p_var="P2P_${idx}"
    local rpc=${!rpc_var}
    local p2p=${!p2p_var}
    local data="$DATA_ROOT/n${idx}"
    local log="$LOG_DIR/node${idx}.log"
    local pidfile="$PID_DIR/node${idx}.pid"

    mkdir -p "$data"

    local mine_args=""
    case $idx in
        0) mine_args="--mine --miner-address $MINER_0 --mining-interval 1" ;;
        1) mine_args="--mine --miner-address $MINER_1 --mining-interval 1" ;;
        *) mine_args="" ;;  # nodes 2, 3 are relay/observer
    esac

    # shellcheck disable=SC2086
    nohup "$BIN" \
        --network test \
        --data-dir "$data" \
        --rpc-bind "$rpc" \
        --p2p-bind "$p2p" \
        $(peer_list "$idx") \
        $mine_args \
        --log-level info \
        >"$log" 2>&1 &

    echo $! >"$pidfile"
    echo "node${idx}: pid=$(cat "$pidfile") rpc=$rpc p2p=$p2p mining=$([ -n "$mine_args" ] && echo yes || echo no)"
}

stop_all() {
    for idx in 0 1 2 3; do
        local pidfile="$PID_DIR/node${idx}.pid"
        if [ -f "$pidfile" ]; then
            local pid
            pid=$(cat "$pidfile")
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                echo "stopped node${idx} pid=$pid"
            fi
            rm -f "$pidfile"
        fi
    done
    # Best-effort cleanup of any strays on Windows.
    if command -v taskkill.exe >/dev/null 2>&1; then
        taskkill.exe //F //IM axiom-node.exe >/dev/null 2>&1 || true
    fi
}

status_all() {
    printf "%-7s %-10s %-18s %-18s %-8s %-8s\n" NODE PID RPC P2P HEIGHT PEERS
    for idx in 0 1 2 3; do
        local rpc_var="RPC_${idx}"
        local p2p_var="P2P_${idx}"
        local rpc=${!rpc_var}
        local p2p=${!p2p_var}
        local pid="-"
        local pidfile="$PID_DIR/node${idx}.pid"
        [ -f "$pidfile" ] && pid=$(cat "$pidfile")

        local height peers
        height=$(curl -s --max-time 2 "http://$rpc/best_height" 2>/dev/null || echo "?")
        peers=$(curl -s --max-time 2 "http://$rpc/peer_count" 2>/dev/null | python -c "import json,sys; print(json.load(sys.stdin).get('count', '?'))" 2>/dev/null || echo "?")
        printf "%-7s %-10s %-18s %-18s %-8s %-8s\n" "n${idx}" "$pid" "$rpc" "$p2p" "$height" "$peers"
    done
}

case "${1:-}" in
    start)
        echo "Starting Axiom testnet on $BIN"
        for idx in 0 1 2 3; do start_one "$idx"; done
        echo "All four nodes launched. Logs: $LOG_DIR/nodeN.log"
        ;;
    stop)
        stop_all
        ;;
    status)
        status_all
        ;;
    restart)
        stop_all
        sleep 2
        "$0" start
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        exit 2
        ;;
esac
