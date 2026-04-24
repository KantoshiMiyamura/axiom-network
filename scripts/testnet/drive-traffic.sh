#!/bin/bash
# Axiom testnet traffic driver.
#
# Submits a continuous stream of transactions to one node (by default n2,
# a relay-only node) so mempool propagation across the mesh can be
# observed. Uses axiom-stress in "validation" mode, which produces
# cryptographically-valid but intentionally-rejectable transactions —
# this exercises every code path up to mempool admission without
# requiring a funded wallet.
#
# For true mempool loading (transactions that actually enter the mempool
# and get mined), supply --mode mempool with a funded wallet.
#
# Usage:
#   scripts/testnet/drive-traffic.sh [tps] [count] [target-node]
#
# Examples:
#   scripts/testnet/drive-traffic.sh 5 0 2    # 5 tps, forever, into n2
#   scripts/testnet/drive-traffic.sh 20 500 0 # 20 tps, 500 total, into n0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STRESS="$PROJECT_ROOT/target/release/axiom-stress.exe"
[ -f "$STRESS" ] || STRESS="$PROJECT_ROOT/target/release/axiom-stress"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/testnet-topology.env"

TPS=${1:-5}
COUNT=${2:-0}       # 0 = indefinite
TARGET=${3:-2}      # node index to submit to
MODE=${FLOOD_MODE:-validation}
WALLET=${FLOOD_WALLET:-}

RPC_VAR="RPC_${TARGET}"
RPC="${!RPC_VAR}"

LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/traffic.log"

echo "Driving traffic at ${TPS} tps -> http://${RPC} (node ${TARGET}, mode=${MODE})"
echo "Log: $LOG"

ARGS=(flood --rpc "http://$RPC" --tps "$TPS" --count "$COUNT" --mode "$MODE")
if [ -n "$WALLET" ]; then
    ARGS+=(--wallet "$WALLET")
fi

exec "$STRESS" "${ARGS[@]}" 2>&1 | tee -a "$LOG"
