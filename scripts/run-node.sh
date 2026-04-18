#!/bin/bash
# Run Axiom Network Node
# Usage: ./scripts/run-node.sh [OPTIONS]

# Default configuration
NETWORK="devnet"
DATA_DIR="./data"
RPC_BIND="127.0.0.1:8332"
P2P_BIND="0.0.0.0:9000"
LOG_LEVEL="info"
MINE=""
MINER_ADDRESS=""
SEEDS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --network)
      NETWORK="$2"
      shift 2
      ;;
    --data-dir)
      DATA_DIR="$2"
      shift 2
      ;;
    --mine)
      MINE="--mine"
      shift
      ;;
    --miner-address)
      MINER_ADDRESS="--miner-address $2"
      shift 2
      ;;
    --seeds)
      SEEDS="--seeds $2"
      shift 2
      ;;
    --log-level)
      LOG_LEVEL="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Build if needed
if [ ! -f "./target/release/axiom-node" ]; then
  echo "Building node binary..."
  cargo build --release -p axiom-cli
fi

# Run node
echo "Starting Axiom Network Node..."
echo "Network: $NETWORK"
echo "Data directory: $DATA_DIR"
echo "RPC: $RPC_BIND"
echo "P2P: $P2P_BIND"
echo ""

./target/release/axiom-node \
  --network "$NETWORK" \
  --data-dir "$DATA_DIR" \
  --rpc-bind "$RPC_BIND" \
  --p2p-bind "$P2P_BIND" \
  --log-level "$LOG_LEVEL" \
  $MINE \
  $MINER_ADDRESS \
  $SEEDS
