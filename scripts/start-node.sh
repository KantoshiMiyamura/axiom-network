#!/bin/bash
# Start a single Axiom Network testnet node

set -e

NODE_ID=${1:-0}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration
NETWORK="test"
DATA_DIR="$PROJECT_ROOT/testnet/data/node$NODE_ID"
RPC_PORT=$((8332 + NODE_ID))
P2P_PORT=$((9000 + NODE_ID))

# Create data directory
mkdir -p "$DATA_DIR"
mkdir -p "$PROJECT_ROOT/testnet/logs"

echo "Starting Axiom Network Node $NODE_ID"
echo "Network: $NETWORK"
echo "Data Dir: $DATA_DIR"
echo "RPC Port: $RPC_PORT"
echo "P2P Port: $P2P_PORT"
echo ""

# Note: This is a placeholder script
# In a real implementation, you would:
# 1. Build the node binary: cargo build --release
# 2. Run: ./target/release/axiom-node --network $NETWORK --data-dir $DATA_DIR --rpc-port $RPC_PORT --p2p-port $P2P_PORT

echo "⚠️  Node binary not yet implemented"
echo "To implement:"
echo "1. Create src/main.rs in axiom-node crate"
echo "2. Add [[bin]] section to Cargo.toml"
echo "3. Implement CLI argument parsing"
echo "4. Start node with RPC server"
echo ""
echo "For now, use programmatic API:"
echo ""
echo "use axiom_node::{Node, Config, Network};"
echo "use axiom_rpc::RpcServer;"
echo "use std::sync::{Arc, Mutex};"
echo ""
echo "let config = Config {"
echo "    network: Network::Test,"
echo "    data_dir: PathBuf::from(\"$DATA_DIR\"),"
echo "    rpc_bind: \"127.0.0.1:$RPC_PORT\".to_string(),"
echo "    mempool_max_size: 300_000_000,"
echo "    mempool_max_count: 50_000,"
echo "    min_fee_rate: 1,"
echo "};"
echo ""
echo "let node = Node::new(config)?;"
echo "let state = Arc::new(Mutex::new(node));"
echo "let server = RpcServer::new(\"127.0.0.1:$RPC_PORT\".parse()?, state);"
echo "server.start().await?;"
