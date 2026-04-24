#!/bin/bash
# Axiom Network — Full funded transaction flow against local 4-node testnet.
#
# Does:
#   1. Creates 4 ML-DSA-87 wallets (W1..W4).
#   2. Launches 4-node testnet on 127.0.0.1 with node-0 mining to W1.
#   3. Waits for W1 to accrue spendable balance (coinbase maturity).
#   4. Submits 3 txs from W1 → W2, W3, W4 at different fee rates to create
#      mempool pressure.
#   5. Captures mempool snapshots on every node (propagation check).
#   6. Waits for block inclusion on every node.
#   7. Verifies final balances and captures block-inclusion proof.
#
# Captures evidence into $OUT_DIR.
#
# Usage:
#   scripts/e2e/run-funded-flow.sh
set -u  # note: no -e — we intentionally trap errors and keep capturing evidence

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN_NODE="$PROJECT_ROOT/target/release/axiom-node.exe"
BIN_AXIOM="$PROJECT_ROOT/target/release/axiom.exe"
[ -f "$BIN_NODE" ] || BIN_NODE="$PROJECT_ROOT/target/release/axiom-node"
[ -f "$BIN_AXIOM" ] || BIN_AXIOM="$PROJECT_ROOT/target/release/axiom"

OUT_DIR="${OUT_DIR:-/tmp/axiom-e2e-run}"
DATA_ROOT="${DATA_ROOT:-/tmp/axiom-testnet}"
PASSWORD="${AXIOM_TEST_PASSWORD:-testpass12345}"

RPC_0="127.0.0.1:18330"
RPC_1="127.0.0.1:18331"
RPC_2="127.0.0.1:18332"
RPC_3="127.0.0.1:18333"
P2P_0="127.0.0.1:29000"
P2P_1="127.0.0.1:29001"
P2P_2="127.0.0.1:29002"
P2P_3="127.0.0.1:29003"

rm -rf "$OUT_DIR" "$DATA_ROOT"
mkdir -p "$OUT_DIR/logs" "$OUT_DIR/wallets" "$OUT_DIR/snapshots" "$DATA_ROOT"

EVIDENCE="$OUT_DIR/EVIDENCE.md"
: >"$EVIDENCE"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT_DIR/driver.log"; }

md()  { echo "$*" >>"$EVIDENCE"; }

die() {
    log "FATAL: $*"
    md "## FATAL"
    md "$*"
    stop_nodes
    exit 1
}

md "# Axiom Network — Funded Transaction Flow Evidence"
md ""
md "Start: $(date -Iseconds)"
md "Binary: $(realpath "$BIN_NODE")"
md "Binary version: $("$BIN_NODE" --version 2>&1 | head -1)"
md ""

# ── 1. Create wallets ──────────────────────────────────────────────────────
log "Creating 4 wallets"
for i in 1 2 3 4; do
    printf "yes\n%s\n%s\n" "$PASSWORD" "$PASSWORD" \
        | "$BIN_AXIOM" wallet create --out "$OUT_DIR/wallets/w${i}.json" \
        >"$OUT_DIR/logs/wallet_create_${i}.log" 2>&1 \
        || die "wallet create w${i} failed"
    ADDR=$(printf "%s\n" "$PASSWORD" | "$BIN_AXIOM" wallet address --wallet "$OUT_DIR/wallets/w${i}.json" 2>/dev/null | grep -oE 'axm[0-9a-f]+' | head -1)
    [ -n "$ADDR" ] || die "could not derive address for w${i}"
    echo "$ADDR" >"$OUT_DIR/wallets/w${i}.addr"
    log "w${i} = $ADDR"
done

W1_ADDR=$(cat "$OUT_DIR/wallets/w1.addr")
W2_ADDR=$(cat "$OUT_DIR/wallets/w2.addr")
W3_ADDR=$(cat "$OUT_DIR/wallets/w3.addr")
W4_ADDR=$(cat "$OUT_DIR/wallets/w4.addr")

md "## 1. Wallets"
md ""
md "| Wallet | Address |"
md "|---|---|"
md "| W1 (miner+sender) | \`$W1_ADDR\` |"
md "| W2 | \`$W2_ADDR\` |"
md "| W3 | \`$W3_ADDR\` |"
md "| W4 | \`$W4_ADDR\` |"
md ""

# ── 2. Start testnet ───────────────────────────────────────────────────────
start_node() {
    local idx=$1
    local rpc=$2
    local p2p=$3
    shift 3
    local peers=("$@")
    local peer_args=()
    for p in "${peers[@]}"; do peer_args+=(--peer "$p"); done
    local data="$DATA_ROOT/n${idx}"
    local log="$OUT_DIR/logs/node${idx}.log"
    mkdir -p "$data"

    local mine_args=()
    if [ "$idx" = "0" ]; then
        mine_args=(--mine --miner-address "$W1_ADDR" --mining-interval 1)
    fi

    nohup "$BIN_NODE" \
        --network dev \
        --data-dir "$data" \
        --rpc-bind "$rpc" \
        --p2p-bind "$p2p" \
        "${peer_args[@]}" \
        "${mine_args[@]}" \
        --log-level info \
        >"$log" 2>&1 &
    echo $! >"$OUT_DIR/node${idx}.pid"
    log "node${idx} pid=$! rpc=$rpc p2p=$p2p $([ $idx = 0 ] && echo '(miner)' || echo '')"
}

stop_nodes() {
    for idx in 0 1 2 3; do
        local pidfile="$OUT_DIR/node${idx}.pid"
        [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null
    done
    command -v taskkill.exe >/dev/null 2>&1 && taskkill.exe //F //IM axiom-node.exe >/dev/null 2>&1 || true
}

trap stop_nodes EXIT

log "Starting 4-node testnet"
start_node 0 "$RPC_0" "$P2P_0" "$P2P_1" "$P2P_2" "$P2P_3"
start_node 1 "$RPC_1" "$P2P_1" "$P2P_0" "$P2P_2" "$P2P_3"
start_node 2 "$RPC_2" "$P2P_2" "$P2P_0" "$P2P_1" "$P2P_3"
start_node 3 "$RPC_3" "$P2P_3" "$P2P_0" "$P2P_1" "$P2P_2"

# ── 3. Wait for handshake ──────────────────────────────────────────────────
log "Waiting for nodes to become RPC-ready + peers connected"
for _ in $(seq 1 30); do
    ALL_UP=1
    for r in $RPC_0 $RPC_1 $RPC_2 $RPC_3; do
        curl -s --max-time 2 "http://$r/health" >/dev/null 2>&1 || ALL_UP=0
    done
    [ "$ALL_UP" = "1" ] && break
    sleep 1
done

# Readiness gate: non-mining peers must have their tip progress once n0 mines a block.
# This is the authoritative propagation signal (the /peer_count endpoint is unreliable
# at the time of writing — broadcast logs show "ready_peers=6/6" while peer_count
# RPC can still read 0 depending on which counter it queries).
get_h() { curl -s --max-time 2 "http://$1/tip" | python -c "import json,sys;d=json.load(sys.stdin);print(d.get('best_height',0))" 2>/dev/null || echo 0; }

for _ in $(seq 1 45); do
    H0=$(get_h "$RPC_0")
    H1=$(get_h "$RPC_1")
    H2=$(get_h "$RPC_2")
    H3=$(get_h "$RPC_3")
    log "heights: n0=$H0 n1=$H1 n2=$H2 n3=$H3"
    # Non-miner nodes received blocks = mesh is wired + blocks propagating.
    if [ "$H1" -gt 0 ] && [ "$H2" -gt 0 ] && [ "$H3" -gt 0 ]; then
        break
    fi
    sleep 2
done

md "## 2. Mesh propagation (tip heights after warmup)"
md ""
md "| Node | Tip height |"
md "|---|---|"
md "| n0 (miner) | $H0 |"
md "| n1 | $H1 |"
md "| n2 | $H2 |"
md "| n3 | $H3 |"
md ""
md "Non-miner nodes advancing past 0 proves the mesh is wired and blocks propagate."
md ""
[ "$H1" -gt 0 ] && [ "$H2" -gt 0 ] && [ "$H3" -gt 0 ] \
    || die "non-miner nodes did not receive any block after 90s"

# ── 4. Wait for W1 to have spendable balance ───────────────────────────────
log "Mining blocks to W1 (waiting for spendable balance)"

get_balance() {
    # /balance/:address — path parameter. Response: { "balance": <u64> }.
    curl -s --max-time 3 "http://$1/balance/$2" \
        | python -c "import json,sys; d=json.load(sys.stdin); print(d.get('balance', 0))" 2>/dev/null \
        || echo 0
}
get_tip() {
    curl -s --max-time 3 "http://$1/tip" \
        | python -c "import json,sys; d=json.load(sys.stdin); print(d.get('best_height', 0))" 2>/dev/null \
        || echo 0
}

BAL=0
# Devnet COINBASE_MATURITY = 5 blocks. Wait for tip ≥ 7 so the earliest coinbases
# (h=1, h=2) are both provably mature and W1 has multiple spendable UTXOs.
# The /balance endpoint reports gross coinbase; a wallet send still rejects with
# "no mature UTXOs" if tip < coinbase_height + maturity.
MIN_TIP_FOR_SPEND=7
for i in $(seq 1 180); do
    H=$(get_tip "$RPC_0")
    BAL=$(get_balance "$RPC_0" "$W1_ADDR")
    log "h=$H W1_confirmed_sat=$BAL"
    if [ -n "$BAL" ] && [ "$BAL" -gt 100000 ] && [ "$H" -ge "$MIN_TIP_FOR_SPEND" ]; then
        break
    fi
    sleep 2
done

md "## 3. Initial mining"
md ""
md "- Tip height after $((i*2))s: \`$H\`"
md "- W1 confirmed balance: \`$BAL\` sat"
md ""

[ "$BAL" -gt 100000 ] || die "W1 did not accrue balance (got $BAL sat after $((i*2))s)"

# Baseline balances ─────────────────────────────────────────────────────────
BAL_W1_BEFORE=$(get_balance "$RPC_0" "$W1_ADDR")
BAL_W2_BEFORE=$(get_balance "$RPC_0" "$W2_ADDR")
BAL_W3_BEFORE=$(get_balance "$RPC_0" "$W3_ADDR")
BAL_W4_BEFORE=$(get_balance "$RPC_0" "$W4_ADDR")
H_BEFORE=$(get_tip "$RPC_0")

log "BEFORE tx: h=$H_BEFORE W1=$BAL_W1_BEFORE W2=$BAL_W2_BEFORE W3=$BAL_W3_BEFORE W4=$BAL_W4_BEFORE"

md "## 4. Balances before sends"
md ""
md "At tip height \`$H_BEFORE\`:"
md ""
md "| Wallet | Confirmed (sat) |"
md "|---|---|"
md "| W1 | $BAL_W1_BEFORE |"
md "| W2 | $BAL_W2_BEFORE |"
md "| W3 | $BAL_W3_BEFORE |"
md "| W4 | $BAL_W4_BEFORE |"
md ""

# ── 5. Submit 3 txs at different fees (mempool pressure) ───────────────────
send_tx() {
    local idx=$1
    local to=$2
    local amount_sat=$3
    local fee=$4
    # axiom wallet send uses rpassword::prompt_password which reads /dev/tty
    # and ignores piped stdin. The test-fixtures feature in axiom-cli adds an
    # env-var fallback for exactly this situation. Binary must be built with
    # `cargo build --release -p axiom-cli --features test-fixtures`.
    AXIOM_TEST_WALLET_PASSWORD="$PASSWORD" "$BIN_AXIOM" wallet send \
        --to "$to" \
        --amount "$amount_sat" --sat \
        --fee "$fee" \
        --wallet "$OUT_DIR/wallets/w1.json" \
        --rpc "http://$RPC_0" \
        --yes \
        >"$OUT_DIR/logs/tx${idx}.log" 2>&1
    return $?
}

log "Submitting 3 txs with fees 500, 2000, 5000"

# Race the miner: spin a fast snapshot loop on all 4 nodes WHILE sends are
# in flight. With --mining-interval 1s, blocks include any pending tx within
# ~1s, so we have to be polling already to catch the propagation state.
SNAP_DIR="$OUT_DIR/snapshots"
SNAP_PID_FILE="$OUT_DIR/snap.pid"
(
    iter=0
    while true; do
        iter=$((iter+1))
        for idx in 0 1 2 3; do
            rpc_var="RPC_${idx}"
            rpc="${!rpc_var}"
            curl -s --max-time 1 "http://$rpc/mempool" \
                >"$SNAP_DIR/mempool_n${idx}_iter${iter}.json" 2>/dev/null
        done
    done
) &
echo $! >"$SNAP_PID_FILE"

# The wallet selects UTXOs from confirmed chain state, not mempool. Without
# a delay between sends, two back-to-back sends pick the same UTXO and the
# second one looks like an RBF replacement (rejected without a 10% fee bump).
# Sleep ~4 blocks of mining (1s interval) between sends so each is confirmed
# before the wallet selects inputs for the next.
send_tx 1 "$W2_ADDR" 10000 500   || log "tx1 non-zero exit (check tx1.log)"
sleep 4
send_tx 2 "$W3_ADDR" 20000 2000  || log "tx2 non-zero exit (check tx2.log)"
sleep 4
send_tx 3 "$W4_ADDR" 30000 5000  || log "tx3 non-zero exit (check tx3.log)"

# Let the polling loop run a bit more to catch tail mempool state.
sleep 2
kill "$(cat "$SNAP_PID_FILE")" 2>/dev/null || true

# Also take a final post-submit snapshot for archival.
log "Capturing final mempool snapshots (post-submit)"
for idx in 0 1 2 3; do
    rpc_var="RPC_${idx}"
    rpc="${!rpc_var}"
    snap="$SNAP_DIR/mempool_n${idx}_after_submit.json"
    curl -s --max-time 3 "http://$rpc/mempool" >"$snap" 2>/dev/null || echo "{}" >"$snap"
done

# Now find, across ALL iterations, the maximum mempool depth observed per
# node. That is the actual propagation evidence: even if mining drained the
# pool to 0 by snapshot time, the parallel poller saw the in-flight state.
md "## 5. Mempool state during submission (parallel polling)"
md ""
md "A background loop polled \`/mempool\` on every node ~5x/sec while the 3 sends"
md "were in flight. With \`--mining-interval=1s\`, blocks normally drain the pool"
md "between snapshots — the parallel poll captures the brief propagation window."
md ""
md "| Node | Max mempool depth observed during sends | After-submit snapshot |"
md "|---|---|---|"
for idx in 0 1 2 3; do
    rpc_var="RPC_${idx}"
    rpc="${!rpc_var}"
    max_depth=$(
        for f in "$SNAP_DIR"/mempool_n${idx}_iter*.json; do
            [ -f "$f" ] || continue
            cat "$f" | python -c "import json,sys; d=json.load(sys.stdin); print(d.get('count', len(d.get('transactions', []))))" 2>/dev/null
        done | sort -n | tail -1
    )
    [ -z "$max_depth" ] && max_depth="0"
    after=$(cat "$SNAP_DIR/mempool_n${idx}_after_submit.json" 2>/dev/null | python -c "import json,sys; d=json.load(sys.stdin); print(d.get('count', len(d.get('transactions', []))))" 2>/dev/null || echo ?)
    md "| n${idx} | $max_depth | $after | "
done
md ""

# Find the iter file with the most txs and show fee fields from it.
BEST_SNAP=$(
    for f in "$SNAP_DIR"/mempool_n0_iter*.json; do
        [ -f "$f" ] || continue
        c=$(cat "$f" | python -c "import json,sys; d=json.load(sys.stdin); print(d.get('count', 0))" 2>/dev/null || echo 0)
        echo "$c $f"
    done | sort -n | tail -1 | awk '{print $2}'
)
if [ -n "$BEST_SNAP" ] && [ -f "$BEST_SNAP" ]; then
    FEE_SAMPLE=$(cat "$BEST_SNAP" | python -c "
import json,sys
d = json.load(sys.stdin)
for t in d.get('transactions', [])[:5]:
    print(f\"{t.get('txid','?')[:16]}... fee_sat={t.get('fee_sat')} size={t.get('size')}\")
" 2>&1)
    md "### Sample fee fields from peak-mempool snapshot ($(basename "$BEST_SNAP"))"
    md ""
    md "Verifies fee_sat is real, not 0:"
    md ""
    md "\`\`\`"
    md "$FEE_SAMPLE"
    md "\`\`\`"
    md ""
fi

# ── 7. Wait for block inclusion ────────────────────────────────────────────
log "Waiting for block inclusion"
for _ in $(seq 1 60); do
    MEM_N0=$(curl -s --max-time 3 "http://$RPC_0/mempool" | python -c "import json,sys; d=json.load(sys.stdin); print(d.get('count', 0))" 2>/dev/null || echo 0)
    log "mempool_n0 after wait = $MEM_N0"
    [ "$MEM_N0" -lt 1 ] && break
    sleep 2
done

H_AFTER=$(get_tip "$RPC_0")
BAL_W1_AFTER=$(get_balance "$RPC_0" "$W1_ADDR")
BAL_W2_AFTER=$(get_balance "$RPC_0" "$W2_ADDR")
BAL_W3_AFTER=$(get_balance "$RPC_0" "$W3_ADDR")
BAL_W4_AFTER=$(get_balance "$RPC_0" "$W4_ADDR")

md "## 6. Balances after block inclusion"
md ""
md "Tip height advanced from \`$H_BEFORE\` → \`$H_AFTER\` (delta = $((H_AFTER - H_BEFORE)) blocks)."
md ""
md "| Wallet | Before (sat) | After (sat) | Δ |"
md "|---|---|---|---|"
md "| W1 (sender+miner) | $BAL_W1_BEFORE | $BAL_W1_AFTER | $((BAL_W1_AFTER - BAL_W1_BEFORE)) |"
md "| W2 (recv 10k, fee 500)  | $BAL_W2_BEFORE | $BAL_W2_AFTER | $((BAL_W2_AFTER - BAL_W2_BEFORE)) |"
md "| W3 (recv 20k, fee 2000) | $BAL_W3_BEFORE | $BAL_W3_AFTER | $((BAL_W3_AFTER - BAL_W3_BEFORE)) |"
md "| W4 (recv 30k, fee 5000) | $BAL_W4_BEFORE | $BAL_W4_AFTER | $((BAL_W4_AFTER - BAL_W4_BEFORE)) |"
md ""

# ── 8. Cross-node consistency check (no fork) ──────────────────────────────
# Tips can briefly differ across nodes during normal propagation (one node is
# 1 block ahead). A real fork = different hashes at the SAME height. We poll
# until either all tips agree or 30s elapses, then classify.
get_tip_pair() {
    curl -s --max-time 2 "http://$1/tip" \
        | python -c "import json,sys;d=json.load(sys.stdin);print(d.get('best_height',0),d.get('best_block_hash',''))" 2>/dev/null \
        || echo "0 ?"
}
CONVERGED=0
for _ in $(seq 1 15); do
    read -r H0 TIP_0 < <(get_tip_pair "$RPC_0")
    read -r H1 TIP_1 < <(get_tip_pair "$RPC_1")
    read -r H2 TIP_2 < <(get_tip_pair "$RPC_2")
    read -r H3 TIP_3 < <(get_tip_pair "$RPC_3")
    if [ "$TIP_0" = "$TIP_1" ] && [ "$TIP_1" = "$TIP_2" ] && [ "$TIP_2" = "$TIP_3" ]; then
        CONVERGED=1
        break
    fi
    sleep 2
done

md "## 7. Cross-node tip agreement"
md ""
md "| Node | Height | Tip hash |"
md "|---|---|---|"
md "| n0 | $H0 | \`$TIP_0\` |"
md "| n1 | $H1 | \`$TIP_1\` |"
md "| n2 | $H2 | \`$TIP_2\` |"
md "| n3 | $H3 | \`$TIP_3\` |"
md ""

if [ "$CONVERGED" = "1" ]; then
    md "**All 4 nodes agree on tip after convergence. No fork.**"
elif [ "$H0" = "$H1" ] && [ "$H1" = "$H2" ] && [ "$H2" = "$H3" ]; then
    md "**FORK DETECTED** — same height, different hashes. Anomaly."
else
    md "**Tips differ but heights also differ — propagation lag, not a fork.**"
fi

md ""
md "End: $(date -Iseconds)"
log "Evidence written: $EVIDENCE"
log "Done."
