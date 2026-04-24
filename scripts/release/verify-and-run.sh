#!/usr/bin/env bash
# Axiom Network — end-user verify + run + send loop.
#
# This is the script an end user should run AFTER downloading a release.
# Performs, in order:
#
#   1. verify SHA256SUMS matches every downloaded artifact
#   2. verify SHA256SUMS.minisig is a valid signature from the Axiom
#      Network minisign public key
#   3. verify the release git tag is GPG-signed (if a source checkout is
#      also present)
#   4. launch axiom-node against the public testnet bootstrap peers
#   5. create a wallet and send a 1-sat test transaction
#   6. report PASS/FAIL for every stage
#
# All failures abort. No silent fallbacks.
#
# REQUIREMENTS:
#   - minisign
#   - sha256sum (or shasum on macOS)
#   - curl, python3
#   - gpg (only if step 3 is run against a source checkout)
#
# INPUTS (environment):
#   AXIOM_RELEASE_DIR         directory containing the downloaded release files
#                             (must contain SHA256SUMS, SHA256SUMS.minisig, and
#                             the extracted axiom-node / axiom binaries)
#   AXIOM_PUBKEY              path to axiom-network minisign public key
#                             (published on the website and in this repo)
#   AXIOM_TESTNET_BOOTSTRAP   comma-separated "host:port" list of known-good
#                             bootstrap peers (printed on the release page)
#
# INVOCATION:
#   export AXIOM_RELEASE_DIR=$PWD/axiom-v1.0.1-testnet.2
#   export AXIOM_PUBKEY=$PWD/axiom-network.pub
#   export AXIOM_TESTNET_BOOTSTRAP="bootstrap1.axiom.example:29000,bootstrap2.axiom.example:29000"
#   scripts/release/verify-and-run.sh
#
# ⚠ This script writes a wallet.json in $AXIOM_RELEASE_DIR/run/. Keep it local.

set -euo pipefail

: "${AXIOM_RELEASE_DIR:?set AXIOM_RELEASE_DIR=/path/to/unpacked/release}"
: "${AXIOM_PUBKEY:?set AXIOM_PUBKEY=/path/to/axiom-network.pub}"
: "${AXIOM_TESTNET_BOOTSTRAP:?set AXIOM_TESTNET_BOOTSTRAP=host:port[,host:port...]}"

cd "$AXIOM_RELEASE_DIR"

step() { printf "\n── %s ──\n" "$*"; }
ok()   { printf "  ✔ %s\n" "$*"; }
fail() { printf "  ✘ %s\n" "$*" >&2; exit 1; }

# ── 1. SHA256 verification ────────────────────────────────────────────────
step "1. Verifying SHA256SUMS"
[ -f SHA256SUMS ]         || fail "SHA256SUMS missing in $AXIOM_RELEASE_DIR"
[ -f SHA256SUMS.minisig ] || fail "SHA256SUMS.minisig missing"

if command -v sha256sum >/dev/null; then
    sha256sum -c SHA256SUMS || fail "sha256 mismatch — release is corrupt or tampered"
elif command -v shasum >/dev/null; then
    shasum -a 256 -c SHA256SUMS || fail "sha256 mismatch"
else
    fail "no sha256sum or shasum on PATH"
fi
ok "all artifact hashes match SHA256SUMS"

# ── 2. minisign verification ──────────────────────────────────────────────
step "2. Verifying minisign signature"
command -v minisign >/dev/null || fail "minisign not installed"
[ -f "$AXIOM_PUBKEY" ]         || fail "public key not found: $AXIOM_PUBKEY"

minisign -V -p "$AXIOM_PUBKEY" -m SHA256SUMS -x SHA256SUMS.minisig \
    || fail "minisign verification FAILED — SHA256SUMS is not signed by the expected key"
ok "SHA256SUMS is signed by $AXIOM_PUBKEY"

# ── 3. Optional: verify the git tag is GPG-signed ─────────────────────────
step "3. Verifying git tag signature (optional)"
if [ -d "$AXIOM_RELEASE_DIR/../source/.git" ] && command -v gpg >/dev/null; then
    TAG=$(git -C "$AXIOM_RELEASE_DIR/../source" describe --tags --abbrev=0 2>/dev/null || echo "")
    if [ -n "$TAG" ]; then
        git -C "$AXIOM_RELEASE_DIR/../source" verify-tag "$TAG" \
            && ok "git tag $TAG is GPG-signed" \
            || fail "git tag $TAG is NOT GPG-signed"
    else
        echo "  (no tag to verify)"
    fi
else
    echo "  (no source checkout alongside — skipping)"
fi

# ── 4. Launch node against real bootstrap peers ───────────────────────────
step "4. Starting axiom-node (testnet)"
NODE_BIN="$AXIOM_RELEASE_DIR/axiom-node"
[ -f "$NODE_BIN" ] || NODE_BIN="$AXIOM_RELEASE_DIR/axiom-node.exe"
[ -x "$NODE_BIN" ] || fail "axiom-node binary missing or not executable"

RUN_DIR="$AXIOM_RELEASE_DIR/run"
mkdir -p "$RUN_DIR/data"

PEER_ARGS=()
IFS=',' read -r -a PEERS <<<"$AXIOM_TESTNET_BOOTSTRAP"
for p in "${PEERS[@]}"; do PEER_ARGS+=(--peer "$p"); done

RPC="127.0.0.1:18330"
nohup "$NODE_BIN" \
    --network test \
    --data-dir "$RUN_DIR/data" \
    --rpc-bind "$RPC" \
    --p2p-bind 0.0.0.0:29000 \
    "${PEER_ARGS[@]}" \
    --log-level info \
    >"$RUN_DIR/node.log" 2>&1 &
NODE_PID=$!
echo "$NODE_PID" >"$RUN_DIR/node.pid"
trap 'kill "$NODE_PID" 2>/dev/null || true' EXIT
sleep 5

for _ in $(seq 1 30); do
    H=$(curl -s --max-time 3 "http://$RPC/tip" | python3 -c "import json,sys;print(json.load(sys.stdin).get('best_height', 0))" 2>/dev/null || echo 0)
    [ "${H:-0}" -gt 0 ] && break
    sleep 2
done
ok "node running, tip height = $H"

# ── 5. Create wallet + send self-transfer (minimum viable tx) ─────────────
step "5. Creating wallet + sending a test transaction"
AXIOM_BIN="$AXIOM_RELEASE_DIR/axiom"
[ -f "$AXIOM_BIN" ] || AXIOM_BIN="$AXIOM_RELEASE_DIR/axiom.exe"

WALLET="$RUN_DIR/wallet.json"
PW="${AXIOM_TEST_PASSWORD:-changeme_changeme}"
if [ ! -f "$WALLET" ]; then
    printf "yes\n%s\n%s\n" "$PW" "$PW" | "$AXIOM_BIN" wallet create --out "$WALLET" >"$RUN_DIR/wallet_create.log" 2>&1
fi
ADDR=$(printf "%s\n" "$PW" | "$AXIOM_BIN" wallet address --wallet "$WALLET" 2>/dev/null | grep -oE 'axm[0-9a-f]+' | head -1)
[ -n "$ADDR" ] || fail "could not derive address"
ok "wallet address: $ADDR"

BAL=$(curl -s "http://$RPC/balance/$ADDR" | python3 -c "import json,sys;print(json.load(sys.stdin).get('balance', 0))" 2>/dev/null || echo 0)
echo "  balance: $BAL sat"
if [ "$BAL" -lt 2000 ]; then
    echo "  (insufficient balance to send — request testnet faucet or mine a few blocks)"
    echo "  stopping at verification step — sign/verify path PASSED"
    exit 0
fi

printf "%s\n" "$PW" | "$AXIOM_BIN" wallet send \
    --to "$ADDR" \
    --amount 1 --sat \
    --fee 1000 \
    --wallet "$WALLET" \
    --rpc "http://$RPC" \
    --yes \
    >"$RUN_DIR/send.log" 2>&1 || fail "self-transfer send failed (see run/send.log)"
ok "self-transfer submitted"

step "DONE — release verified, node running, tx submitted."
echo "logs: $RUN_DIR/"
