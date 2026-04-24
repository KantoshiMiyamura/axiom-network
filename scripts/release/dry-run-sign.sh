#!/usr/bin/env bash
# Axiom Network — DRY RUN of the release-signing path.
#
# ⚠  DRY RUN — DOES NOT SIGN WITH THE REAL RELEASE KEY.
#
# Generates a throwaway minisign keypair, signs the artifacts with it, and
# walks through the verify path end-to-end. Use this to confirm the signing
# workflow and user-verification workflow are coherent before you commit
# your real release key.
#
# This script does NOT:
#   - touch your real ~/.minisign or ~/.gnupg
#   - create or push any git tag
#   - create or modify any GitHub release
#
# Outputs land in scripts/release/.dryrun/ (gitignored).
#
# INVOCATION:
#   scripts/release/dry-run-sign.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DRYDIR="$SCRIPT_DIR/.dryrun"
DIST="$DRYDIR/dist"
KEYS="$DRYDIR/keys"

for cmd in minisign sha256sum; do
    command -v "$cmd" >/dev/null || { echo "missing: $cmd" >&2; exit 1; }
done

rm -rf "$DRYDIR"
mkdir -p "$DIST" "$KEYS"

echo "── Generating throwaway minisign keypair in $KEYS ──"
# -W = no password (DRY RUN ONLY; never use -W for a real release key)
minisign -G -W -p "$KEYS/test.pub" -s "$KEYS/test.key"

echo "── Copying release binaries to $DIST for hashing ──"
for f in axiom-node axiom axiom-keygen axiom-sign axiom-bump-fee; do
    for ext in "" ".exe"; do
        src="$PROJECT_ROOT/target/release/$f$ext"
        [ -f "$src" ] && cp "$src" "$DIST/"
    done
done
ls -l "$DIST"

echo "── Signing (dry-run) with throwaway key ──"
AXIOM_TAG="v0.0.0-dryrun" \
AXIOM_GPG_KEY_ID="SKIP" \
AXIOM_MINISIGN_SECKEY="$KEYS/test.key" \
AXIOM_MINISIGN_PASSWORD="" \
AXIOM_ARTIFACTS_DIR="$DIST" \
    bash -c '
set -euo pipefail
cd "$AXIOM_ARTIFACTS_DIR"
find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name "*.minisig" -print0 \
    | sort -z | xargs -0 sha256sum >SHA256SUMS
minisign -S -s "$AXIOM_MINISIGN_SECKEY" -m SHA256SUMS -x SHA256SUMS.minisig \
    -c "axiom-network DRYRUN" -t "axiom-network DRYRUN" <<<""
'

echo "── Verifying (dry-run) the signed SHA256SUMS ──"
minisign -V -p "$KEYS/test.pub" -m "$DIST/SHA256SUMS" -x "$DIST/SHA256SUMS.minisig"

echo
echo "── Verifying every binary against SHA256SUMS ──"
(cd "$DIST" && sha256sum -c SHA256SUMS)

echo
echo "── Dry-run OK ──"
echo "Throwaway key:  $KEYS/test.pub"
echo "Signed sums:    $DIST/SHA256SUMS"
echo "Signature:      $DIST/SHA256SUMS.minisig"
echo
echo "DO NOT PUBLISH THESE SIGNATURES — the private key is a throwaway."
echo "Use scripts/release/sign-release.sh with your real key for a real release."
