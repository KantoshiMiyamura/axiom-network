#!/usr/bin/env bash
# verify-release.sh — Verify downloaded Axiom Network release artifacts.
#
# This script is for END USERS who have downloaded a release and want to prove
# the files are authentic and unmodified. It does not require any secrets.
#
# Usage:
#   bash scripts/verify-release.sh <dir-containing-downloaded-files>
#
# The directory must contain at minimum:
#   SHA256SUMS
#   SHA256SUMS.minisig
# and the artifacts named inside SHA256SUMS.
#
# The minisign public key is expected at docs/minisign.pub (bundled in the repo)
# OR provided via env var MINISIGN_PUBKEY pointing at a local .pub file.

set -euo pipefail

log() { echo "[verify] $*"; }
die() { echo "[verify] ERROR: $*" >&2; exit 1; }

DIR="${1:-}"
[[ -n "$DIR" && -d "$DIR" ]] || die "usage: $0 <dir>"

cd "$DIR"

[[ -f SHA256SUMS ]]          || die "missing SHA256SUMS in $DIR"
[[ -f SHA256SUMS.minisig ]]  || die "missing SHA256SUMS.minisig in $DIR"

# Locate the public key.
PUBKEY="${MINISIGN_PUBKEY:-}"
if [[ -z "$PUBKEY" ]]; then
    for candidate in docs/minisign.pub ../docs/minisign.pub ../../docs/minisign.pub; do
        if [[ -f "$candidate" ]]; then PUBKEY="$(cd "$(dirname "$candidate")" && pwd)/$(basename "$candidate")"; break; fi
    done
fi
[[ -n "$PUBKEY" && -f "$PUBKEY" ]] || die "minisign public key not found — set MINISIGN_PUBKEY=<path> or place it at docs/minisign.pub"

log "public key: $PUBKEY"

# 1. Verify the minisign signature on SHA256SUMS.
command -v minisign >/dev/null 2>&1 || die "minisign not installed. See: https://jedisct1.github.io/minisign/"
log "verifying SHA256SUMS signature..."
minisign -Vm SHA256SUMS -p "$PUBKEY"

# 2. Verify every file listed in SHA256SUMS matches.
log "verifying artifact hashes..."
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c SHA256SUMS
else
    die "need sha256sum or shasum on PATH"
fi

log ""
log "OK — release artifacts are authentic and unmodified."
