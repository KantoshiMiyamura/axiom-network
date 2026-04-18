#!/usr/bin/env bash
# Copyright (c) 2026 Kantoshi Miyamura
#
# build-release.sh — Build release binaries for local smoke-testing.
#
# This script mirrors the matrix in .github/workflows/release.yml so you can
# validate a tag locally before pushing it. It does NOT produce artifacts that
# should be published — publication always happens through CI.
#
# Usage:
#   bash scripts/build-release.sh                          # native target
#   bash scripts/build-release.sh --target <TRIPLE>        # cross target
#
# Outputs:
#   release/
#     axiom[.exe]            — CLI entrypoint (from axiom-cli crate)
#     axiom-node[.exe]
#     axiom-keygen[.exe]
#     axiom-sign[.exe]
#     axiom-bump-fee[.exe]
#     SHA256SUMS
#     BUILD_INFO.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_DIR="$REPO_ROOT/release"

NATIVE_TARGET="$(rustc -vV | grep 'host:' | awk '{print $2}')"
TARGET="${TARGET:-$NATIVE_TARGET}"

# Binary names produced by the build (not crate names). axiom-cli crate → axiom.
BINARIES=("axiom" "axiom-node" "axiom-keygen" "axiom-sign" "axiom-bump-fee")
# Cargo packages to -p into the build. axiom is produced by axiom-cli.
PACKAGES=("axiom-cli" "axiom-node" "axiom-keygen" "axiom-sign" "axiom-bump-fee")

for arg in "$@"; do
    case "$arg" in
        --target=*) TARGET="${arg#--target=}" ;;
        --target)   shift; TARGET="$1" ;;
    esac
done

log() { echo "[build-release] $*"; }
die() { echo "[build-release] ERROR: $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

require_cmd rustc
require_cmd cargo
require_cmd sha256sum

RUSTC_VERSION="$(rustc --version)"
PINNED_VERSION="1.93.1"
if [[ "$RUSTC_VERSION" != *"$PINNED_VERSION"* ]]; then
    die "toolchain mismatch: expected $PINNED_VERSION, got $RUSTC_VERSION. Run: rustup toolchain install $PINNED_VERSION"
fi

log "repo:   $REPO_ROOT"
log "target: $TARGET"
log "rust:   $RUSTC_VERSION"

rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

cd "$REPO_ROOT"

# Optional: cargo-audit if installed. Non-blocking here; CI is authoritative.
if command -v cargo-audit >/dev/null 2>&1; then
    log "running cargo audit (advisory)..."
    cargo audit || log "WARNING: cargo audit reported issues — CI will block on these"
fi

CARGO_ARGS=(build --release)
for pkg in "${PACKAGES[@]}"; do CARGO_ARGS+=(-p "$pkg"); done
if [[ "$TARGET" != "$NATIVE_TARGET" ]]; then
    CARGO_ARGS+=(--target "$TARGET")
fi

log "building: cargo ${CARGO_ARGS[*]}"
cargo "${CARGO_ARGS[@]}"

BIN_EXT=""
[[ "$TARGET" == *"windows"* ]] && BIN_EXT=".exe"

if [[ "$TARGET" == "$NATIVE_TARGET" ]]; then
    BUILD_DIR="$REPO_ROOT/target/release"
else
    BUILD_DIR="$REPO_ROOT/target/$TARGET/release"
fi

for bin in "${BINARIES[@]}"; do
    SRC="$BUILD_DIR/${bin}${BIN_EXT}"
    DST="$RELEASE_DIR/${bin}${BIN_EXT}"
    [[ -f "$SRC" ]] || die "missing binary: $SRC"
    cp "$SRC" "$DST"
    log "  -> $DST"
done

cd "$RELEASE_DIR"
sha256sum * > SHA256SUMS
log "SHA256SUMS:"
cat SHA256SUMS

cat > BUILD_INFO.txt <<EOF
Axiom Network local smoke build
===============================
Date:       $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Target:     $TARGET
Rust:       $RUSTC_VERSION
Git commit: $(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo "N/A")
Git tag:    $(cd "$REPO_ROOT" && git describe --tags --exact-match 2>/dev/null || echo "(none)")
Packages:   ${PACKAGES[*]}
Binaries:   ${BINARIES[*]}
NOTE:       This is a LOCAL smoke build — do not publish. CI is authoritative.
EOF

log ""
log "done. artifacts in: $RELEASE_DIR/"
ls -lh "$RELEASE_DIR/"
