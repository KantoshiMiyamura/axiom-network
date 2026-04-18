#!/usr/bin/env bash
# Copyright (c) 2026 Kantoshi Miyamura
#
# build-dist.sh — Build production distribution packages for Axiom Network.
#
# Produces versioned, checksummed release archives ready for download.
#
# Usage:
#   bash scripts/build-dist.sh                          # native platform
#   bash scripts/build-dist.sh --target x86_64-pc-windows-msvc
#   bash scripts/build-dist.sh --target x86_64-unknown-linux-gnu
#   bash scripts/build-dist.sh --target x86_64-apple-darwin
#   bash scripts/build-dist.sh --target aarch64-apple-darwin
#
# Output:
#   dist/
#     axiom-v0.1.0-x86_64-pc-windows-msvc/
#       axiom.exe
#       axiom-node.exe
#       axiom-keygen.exe
#       axiom-bump-fee.exe
#       axiom.conf.example
#       LICENSE
#       README.txt
#     axiom-v0.1.0-x86_64-pc-windows-msvc.zip        (Windows)
#     axiom-v0.1.0-x86_64-unknown-linux-gnu.tar.gz    (Linux)
#     axiom-v0.1.0-x86_64-apple-darwin.tar.gz         (macOS)
#     SHA256SUMS

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Version from workspace Cargo.toml
VERSION=$(grep -m1 'version = ' "$REPO_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/' | head -1)
# Fallback: read from axiom-cli
if [[ -z "$VERSION" || "$VERSION" == *"workspace"* ]]; then
    VERSION=$(grep 'version.workspace' "$REPO_ROOT/crates/axiom-cli/Cargo.toml" >/dev/null 2>&1 && \
              grep -m1 '^version = ' "$REPO_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/' || echo "0.1.0")
fi
VERSION="${VERSION:-0.1.0}"

NATIVE_TARGET="$(rustc -vV | grep 'host:' | awk '{print $2}')"
TARGET="${TARGET:-$NATIVE_TARGET}"

DIST_DIR="$REPO_ROOT/dist"

# All binaries to include in the distribution
BINARIES=("axiom" "axiom-node" "axiom-keygen" "axiom-bump-fee")

# ── Parse Arguments ───────────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --target=*)  TARGET="${arg#--target=}" ;;
        --version=*) VERSION="${arg#--version=}" ;;
    esac
done

# Shift past consumed --target / --version flag-value pairs
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)  TARGET="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        *)         shift ;;
    esac
done

PACKAGE_NAME="axiom-v${VERSION}-${TARGET}"
PACKAGE_DIR="$DIST_DIR/$PACKAGE_NAME"

# ── Functions ─────────────────────────────────────────────────────────────────

log()  { echo "[build-dist] $*"; }
die()  { echo "[build-dist] ERROR: $*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# ── Preflight ─────────────────────────────────────────────────────────────────

require_cmd rustc
require_cmd cargo

RUSTC_VERSION="$(rustc --version)"
GIT_HASH="$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
BUILD_DATE="$(date -u '+%Y-%m-%d')"

log ""
log "============================================================"
log "  Axiom Network — Distribution Builder"
log "============================================================"
log ""
log "  Version:  v${VERSION}"
log "  Target:   ${TARGET}"
log "  Rust:     ${RUSTC_VERSION}"
log "  Commit:   ${GIT_HASH}"
log "  Date:     ${BUILD_DATE}"
log ""

# ── Clean ─────────────────────────────────────────────────────────────────────

rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"

# ── Build Release Binaries ────────────────────────────────────────────────────

log "Building release binaries..."

CARGO_ARGS=(build --release)

# All binaries come from axiom-cli crate
CARGO_ARGS+=(-p axiom-cli)

if [[ "$TARGET" != "$NATIVE_TARGET" ]]; then
    log "Cross-compiling for $TARGET"
    CARGO_ARGS+=(--target "$TARGET")
fi

cd "$REPO_ROOT"
cargo "${CARGO_ARGS[@]}"

log "Build complete."

# ── Collect Binaries ──────────────────────────────────────────────────────────

BIN_EXT=""
if [[ "$TARGET" == *"windows"* ]]; then
    BIN_EXT=".exe"
fi

if [[ "$TARGET" == "$NATIVE_TARGET" ]]; then
    BUILD_DIR="$REPO_ROOT/target/release"
else
    BUILD_DIR="$REPO_ROOT/target/$TARGET/release"
fi

for bin in "${BINARIES[@]}"; do
    SRC="$BUILD_DIR/${bin}${BIN_EXT}"
    DST="$PACKAGE_DIR/${bin}${BIN_EXT}"
    if [[ -f "$SRC" ]]; then
        cp "$SRC" "$DST"
        # Strip debug symbols on non-Windows (reduces binary size ~60%)
        if [[ "$TARGET" != *"windows"* ]] && command -v strip >/dev/null 2>&1; then
            strip "$DST" 2>/dev/null || true
        fi
        log "  + ${bin}${BIN_EXT} ($(du -h "$DST" | cut -f1))"
    else
        die "Binary not found: $SRC"
    fi
done

# ── Include Support Files ─────────────────────────────────────────────────────

log "Adding support files..."

# Example config
cat > "$PACKAGE_DIR/axiom.conf.example" <<'CONF'
# Axiom Network Configuration
# Copy to axiom.conf and edit as needed.

# Network: mainnet, testnet, devnet
network = "mainnet"

# RPC server (localhost only — safe default)
rpc_bind = "127.0.0.1:8332"

# P2P listening port
p2p_bind = "0.0.0.0:9000"

# Logging level: error, warn, info, debug, trace
log_level = "info"

# Mining (uncomment to enable)
# mine = true
# miner_address = "axm..."

# Block interval in seconds (default: 30)
# mining_interval = 30

# RPC authentication (recommended for non-localhost access)
# rpc_auth_token = "your-secret-token"
CONF

# README
cat > "$PACKAGE_DIR/README.txt" <<README
Axiom Network v${VERSION}
========================

Post-quantum blockchain powered by ML-DSA-87 (NIST FIPS 204).
All private keys stay on your device. Nothing leaves your machine.

QUICK START
-----------

  1. Initialize:        axiom init
  2. Create wallet:     axiom wallet create
  3. Start node:        axiom start
  4. Start mining:      axiom start --mine
  5. Check status:      axiom status
  6. Check balance:     axiom wallet balance
  7. View rewards:      axiom rewards

ALL COMMANDS
------------

  axiom init                    First-run setup (data dir, config, wallet)
  axiom start                   Run the full node
  axiom start --mine            Run node + mine blocks
  axiom wallet create           Create new encrypted wallet
  axiom wallet import           Restore wallet from 24-word seed
  axiom wallet balance          Check wallet balance
  axiom wallet address          Show wallet address
  axiom worker start            Connect mining worker to node
  axiom rewards                 Show block reward schedule
  axiom status                  Query running node status
  axiom version                 Print version info

  axiom-node                    Full node (advanced, direct)
  axiom-keygen                  Generate ML-DSA-87 keypair
  axiom-bump-fee                Replace stuck transaction (RBF)

SECURITY
--------

  - Wallet encrypted with Argon2id + XChaCha20-Poly1305
  - Signatures: ML-DSA-87 (256-bit post-quantum, NIST Category 5)
  - Private keys never leave your device
  - RPC binds to localhost only by default

SYSTEM REQUIREMENTS
-------------------

  Minimum:     2 CPU cores, 4 GB RAM, 10 GB disk
  Recommended: 4+ CPU cores, 8 GB RAM, 50 GB SSD

VERIFY DOWNLOAD
---------------

  Check SHA256SUMS against the hash of your download:
    sha256sum --check SHA256SUMS        (Linux/macOS)
    Get-FileHash <file> -Algorithm SHA256  (Windows PowerShell)

LICENSE
-------

  MIT License. See LICENSE file.

SUPPORT
-------

  GitHub:   https://github.com/axiom-network/axiom
  Discord:  https://discord.gg/axiom-network

README

# License
if [[ -f "$REPO_ROOT/LICENSE" ]]; then
    cp "$REPO_ROOT/LICENSE" "$PACKAGE_DIR/LICENSE"
else
    echo "MIT License" > "$PACKAGE_DIR/LICENSE"
    echo "Copyright (c) 2026 Kantoshi Miyamura" >> "$PACKAGE_DIR/LICENSE"
fi

# Build info manifest
cat > "$PACKAGE_DIR/BUILD_INFO.json" <<MANIFEST
{
  "name": "axiom-network",
  "version": "${VERSION}",
  "target": "${TARGET}",
  "git_commit": "${GIT_HASH}",
  "build_date": "${BUILD_DATE}",
  "rust_version": "${RUSTC_VERSION}",
  "signature_scheme": "ML-DSA-87 (FIPS 204)",
  "binaries": [$(printf '"%s",' "${BINARIES[@]}" | sed 's/,$//')]
}
MANIFEST

# ── Platform-Specific Launchers ──────────────────────────────────────────────

if [[ "$TARGET" == *"windows"* ]]; then
    log "Adding Windows launchers..."

    cat > "$PACKAGE_DIR/START.bat" <<'BAT'
@echo off
title Axiom Network
echo.
echo ========================================================
echo            Axiom Network - Quick Start
echo ========================================================
echo.

REM Check if initialized
if not exist "%APPDATA%\axiom\axiom.conf" (
    echo  First run detected. Running setup...
    echo.
    axiom.exe init
    echo.
)

echo  Starting Axiom node...
echo.
axiom.exe start
pause
BAT

    cat > "$PACKAGE_DIR/MINE.bat" <<'BAT'
@echo off
title Axiom Miner
echo.
echo ========================================================
echo            Axiom Network - Mining
echo ========================================================
echo.

REM Check for wallet
if not exist "%APPDATA%\axiom\wallet.json" (
    echo  No wallet found. Creating one first...
    echo.
    axiom.exe wallet create
    echo.
)

echo  Starting node with mining enabled...
echo.
axiom.exe start --mine
pause
BAT

    cat > "$PACKAGE_DIR/WALLET.bat" <<'BAT'
@echo off
title Axiom Wallet
echo.
echo ========================================================
echo            Axiom Network - Wallet
echo ========================================================
echo.
echo  1. Create new wallet
echo  2. Import from seed phrase
echo  3. Check balance
echo  4. Show address
echo.
set /p choice="  Choose (1-4): "

if "%choice%"=="1" axiom.exe wallet create
if "%choice%"=="2" axiom.exe wallet import
if "%choice%"=="3" axiom.exe wallet balance
if "%choice%"=="4" axiom.exe wallet address

pause
BAT

    cat > "$PACKAGE_DIR/STATUS.bat" <<'BAT'
@echo off
echo.
axiom.exe status
echo.
pause
BAT

fi

# ── Create Archive ────────────────────────────────────────────────────────────

log "Creating distribution archive..."
cd "$DIST_DIR"

if [[ "$TARGET" == *"windows"* ]]; then
    # ZIP for Windows
    ARCHIVE="${PACKAGE_NAME}.zip"
    if command -v zip >/dev/null 2>&1; then
        zip -r "$ARCHIVE" "$PACKAGE_NAME/"
    elif command -v 7z >/dev/null 2>&1; then
        7z a "$ARCHIVE" "$PACKAGE_NAME/"
    else
        # PowerShell fallback (works on Windows with Git Bash)
        powershell -Command "Compress-Archive -Path '${PACKAGE_NAME}' -DestinationPath '${ARCHIVE}'" 2>/dev/null || \
            die "No zip tool found. Install zip, 7z, or use PowerShell."
    fi
else
    # tar.gz for Linux/macOS
    ARCHIVE="${PACKAGE_NAME}.tar.gz"
    tar -czf "$ARCHIVE" "$PACKAGE_NAME/"
fi

log "  Archive: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# ── Checksums ─────────────────────────────────────────────────────────────────

log "Generating checksums..."

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$ARCHIVE" >> SHA256SUMS 2>/dev/null || true
    # Also checksum individual binaries
    for bin in "${BINARIES[@]}"; do
        sha256sum "$PACKAGE_NAME/${bin}${BIN_EXT}" >> SHA256SUMS 2>/dev/null || true
    done
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$ARCHIVE" >> SHA256SUMS 2>/dev/null || true
    for bin in "${BINARIES[@]}"; do
        shasum -a 256 "$PACKAGE_NAME/${bin}${BIN_EXT}" >> SHA256SUMS 2>/dev/null || true
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────

log ""
log "============================================================"
log "  Distribution build complete!"
log "============================================================"
log ""
log "  Package:   ${ARCHIVE}"
log "  Directory: dist/${PACKAGE_NAME}/"
log ""
log "  Contents:"
ls -lh "$PACKAGE_DIR/" | tail -n +2 | while read line; do
    log "    $line"
done
log ""
log "  Checksums:"
if [[ -f SHA256SUMS ]]; then
    grep "$ARCHIVE" SHA256SUMS | while read line; do
        log "    $line"
    done
fi
log ""
log "  To verify: sha256sum --check SHA256SUMS"
log ""
