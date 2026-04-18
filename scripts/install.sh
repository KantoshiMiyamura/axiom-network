#!/usr/bin/env bash
# Copyright (c) 2026 Kantoshi Miyamura
#
# install.sh — Install Axiom Network binaries on Linux/macOS.
#
# Usage:
#   bash install.sh                   # install to ~/.local/bin (default)
#   bash install.sh --prefix /usr/local  # install to /usr/local/bin
#   bash install.sh --uninstall       # remove installed binaries
#
# This script:
#   1. Copies binaries to the install prefix
#   2. Creates default data directory
#   3. Writes example config
#   4. Adds install dir to PATH if needed
#   5. Runs `axiom init` for first-run setup

set -euo pipefail

PREFIX="${HOME}/.local"
INSTALL_DIR=""
DATA_DIR="${HOME}/.axiom"
UNINSTALL=false

BINARIES=("axiom" "axiom-node" "axiom-keygen" "axiom-bump-fee")

# ── Parse Arguments ───────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)     PREFIX="$2"; shift 2 ;;
        --prefix=*)   PREFIX="${1#--prefix=}"; shift ;;
        --uninstall)  UNINSTALL=true; shift ;;
        --help|-h)    show_help; exit 0 ;;
        *)            shift ;;
    esac
done

INSTALL_DIR="${PREFIX}/bin"

# ── Functions ─────────────────────────────────────────────────────────────────

log()  { echo "[axiom] $*"; }
warn() { echo "[axiom] WARNING: $*" >&2; }
die()  { echo "[axiom] ERROR: $*" >&2; exit 1; }

show_help() {
    echo "Axiom Network Installer"
    echo ""
    echo "Usage: bash install.sh [options]"
    echo ""
    echo "Options:"
    echo "  --prefix DIR    Install prefix (default: ~/.local)"
    echo "  --uninstall     Remove installed binaries"
    echo "  --help          Show this help"
}

# ── Uninstall ─────────────────────────────────────────────────────────────────

if $UNINSTALL; then
    log "Uninstalling Axiom Network binaries..."
    for bin in "${BINARIES[@]}"; do
        target="$INSTALL_DIR/$bin"
        if [[ -f "$target" ]]; then
            rm -f "$target"
            log "  Removed: $target"
        fi
    done
    log ""
    log "Binaries removed. Data directory at ${DATA_DIR} was NOT deleted."
    log "To remove all data: rm -rf ${DATA_DIR}"
    exit 0
fi

# ── Detect Source Directory ───────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if binaries are in the same directory (extracted archive)
# or in parent directory (running from scripts/ in repo)
if [[ -f "$SCRIPT_DIR/axiom" ]]; then
    SRC_DIR="$SCRIPT_DIR"
elif [[ -f "$SCRIPT_DIR/../axiom" ]]; then
    SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [[ -f "$SCRIPT_DIR/../target/release/axiom" ]]; then
    SRC_DIR="$SCRIPT_DIR/../target/release"
else
    die "Cannot find axiom binary. Run from the extracted archive directory."
fi

# ── Install ───────────────────────────────────────────────────────────────────

echo ""
echo "========================================================"
echo "         Axiom Network — Installer"
echo "========================================================"
echo ""
echo "  Install to: ${INSTALL_DIR}"
echo "  Data dir:   ${DATA_DIR}"
echo ""

# Create install directory
mkdir -p "$INSTALL_DIR"

# Copy binaries
log "Installing binaries..."
for bin in "${BINARIES[@]}"; do
    src="$SRC_DIR/$bin"
    dst="$INSTALL_DIR/$bin"
    if [[ -f "$src" ]]; then
        cp "$src" "$dst"
        chmod +x "$dst"
        log "  + $bin → $dst"
    else
        warn "Binary not found: $src (skipping)"
    fi
done

# ── Data Directory ────────────────────────────────────────────────────────────

log "Setting up data directory..."
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/blocks"
mkdir -p "$DATA_DIR/chainstate"
mkdir -p "$DATA_DIR/keystore"
mkdir -p "$DATA_DIR/logs"
log "  ${DATA_DIR}/"

# Write example config if none exists
if [[ ! -f "$DATA_DIR/axiom.conf" ]]; then
    cat > "$DATA_DIR/axiom.conf" <<'CONF'
# Axiom Network Configuration
network = "mainnet"
rpc_bind = "127.0.0.1:8332"
p2p_bind = "0.0.0.0:9000"
log_level = "info"
CONF
    log "  Wrote default config: ${DATA_DIR}/axiom.conf"
fi

# ── PATH Check ────────────────────────────────────────────────────────────────

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    log ""
    log "Add to your shell profile:"
    log ""

    SHELL_NAME="$(basename "$SHELL" 2>/dev/null || echo "bash")"
    case "$SHELL_NAME" in
        zsh)
            PROFILE="~/.zshrc"
            ;;
        fish)
            PROFILE="~/.config/fish/config.fish"
            ;;
        *)
            PROFILE="~/.bashrc"
            ;;
    esac

    if [[ "$SHELL_NAME" == "fish" ]]; then
        log "  fish_add_path ${INSTALL_DIR}"
    else
        log "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
    log ""
    log "Then restart your terminal or run: source ${PROFILE}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "========================================================"
echo "  Installation complete!"
echo "========================================================"
echo ""
echo "  Next steps:"
echo "    1. axiom wallet create     Create your wallet"
echo "    2. axiom start             Run the node"
echo "    3. axiom start --mine      Start mining"
echo "    4. axiom status            Check node status"
echo ""
echo "  All private keys stay on YOUR device."
echo "  Nothing leaves your machine."
echo ""
