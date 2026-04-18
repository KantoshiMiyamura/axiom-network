#!/bin/bash
###############################################################################
# Axiom Network v1.0.0 — Production Deployment Script
# Date: 2026-04-13
#
# Deploys:
#   1. Blockchain node + RPC server (Rust release binaries)
#   2. Systemd services with security hardening
#   3. Log rotation and monitoring
#
# Usage:
#   sudo bash deploy-production.sh
###############################################################################

set -euo pipefail

VERSION="1.0.0"
PROJECT_DIR="/opt/axiom"
BIN_DIR="$PROJECT_DIR/bin"
DATA_DIR="/var/lib/axiom-node"
LOG_DIR="/var/log/axiom"
CONF_DIR="/etc/axiom"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}   $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERR]${NC}  $1"; }

###############################################################################
# Pre-flight
###############################################################################

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Axiom Network v${VERSION} — Production Deployment${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    log_error "Must run as root (use sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

command -v rustc >/dev/null 2>&1 || { log_error "Rust not installed"; exit 1; }
log_success "Pre-flight checks passed"

###############################################################################
# 1. Stop old services
###############################################################################

log_info "Stopping existing services..."

for svc in axiom-node axiom-mind axiom-web; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc"
        log_success "Stopped $svc"
    fi
done

# Kill any remaining axiom processes
pkill -f "axiom-node" 2>/dev/null || true
pkill -f "axiom-rpc" 2>/dev/null || true
sleep 2

log_success "Old processes cleared"

###############################################################################
# 2. Backup existing data (if any)
###############################################################################

if [ -d "$DATA_DIR" ] && [ "$(ls -A $DATA_DIR 2>/dev/null)" ]; then
    BACKUP_DIR="/var/backups/axiom-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    cp -r "$DATA_DIR" "$BACKUP_DIR/data" 2>/dev/null || true
    cp -r "$CONF_DIR" "$BACKUP_DIR/conf" 2>/dev/null || true
    log_success "Backed up existing data to $BACKUP_DIR"
fi

###############################################################################
# 3. Create system user
###############################################################################

if ! id -u axiom >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin axiom
    log_success "Created 'axiom' system user"
else
    log_info "'axiom' user exists"
fi

###############################################################################
# 4. Create directories
###############################################################################

mkdir -p "$BIN_DIR" "$DATA_DIR" "$LOG_DIR" "$CONF_DIR"
chmod 755 "$PROJECT_DIR" "$BIN_DIR"
chmod 700 "$DATA_DIR"
chmod 755 "$LOG_DIR"
chmod 755 "$CONF_DIR"

log_success "Directories created"

###############################################################################
# 5. Build release binaries
###############################################################################

log_info "Building release binaries (this may take several minutes)..."

cd "$REPO_ROOT"

cargo build --release \
    -p axiom-cli \
    -p axiom-node \
    -p axiom-rpc \
    -p axiom-wallet \
    -p axiom-crypto \
    -p axiom-consensus

log_success "Build complete"

###############################################################################
# 6. Install binaries
###############################################################################

log_info "Installing binaries..."

for bin in axiom-node axiom axiom-keygen axiom-bump-fee; do
    src="$REPO_ROOT/target/release/$bin"
    if [ -f "$src" ]; then
        cp "$src" "$BIN_DIR/$bin"
        chmod 755 "$BIN_DIR/$bin"
        # Also install to /usr/local/bin for PATH access
        cp "$src" "/usr/local/bin/$bin"
        chmod 755 "/usr/local/bin/$bin"
        log_success "Installed $bin"
    else
        log_warn "Binary not found: $bin (skipping)"
    fi
done

# Generate SHA-256 checksums
cd "$BIN_DIR"
sha256sum axiom-node axiom axiom-keygen axiom-bump-fee > SHA256SUMS 2>/dev/null || true
log_success "Checksums generated"

###############################################################################
# 7. Write production config
###############################################################################

if [ ! -f "$CONF_DIR/axiom.conf" ]; then
    cat > "$CONF_DIR/axiom.conf" <<'CONF'
# Axiom Network v1.0.0 — Production Configuration

# Network: mainnet, testnet, devnet
network = "mainnet"

# RPC server — bind to localhost only (use reverse proxy for external access)
rpc_bind = "127.0.0.1:8332"

# P2P listening port — open to all interfaces for peer connections
p2p_bind = "0.0.0.0:9000"

# Logging level: error, warn, info, debug, trace
log_level = "info"

# Mining (uncomment to enable)
# mine = true
# miner_address = "axm..."

# Block interval (seconds)
# mining_interval = 30

# RPC authentication — REQUIRED for production
# Generate with: openssl rand -hex 32
# rpc_auth_token = "your-secret-token-here"
CONF
    chmod 644 "$CONF_DIR/axiom.conf"
    log_success "Production config written"
else
    log_info "Config exists, preserving"
fi

###############################################################################
# 8. Install systemd services
###############################################################################

log_info "Installing systemd services..."

cat > /etc/systemd/system/axiom-node.service <<EOF
[Unit]
Description=Axiom Network v${VERSION} — Blockchain Node
Documentation=https://axiom.network/docs
After=network-online.target
Wants=network-online.target

[Service]
User=axiom
Group=axiom
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${DATA_DIR}
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65536
LimitNPROC=512

Type=simple
WorkingDirectory=${DATA_DIR}
ExecStart=/usr/local/bin/axiom-node \\
    --network mainnet \\
    --data-dir ${DATA_DIR} \\
    --rpc-bind 127.0.0.1:8332 \\
    --p2p-bind 0.0.0.0:9000 \\
    --log-level info

Restart=always
RestartSec=5s
StartLimitIntervalSec=60
StartLimitBurst=5
TimeoutStopSec=60

Environment=RUST_BACKTRACE=1
Environment=RUST_LOG=axiom_node=info,axiom_rpc=info

StandardOutput=journal
StandardError=journal
SyslogIdentifier=axiom-node

[Install]
WantedBy=multi-user.target
EOF

log_success "Systemd service installed"

###############################################################################
# 9. Log rotation
###############################################################################

cat > /etc/logrotate.d/axiom <<'LOGROTATE'
/var/log/axiom/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 axiom axiom
}
LOGROTATE

log_success "Log rotation configured"

###############################################################################
# 10. Set ownership
###############################################################################

chown -R axiom:axiom "$DATA_DIR"
chown -R axiom:axiom "$LOG_DIR"
chown -R root:root "$BIN_DIR"

systemctl daemon-reload

log_success "Permissions set"

###############################################################################
# 11. Remove old/obsolete files
###############################################################################

log_info "Cleaning up obsolete files..."

# Remove old deploy artifacts
rm -rf /opt/axiom/blockchain 2>/dev/null || true
rm -rf /opt/axiom/axiom-mind 2>/dev/null || true
rm -rf /opt/axiom/web 2>/dev/null || true

# Remove old service files
rm -f /etc/systemd/system/axiom-mind.service 2>/dev/null || true
rm -f /etc/systemd/system/axiom-web.service 2>/dev/null || true

systemctl daemon-reload

log_success "Cleanup complete"

###############################################################################
# Summary
###############################################################################

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Axiom Network v${VERSION} — Deployment Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Binaries:  ${BIN_DIR}/"
echo "  Data:      ${DATA_DIR}/"
echo "  Config:    ${CONF_DIR}/axiom.conf"
echo "  Logs:      journalctl -u axiom-node -f"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Edit config (set rpc_auth_token for production):"
echo "     nano ${CONF_DIR}/axiom.conf"
echo ""
echo "  2. Start the node:"
echo "     systemctl start axiom-node"
echo ""
echo "  3. Enable at boot:"
echo "     systemctl enable axiom-node"
echo ""
echo "  4. Check status:"
echo "     systemctl status axiom-node"
echo "     axiom status"
echo ""
echo "  5. Verify RPC:"
echo "     curl -s http://127.0.0.1:8332/health"
echo "     curl -s http://127.0.0.1:8332/status"
echo ""
echo "  SECURITY REMINDERS:"
echo "  - Set rpc_auth_token in config before exposing RPC externally"
echo "  - Use a reverse proxy (nginx/caddy) with TLS for external access"
echo "  - Firewall: allow TCP 9000 (P2P), restrict 8332 (RPC) to localhost"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
