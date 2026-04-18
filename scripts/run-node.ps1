# Run Axiom Network Node (PowerShell)
# Usage: .\scripts\run-node.ps1 [-Network devnet] [-Mine] [-MinerAddress "..."]

param(
    [string]$Network = "devnet",
    [string]$DataDir = "./data",
    [string]$RpcBind = "127.0.0.1:8332",
    [string]$P2pBind = "0.0.0.0:9000",
    [string]$LogLevel = "info",
    [switch]$Mine,
    [string]$MinerAddress = "",
    [string]$Seeds = "",
    [int]$MiningInterval = 30
)

# Build if needed
if (-not (Test-Path "./target/release/axiom-node.exe")) {
    Write-Host "Building node binary..." -ForegroundColor Yellow
    cargo build --release -p axiom-cli
}

# Prepare arguments
$args = @(
    "--network", $Network,
    "--data-dir", $DataDir,
    "--rpc-bind", $RpcBind,
    "--p2p-bind", $P2pBind,
    "--log-level", $LogLevel,
    "--mining-interval", $MiningInterval
)

if ($Mine) {
    $args += "--mine"
}

if ($MinerAddress) {
    $args += "--miner-address", $MinerAddress
}

if ($Seeds) {
    $args += "--seeds", $Seeds
}

# Run node
Write-Host "Starting Axiom Network Node..." -ForegroundColor Green
Write-Host "Network: $Network"
Write-Host "Data directory: $DataDir"
Write-Host "RPC: $RpcBind"
Write-Host "P2P: $P2pBind"
Write-Host ""

& "./target/release/axiom-node.exe" @args
