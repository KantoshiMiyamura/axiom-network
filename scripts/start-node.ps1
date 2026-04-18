# Start a single Axiom Network testnet node
param(
    [int]$NodeId = 0
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

# Configuration
$Network = "test"
$DataDir = Join-Path $ProjectRoot "testnet\data\node$NodeId"
$RpcPort = 8332 + $NodeId
$P2pPort = 9000 + $NodeId

# Create directories
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $ProjectRoot "testnet\logs") | Out-Null

Write-Host "Starting Axiom Network Node $NodeId"
Write-Host "Network: $Network"
Write-Host "Data Dir: $DataDir"
Write-Host "RPC Port: $RpcPort"
Write-Host "P2P Port: $P2pPort"
Write-Host ""

Write-Host "⚠️  Node binary not yet implemented" -ForegroundColor Yellow
Write-Host ""
Write-Host "To implement:"
Write-Host "1. Create src/main.rs in axiom-node crate"
Write-Host "2. Add [[bin]] section to Cargo.toml"
Write-Host "3. Implement CLI argument parsing"
Write-Host "4. Start node with RPC server"
Write-Host ""
Write-Host "For now, use programmatic API in Rust"
