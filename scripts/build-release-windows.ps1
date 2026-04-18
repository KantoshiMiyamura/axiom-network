# Copyright (c) 2026 Kantoshi Miyamura
#
# build-release-windows.ps1 — Build distributable release binaries on Windows.
#
# Usage:
#   .\scripts\build-release-windows.ps1
#   .\scripts\build-release-windows.ps1 -Target x86_64-pc-windows-msvc
#
# Outputs:
#   release\
#     axiom-node-x86_64-pc-windows-msvc.exe
#     axiom-faucet-x86_64-pc-windows-msvc.exe
#     axiom-stress-x86_64-pc-windows-msvc.exe
#     SHA256SUMS.txt
#     BUILD_INFO.txt

param(
    [string]$Target = "",
    [string[]]$Binaries = @("axiom-node", "axiom-faucet", "axiom-stress")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Configuration ─────────────────────────────────────────────────────────────

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$ReleaseDir = Join-Path $RepoRoot "release"

# Detect native target
$RustcVersion = & rustc -vV 2>&1
$NativeTarget = ($RustcVersion | Select-String "host:").ToString().Split(" ")[1].Trim()
if ($Target -eq "") { $Target = $NativeTarget }

Write-Host "[build-release] Repository: $RepoRoot"
Write-Host "[build-release] Target:     $Target"
Write-Host "[build-release] Binaries:   $($Binaries -join ', ')"

# ── Verify toolchain ──────────────────────────────────────────────────────────

$PinnedVersion = "1.93.1"
$RustcLine = (& rustc --version 2>&1).ToString()
Write-Host "[build-release] Rust:       $RustcLine"

if ($RustcLine -notlike "*$PinnedVersion*") {
    Write-Error "Toolchain mismatch: expected $PinnedVersion but got $RustcLine"
    Write-Error "Run: rustup toolchain install $PinnedVersion"
    exit 1
}

# ── Clean output directory ────────────────────────────────────────────────────

if (Test-Path $ReleaseDir) {
    Remove-Item -Recurse -Force $ReleaseDir
}
New-Item -ItemType Directory -Path $ReleaseDir | Out-Null

# ── Security check ────────────────────────────────────────────────────────────

Write-Host "[build-release] Running cargo audit..."
$AuditCmd = Get-Command "cargo-audit" -ErrorAction SilentlyContinue
if ($AuditCmd) {
    Set-Location $RepoRoot
    & cargo audit
} else {
    Write-Warning "cargo-audit not installed. Skipping dependency security check."
    Write-Warning "Install with: cargo install cargo-audit"
}

# ── Build ─────────────────────────────────────────────────────────────────────

Write-Host "[build-release] Building release binaries..."
Set-Location $RepoRoot

$BuildArgs = @("build", "--release")
foreach ($Bin in $Binaries) {
    $BuildArgs += @("-p", $Bin)
}
if ($Target -ne $NativeTarget) {
    Write-Host "[build-release] Cross-compiling to $Target"
    $BuildArgs += @("--target", $Target)
}

& cargo @BuildArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Cargo build failed"
    exit 1
}

Write-Host "[build-release] Build complete."

# ── Collect binaries ──────────────────────────────────────────────────────────

if ($Target -eq $NativeTarget) {
    $BuildDir = Join-Path $RepoRoot "target\release"
} else {
    $BuildDir = Join-Path $RepoRoot "target\$Target\release"
}

foreach ($Bin in $Binaries) {
    $Src = Join-Path $BuildDir "$Bin.exe"
    $Dst = Join-Path $ReleaseDir "$Bin-$Target.exe"
    if (Test-Path $Src) {
        Copy-Item $Src $Dst
        Write-Host "[build-release] Copied: $Dst"
    } else {
        Write-Warning "Binary not found: $Src (skipping)"
    }
}

# ── Generate checksums ────────────────────────────────────────────────────────

Write-Host "[build-release] Generating SHA256SUMS.txt..."
Set-Location $ReleaseDir

$ChecksumLines = @()
Get-ChildItem -Filter "*.exe" | ForEach-Object {
    $Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    $ChecksumLines += "$Hash  $($_.Name)"
    Write-Host "$Hash  $($_.Name)"
}
$ChecksumLines | Out-File -FilePath "SHA256SUMS.txt" -Encoding ascii

# ── Build info ────────────────────────────────────────────────────────────────

$CargoVersion = (& cargo --version 2>&1).ToString()
$BuildDate    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + " UTC"

try {
    Set-Location $RepoRoot
    $GitCommit = (& git rev-parse HEAD 2>&1).ToString()
} catch {
    $GitCommit = "N/A (not a git repo)"
}

$BuildInfo = @"
Axiom Network Release Build
===========================
Date:       $BuildDate
Target:     $Target
Rust:       $RustcLine
Cargo:      $CargoVersion
Git commit: $GitCommit
Binaries:   $($Binaries -join ', ')
"@

$BuildInfo | Out-File -FilePath (Join-Path $ReleaseDir "BUILD_INFO.txt") -Encoding ascii
Write-Host $BuildInfo

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[build-release] Release artifacts in: $ReleaseDir\"
Get-ChildItem $ReleaseDir | Format-Table Name, Length -AutoSize
Write-Host ""
Write-Host "[build-release] To verify checksums after distribution:"
Write-Host "  Get-Content SHA256SUMS.txt | ForEach-Object {"
Write-Host "    `$hash, `$file = `$_ -split '  '"
Write-Host "    if ((Get-FileHash `$file -Algorithm SHA256).Hash.ToLower() -eq `$hash) { 'OK: ' + `$file } else { 'FAIL: ' + `$file }"
Write-Host "  }"
