@echo off
REM Copyright (c) 2026 Kantoshi Miyamura
REM
REM install.bat - Install Axiom Network on Windows
REM
REM Copies binaries to %LOCALAPPDATA%\Axiom and adds to PATH.
REM Creates data directory and default config.
REM All private keys stay on YOUR device.

setlocal enabledelayedexpansion

set "INSTALL_DIR=%LOCALAPPDATA%\Axiom\bin"
set "DATA_DIR=%APPDATA%\axiom"

echo.
echo ========================================================
echo          Axiom Network - Windows Installer
echo ========================================================
echo.
echo   Install to: %INSTALL_DIR%
echo   Data dir:   %DATA_DIR%
echo.

REM ── Create directories ──────────────────────────────────────

echo   [1/5] Creating directories...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\blocks" mkdir "%DATA_DIR%\blocks"
if not exist "%DATA_DIR%\chainstate" mkdir "%DATA_DIR%\chainstate"
if not exist "%DATA_DIR%\keystore" mkdir "%DATA_DIR%\keystore"
if not exist "%DATA_DIR%\logs" mkdir "%DATA_DIR%\logs"
echo          Done.

REM ── Copy binaries ───────────────────────────────────────────

echo   [2/5] Installing binaries...

set "SRC_DIR=%~dp0"

for %%B in (axiom.exe axiom-node.exe axiom-keygen.exe axiom-bump-fee.exe) do (
    if exist "%SRC_DIR%%%B" (
        copy /Y "%SRC_DIR%%%B" "%INSTALL_DIR%\%%B" >nul 2>&1
        echo          + %%B
    ) else (
        echo          - %%B not found, skipping
    )
)

REM ── Write default config ────────────────────────────────────

echo   [3/5] Writing default configuration...

if not exist "%DATA_DIR%\axiom.conf" (
    (
        echo # Axiom Network Configuration
        echo network = "mainnet"
        echo rpc_bind = "127.0.0.1:8332"
        echo p2p_bind = "0.0.0.0:9000"
        echo log_level = "info"
    ) > "%DATA_DIR%\axiom.conf"
    echo          %DATA_DIR%\axiom.conf
) else (
    echo          Config already exists, skipping.
)

REM ── Add to PATH ─────────────────────────────────────────────

echo   [4/5] Checking PATH...

echo %PATH% | findstr /I /C:"%INSTALL_DIR%" >nul 2>&1
if errorlevel 1 (
    echo          Adding %INSTALL_DIR% to user PATH...
    setx PATH "%PATH%;%INSTALL_DIR%" >nul 2>&1
    if errorlevel 1 (
        echo          Could not update PATH automatically.
        echo          Please add this directory to your PATH manually:
        echo            %INSTALL_DIR%
    ) else (
        echo          PATH updated. Restart your terminal to use 'axiom' command.
    )
) else (
    echo          Already in PATH.
)

REM ── Create desktop shortcuts ────────────────────────────────

echo   [5/5] Creating start menu shortcuts...

set "SHORTCUT_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Axiom Network"
if not exist "%SHORTCUT_DIR%" mkdir "%SHORTCUT_DIR%"

REM Create a simple batch launcher in Start Menu
(
    echo @echo off
    echo title Axiom Network
    echo "%INSTALL_DIR%\axiom.exe" start
    echo pause
) > "%SHORTCUT_DIR%\Start Axiom Node.bat"

(
    echo @echo off
    echo title Axiom Miner
    echo "%INSTALL_DIR%\axiom.exe" start --mine
    echo pause
) > "%SHORTCUT_DIR%\Start Mining.bat"

(
    echo @echo off
    echo title Axiom Wallet
    echo "%INSTALL_DIR%\axiom.exe" wallet create
    echo pause
) > "%SHORTCUT_DIR%\Create Wallet.bat"

echo          Start Menu shortcuts created.

REM ── Done ────────────────────────────────────────────────────

echo.
echo ========================================================
echo   Installation complete!
echo ========================================================
echo.
echo   Next steps:
echo     1. Open a NEW terminal (cmd or PowerShell)
echo     2. axiom init              First-run setup
echo     3. axiom wallet create     Create your wallet
echo     4. axiom start             Run the node
echo     5. axiom start --mine      Start mining
echo.
echo   All private keys stay on YOUR device.
echo   Nothing leaves your machine.
echo.
pause
