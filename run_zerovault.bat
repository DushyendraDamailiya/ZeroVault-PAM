@echo off
title ZeroVault PAM - Privileged Access Management Gateway
color 0B
echo =======================================================================
echo     ZEROVAULT PAM - ZERO-TRUST ACCESS VAULT & SSH PROXY GATEWAY
echo =======================================================================
echo.
echo [*] Checking Python environment...
python --version
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b 1
)

echo [*] Initializing ZeroVault Cryptographic Vault...
python -c "from pam_backend.database import init_db; init_db(); print('[+] Database & Genesis Block initialized.')"

echo [*] Starting ZeroVault PAM Web Console on http://localhost:5005 ...
echo [*] Starting Live SSH Protocol Proxy on Port 2222 ...
start "" http://localhost:5005
python -m pam_backend.app
pause
