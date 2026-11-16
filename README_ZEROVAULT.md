# ZeroVault PAM - Zero-Trust Privileged Access Management & Live SSH Protocol Proxy

![ZeroVault PAM](https://img.shields.io/badge/Architecture-Zero--Trust%20PAM%20%7C%20Bastion%20Proxy-06b6d4?style=for-the-badge)
![Security Standard](https://img.shields.io/badge/Cryptography-AES--256--GCM%20%7C%20600K%20PBKDF2-8b5cf6?style=for-the-badge)
![Tamper Detection](https://img.shields.io/badge/Audit%20Ledger-Merkle%20SHA--256%20Hash%20Chain-10b981?style=for-the-badge)
![Port](https://img.shields.io/badge/SSH%20Proxy-Port%202222-f59e0b?style=for-the-badge)

ZeroVault PAM is a **production-grade, on-premise Privileged Access Management (PAM) vault, Ephemeral Identity Provisioner, and Live SSH Protocol Proxy Gateway** modeled on enterprise systems like **CyberArk Privileged Access Manager**, **Teleport**, and **HashiCorp Boundary**.

It solves the core problem of shared administrative credentials: **engineers and administrators are never given permanent passwords to production servers**. Instead, they receive Just-In-Time (JIT) ephemeral leases, connect through a credentialless proxy on Port 2222, have their keystrokes inspected by a mid-air command firewall, and have their sessions cryptographically recorded in an immutable Merkle hash-chain ledger.

---

## 🎯 The 5 Core Pillars of ZeroVault PAM

1. **AES-256-GCM Envelope Encryption Secret Vault (`vault_crypto.py`):**
   - Stores server master credentials encrypted using an envelope encryption model.
   - Derives a 256-bit Key Encryption Key (KEK) using **PBKDF2-HMAC-SHA256 with 600,000 iterations** (OWASP/NIST standard).
   - Generates a unique 256-bit Data Encryption Key (DEK) per secret, encrypting the secret with AES-256-GCM (12-byte random nonce + 128-bit authentication tag).
   - Never saves or logs plaintext credentials to disk.

2. **Just-In-Time (JIT) Ephemeral Identity Provisioner (`jit_provisioner.py`):**
   - When an engineer requests access for 15 minutes, ZeroVault connects to the target Linux server over SSH.
   - Executes: `sudo useradd -m -s /bin/bash jit_u8492` with a random 24-character password in RAM.
   - Issues a one-time lease token (e.g. `lease_9f8a2b`).
   - The user connects without ever knowing the password.

3. **Live SSH Bastion Reverse Proxy Gateway on Port 2222 (`ssh_proxy_gateway.py`):**
   - Built on custom Paramiko `ServerInterface` with a local 2048-bit RSA Host Key.
   - User connects via standard terminal: `ssh -p 2222 lease_9f8a2b@127.0.0.1`.
   - Bridges client socket $\leftrightarrow$ target Linux server shell with sub-2ms latency.

4. **Mid-Stream Keystroke Interceptor & Command Firewall:**
   - Evaluates keystrokes in real time before Enter (`\r`):
     - **Safe Commands** (`whoami`, `uname -a`, `ls -la`, `df -h`): Forwarded to target shell and logged to audit ledger.
     - **Prohibited Commands** (`cat /etc/shadow`, `rm -rf /`, `sudo su`, `visudo`, `nc -e`, `chmod 777`): Intercepted in mid-air!
     - Sends `Ctrl+C` (`\x03`) to remote server to clear remote buffer.
     - Injects a bright red alert: `[ZEROVAULT PAM FIREWALL] BLOCKED: Command 'cat /etc/shadow' violates Zero-Trust Policy!`.
     - Increments session violation count and logs to tamper-proof audit ledger.

5. **Tamper-Evident Merkle / Blockchain-Style SHA-256 Audit Ledger (`audit_ledger.py`):**
   - Every command, login, logout, and firewall block is chained:
     $$H_i = \text{SHA256}(H_{i-1} \parallel \text{timestamp} \parallel \text{lease\_id} \parallel \text{user} \parallel \text{server} \parallel \text{command} \parallel \text{action} \parallel \text{rule})$$
   - Cryptographic verification walk recalculates all hashes from Genesis Block #0.
   - If an attacker or insider secretly modifies a single database row, the Merkle chain breaks immediately and flags the exact compromised block.

---

## 🏗️ Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│      ENGINEER / ADMIN WORKSTATION (Windows Terminal / PuTTY / CLI)     │
│      Connects with 1-Time Lease Token (NEVER sees real password):      │
│      > ssh -p 2222 lease_9f8a2b@127.0.0.1                             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    │ 1. Live SSH Connection (Port 2222)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        ZEROVAULT PAM ENGINE                            │
│                                                                        │
│   ┌───────────────────────────┐      ┌───────────────────────────────┐ │
│   │ 1. AES-256-GCM Vault      │      │ 2. JIT Ephemeral Provisioner  │ │
│   │ - 600,000 PBKDF2 Iter     │      │ - Paramiko SSH to Target      │ │
│   │ - Envelope DEK Encryption │      │ - Runs: sudo useradd (TTL 15m)│ │
│   └─────────────┬─────────────┘      └───────────────┬───────────────┘ │
│                 │                                    │                 │
│                 ▼                                    ▼                 │
│   ┌──────────────────────────────────────────────────────────────────┐ │
│   │ 3. Live SSH Reverse Proxy & Command Firewall (Port 2222)         │ │
│   │ - Resolves Backspaces/Arrows in line buffer before Enter (\r)    │ │
│   │ - Drops forbidden commands (cat /etc/shadow, rm -rf, sudo su)    │ │
│   └─────────────┬────────────────────────────────────┬───────────────┘ │
│                 │                                    │                 │
│                 ▼                                    ▼                 │
│   ┌───────────────────────────┐      ┌───────────────────────────────┐ │
│   │ 4. Background Daemons     │      │ 5. Tamper-Evident Ledger      │ │
│   │ - TTL Reaper (Every 3s)   │      │ - Merkle SHA-256 Hash Chain   │ │
│   │ - Master Password Rotator │      │ - Real-Time Fraud Detection   │ │
│   └───────────────────────────┘      └───────────────────────────────┘ │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    │ 2. Authenticated Backend SSH Tunnel (Port 22)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│           REAL TARGET PRODUCTION SERVER (Kali Linux VM / WSL2)         │
│   - OpenSSH Server (sshd) on Port 22                                   │
│   - Ephemeral Linux user in /etc/passwd wiped when TTL expires         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 How to Run & Verify

### Option 1: One-Click Windows Launch (Web UI & SSH Proxy)
Double-click `run_zerovault.bat` in the project root:
```cmd
F:\Project 2\run_zerovault.bat
```
*Starts the Web Dashboard on `http://localhost:5005` and launches the live SSH Proxy on Port 2222.*

---

### Option 2: Run the Interactive SSH Terminal & Firewall Simulator
To test credentialless login, command execution, and mid-stream firewall blocking in terminal:
```cmd
run_pam_simulation.bat
```
*(Or run `python simulate_ssh_session.py`)*.

---

### Option 3: Run the Automated Test Suite
To verify that all 13 unit/integration tests pass:
```cmd
run_pam_tests.bat
```
*(Or run `python test_zerovault_pam.py`)*.

---

## 📂 Project Directory Structure

```
F:\Project 2\
├── pam_backend/
│   ├── __init__.py
│   ├── config.py             # Ports, PBKDF2 iterations, blocked command regex policies
│   ├── database.py           # SQLite schema (servers, leases, audit_ledger, sessions)
│   ├── vault_crypto.py       # AES-256-GCM Envelope Encryption & PBKDF2 key derivation
│   ├── audit_ledger.py       # SHA-256 Merkle Hash-Chain logger & tamper verifier
│   ├── jit_provisioner.py    # Real Paramiko SSH engine creating/deleting Linux OS users
│   ├── ssh_proxy_gateway.py  # Live Port 2222 SSH Bastion Proxy & keystroke interceptor
│   ├── background_daemons.py # TTL Reaper Daemon (3s) & Master Password Rotator Daemon
│   ├── app.py                # Flask REST API for Vault, JIT Leases, & Audit Verification
│   └── zerovault_pam.db      # SQLite persistence layer
├── frontend/
│   ├── index.html            # ZeroVault PAM Command Center & Live Session DVR UI
│   ├── style.css             # Enterprise dark-mode cyber-slate theme
│   └── app.js                # Lease countdown timers, live session DVR, tamper test
├── test_zerovault_pam.py     # 13-test comprehensive automated verification suite
├── simulate_ssh_session.py   # Standalone interactive SSH session & firewall test tool
├── run_zerovault.bat         # Windows 1-click launcher for Web UI & SSH Proxy
├── run_pam_tests.bat         # Windows 1-click launcher for test suite
├── run_pam_simulation.bat    # Windows 1-click launcher for CLI simulator
├── requirements.txt          # Production dependencies (cryptography, paramiko, flask, flask-cors)
└── README_ZEROVAULT.md       # Complete technical and operational documentation
```
