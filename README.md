# ZeroVault PAM - Enterprise Zero-Trust Privileged Access Management & Live SSH Protocol Proxy

![ZeroVault PAM](https://img.shields.io/badge/Architecture-Zero--Trust%20PAM%20%7C%20Bastion%20Proxy-06b6d4?style=for-the-badge)
![Security Standard](https://img.shields.io/badge/Cryptography-AES--256--GCM%20%7C%20600K%20PBKDF2-8b5cf6?style=for-the-badge)
![Tamper Detection](https://img.shields.io/badge/Audit%20Ledger-Merkle%20SHA--256%20Hash%20Chain-10b981?style=for-the-badge)
![MFA Standard](https://img.shields.io/badge/2FA%20Authentication-Google%20Authenticator%20TOTP-f59e0b?style=for-the-badge)
![Database Engine](https://img.shields.io/badge/Relational%20DB-SQLite%20%7C%20MySQL%208.0-3b82f6?style=for-the-badge)
![Containerization](https://img.shields.io/badge/Docker-Multi--Container%20Compose-2496ed?style=for-the-badge)

ZeroVault PAM is a **production-grade, enterprise Privileged Access Management (PAM) vault, Ephemeral Identity Provisioner, and Live SSH Protocol Proxy Gateway** modeled after industry standards like **CyberArk Privileged Access Manager**, **Teleport Enterprise**, and **HashiCorp Boundary**.

It eliminates the risk of shared administrative passwords: **engineers, DBAs, and third-party contractors are never given static master passwords to production servers or databases**. Instead, users request Just-In-Time (JIT) ephemeral leases, verify their identity via **Google Authenticator 2FA**, undergo **Maker-Checker Dual-Approval** for high-risk tasks, connect through a credentialless proxy on Port 2222, have keystrokes inspected by a mid-air command firewall, and have all sessions cryptographically recorded into an immutable **SHA-256 Merkle hash-chain ledger**.

[ZeroVault PAM Command Center & SOC Dashboard]<img width="1501" height="803" alt="1" src="https://github.com/user-attachments/assets/28d98e58-f7f4-475d-8eb1-e3210f458245" />

[Just-In-Time Ephemeral Access Request Console]<img width="1500" height="800" alt="2" src="https://github.com/user-attachments/assets/39f4ae66-7d71-4ffc-9162-1e01bb62d3b5" />

[Google Authenticator Multi-Factor Authentication (RFC 6238 TOTP)]<img width="1200" height="600" alt="3" src="https://github.com/user-attachments/assets/88e2ea3a-8a6c-4aeb-b2b3-63598c77674a" />


[Active JIT Ephemeral Leases with Live Countdown & TTL Controls]<img width="1500" height="337" alt="4" src="https://github.com/user-attachments/assets/a3bf041d-cce0-4af9-8d91-50451780ef81" />

[Live SSH Protocol Proxy (Port 2222) & Mid-Air Keystroke Firewall]<img width="1047" height="508" alt="5" src="https://github.com/user-attachments/assets/1a8d650d-52d9-4cf4-9559-03061db975a6" />

[Real-Time Push Alerts & Security Incident Notifications]<img width="1418" height="801" alt="6" src="https://github.com/user-attachments/assets/eae83dd1-2e45-4466-96fe-c1aa27b9fb1c" />

[Maker-Checker Dual-Approval Governance Queue]<img width="1893" height="492" alt="7" src="https://github.com/user-attachments/assets/35205144-7eba-4ae0-8188-d62971a91a83" />


---

## 🎯 The 8 Core Pillars of ZeroVault PAM

### 1. 🔐 AES-256-GCM Envelope Encryption Secret Vault (`vault_crypto.py`)
- Master credentials are encrypted using an envelope encryption hierarchy.
- A 256-bit Key Encryption Key (KEK) is derived using **PBKDF2-HMAC-SHA256 with 600,000 iterations** (OWASP & NIST SP 800-132 standards).
- Each secret is wrapped with a unique 256-bit Data Encryption Key (DEK) using **AES-256-GCM** (12-byte random IV nonce + 128-bit authentication tag).
- Zero plaintext credentials ever touch storage or application logs.

### 2. 📱 Google Authenticator Multi-Factor Authentication (`mfa.py`)
- Enforces **RFC 6238 Standard Time-Based One-Time Passwords (TOTP)** for every JIT access request.
- Generates dynamic, high-resolution Base64 QR codes compatible with **Google Authenticator, Microsoft Authenticator, and Authy**.
- Independent 30-second time-step verification with clock-drift compensation (+/- 30s tolerance window).

### 3. 👥 Maker-Checker Dual-Approval Governance ("Four-Eyes" Principle)
- Implements banking-grade Maker-Checker separation of duties:
  - **🟢 Standard Access Tier**: Auto-approved immediately upon successful 2FA verification.
  - **🔴 Critical Production Tier**: High-risk production database and root actions are quarantined in the **Approvals Queue**.
- Senior Security Admins review business justification, risk score, and target host before clicking **Approve** (dynamically minting credentials) or **Reject** (logging rejection with audit reasoning).

### 4. ⚡ Just-In-Time (JIT) Identity Provisioner & TTL Auto-Reaper (`jit_provisioner.py`, `background_daemons.py`)
- When an access request is approved, ZeroVault connects to the target Linux host over SSH.
- Executes: `sudo useradd -m -s /bin/bash jit_uXXXX` with an ephemeral 24-character cryptographic password in memory.
- Issues a temporary lease token (e.g., `lease_ccb9e914`) with a strict countdown timer.
- Background **TTL Reaper Daemon** polls every 3 seconds: the instant TTL reaches `00:00`, it cuts active SSH sockets in mid-air and executes `sudo userdel -rf jit_uXXXX` on the target host.

### 5. 🛡️ Live SSH Protocol Proxy Gateway on Port 2222 (`ssh_proxy_gateway.py`)
- Custom raw socket SSHv2 server built with Paramiko and backed by a local 2048-bit RSA Host Key.
- Connect via any standard terminal: `ssh -p 2222 lease_ccb9e914@127.0.0.1`.
- Transparently bridges client PTY $\leftrightarrow$ target Linux server shell with sub-2ms latency. The client never learns the real password.

### 6. 🚨 Mid-Air Keystroke Interceptor & Command Firewall
- Real-time line-buffer parser resolves backspaces and arrow navigation before `\r` (Enter).
- Enforces 5 strict regex security policies:
  - **RULE-CRED-01**: `CREDENTIAL_FILE_ACCESS` (cat/grep `/etc/shadow`, `/etc/gshadow`).
  - **RULE-DESTR-02**: `DESTRUCTIVE_FILESYSTEM_WIPE` (`rm -rf /`, `rm -rf /*`, `--no-preserve-root`).
  - **RULE-PRIVESC-03**: `UNAUTHORIZED_ROOT_ESCAPE` (`sudo su`, `sudo -i`, `visudo`, `passwd root`).
  - **RULE-EXFIL-04**: `REVERSE_SHELL_OR_EXFILTRATION` (`nc -e`, `/dev/tcp`, `curl | bash`).
  - **RULE-PERM-05**: `INSECURE_PERMISSIONS_OVERWRITE` (`chmod 777 /`, `chmod -R 777 /etc`).
- Prohibited commands are dropped mid-air: sends `\x03` (`Ctrl+C`) to the target server, injects a bright red terminal alert, increments session violation metrics, and buzzes the admin's phone.

### 7. 🗄️ Database SQL Protocol Firewall (`sql_firewall.py`)
- Inspects SQL statements prior to execution.
- Blocks destructive DDL statements (`DROP TABLE`, `TRUNCATE TABLE`).
- Blocks column-level data exfiltration (`credit_cards`, `card_numbers`, `cvv`, `passwords`, `ssn`).
- Blocks unrestricted mass updates and deletes without restrictive `WHERE` clauses.

### 8. 🔗 Tamper-Evident SHA-256 Merkle Hash-Chain Audit Ledger (`audit_ledger.py`)
- Every command, session event, firewall block, approval, and rejection is chained:
  $$H_i = \text{SHA256}(H_{i-1} \parallel \text{timestamp} \parallel \text{lease\_id} \parallel \text{user} \parallel \text{server} \parallel \text{command} \parallel \text{action} \parallel \text{rule})$$
- Cryptographic verification walk recalculates every hash from Genesis Block #0.
- If a rogue admin or intruder alters even a single byte in the database (e.g. changing `cat /etc/shadow` to `ls -la`), the verification algorithm immediately detects chain fracture and isolates the tampered block index.

---

## 🏗️ End-to-End System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│             ENGINEER / WORKSTATION (PowerShell / Terminal / Web UI)              │
│                                                                                  │
│   1. Request Access (MFA: Google Authenticator QR & 6-Digit TOTP Challenge)      │
│   2. Critical Tiers -> Held in Maker-Checker Senior Admin Approvals Queue         │
│   3. Connect via Credentialless Proxy: > ssh -p 2222 lease_ccb9e914@127.0.0.1    │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              ZEROVAULT PAM CORE                                  │
│                                                                                  │
│   ┌───────────────────────────┐      ┌───────────────────────────────────────┐   │
│   │ 1. AES-256-GCM Vault      │      │ 2. MFA TOTP Engine (RFC 6238)         │   │
│   │ - 600K PBKDF2 Iterations  │      │ - Dynamic QR Code & 30s Window Check  │   │
│   │ - Envelope DEK Encryption │      │ - Google / Authy / Microsoft Auth     │   │
│   └─────────────┬─────────────┘      └───────────────────┬───────────────────┘   │
│                 │                                        │                       │
│                 ▼                                        ▼                       │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │ 3. Maker-Checker Approvals Queue & JIT Identity Provisioner              │   │
│   │ - Four-Eyes Approval Workflow for Critical Infrastructure                │   │
│   │ - Dynamic Linux OS User Creation: sudo useradd -m -s /bin/bash jit_uXXXX │   │
│   └─────────────────────────────────────┬────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │ 4. Live SSH Protocol Proxy Gateway & Mid-Air Keystroke Firewall          │   │
│   │ - Port 2222 Listening Socket (Paramiko SSHv2 with 2048-bit RSA Key)      │   │
│   │ - Mid-Air Keystroke Interception (cat /etc/shadow, rm -rf, sudo su)      │   │
│   │ - Real-Time Push Alerts (Telegram Bot & Discord Webhooks)                │   │
│   └─────────────────────────────────────┬────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│   ┌───────────────────────────┐      ┌───────────────────────────────────────┐   │
│   │ 5. Background Daemons     │      │ 6. Tamper-Evident Ledger              │   │
│   │ - TTL Reaper (Every 3s)   │      │ - SHA-256 Merkle Sequential Chain     │   │
│   │ - Master Password Rotator │      │ - Mathematical Fraud Detection Walk   │   │
│   └───────────────────────────┘      └───────────────────────────────────────┘   │
│                                         │                                        │
│                                         ▼                                        │
│   ┌──────────────────────────────────────────────────────────────────────────┐   │
│   │ 7. Relational Persistence Layer (Dual Engine Support)                    │   │
│   │ - SQLite: Embedded persistent storage (zerovault_pam.db)                 │   │
│   │ - MySQL 8.0: Enterprise transactional InnoDB storage (Docker Mode)       │   │
│   └──────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
                                         ▼ (Secure Backend SSH Tunnel: Port 22)
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      TARGET PRODUCTION SERVERS & BASTIONS                        │
│   • Kali Linux Production Bastion (127.0.0.1:22)                                 │
│   • Ubuntu Cloud Financial Database Host (192.168.1.150:22)                      │
│   • Docker Containerized Linux Target (target-server:22)                         │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 How to Run the Project

### Option A: 1-Click Local Launch (Windows)

Double-click `run_zerovault.bat` or run in PowerShell:

```powershell
.\run_zerovault.bat
```

*Automatically initializes database schemas, launches the Web Dashboard on `http://localhost:5005`, and starts the live SSH Proxy on Port `2222`.*

---

### Option B: Docker Multi-Container Compose (Production Setup)

Run the entire platform with full **MySQL 8.0** and a **Target Linux SSH container** in 1 command:

```powershell
docker compose up --build
```

#### Containers Spawned:
1. **`zerovault_pam`**: Web Dashboard (`http://localhost:5005`) & SSH Proxy (`localhost:2222`).
2. **`zerovault_mysql`**: Enterprise MySQL 8.0 relational database engine (`localhost:3306`).
3. **`zerovault_target_linux`**: Target Linux bastion server (`localhost:2223`).

To stop:
```powershell
docker compose down
```

---

### Option C: Automated Verification Test Suite (25 Tests)

To run the complete automated test suite verifying encryption, proxy, firewall, provisioner, Merkle ledger, MFA, and Maker-Checker:

```powershell
.\run_pam_tests.bat
```
*(Or run `python test_zerovault_pam.py`)*

#### Test Suite Coverage (100% Passing):
```
Ran 25 tests in 23.694s
OK (All 25 unit and integration tests passed)
```

---

## 📂 Project Directory Structure

```
F:\Project 2\
├── pam_backend/
│   ├── __init__.py
│   ├── config.py             # Port bindings, PBKDF2 iterations, blocked regex rules, MySQL settings
│   ├── database.py           # Unified database engine adapter (SQLite persistent + MySQL 8.0)
│   ├── vault_crypto.py       # AES-256-GCM Envelope Encryption & PBKDF2 key derivation
│   ├── mfa.py                # RFC 6238 TOTP Google Authenticator & QR code engine
│   ├── audit_ledger.py       # SHA-256 Merkle Hash-Chain logger & cryptographic verifier
│   ├── jit_provisioner.py    # Paramiko SSH engine provisioning/purging Linux OS users
│   ├── ssh_proxy_gateway.py  # Live Port 2222 SSH Bastion Proxy & keystroke interceptor
│   ├── background_daemons.py # TTL Reaper Daemon (3s) & Master Password Rotator Daemon
│   ├── sql_firewall.py       # Database SQL Protocol Proxy & Query Firewall
│   ├── notifier.py           # Real-Time Push Alerts (Telegram Bot & Discord Webhooks)
│   ├── app.py                # Flask REST API Controller & Verification Endpoints
│   ├── zerovault_pam.db      # Persistent SQLite relational storage
│   └── zerovault_rsa.key     # 2048-bit RSA Host Key for SSH Proxy Gateway
├── frontend/
│   ├── index.html            # ZeroVault PAM Command Center UI (Dark Carbon Obsidian Theme)
│   ├── style.css             # High-contrast multi-colored SOC styling (Cyan, Amber, Crimson, Emerald)
│   └── app.js                # Dynamic JIT countdowns, MFA modal, Maker-Checker queue, terminal DVR
├── Dockerfile                # Production multi-stage lightweight Python container image
├── docker-compose.yml        # Orchestration for ZeroVault PAM, MySQL 8.0, and Linux Bastion
├── .dockerignore             # Excludes test databases, venvs, and cache files from container images
├── test_zerovault_pam.py     # 25-test comprehensive verification test suite (isolated test DB)
├── simulate_ssh_session.py   # Standalone interactive CLI terminal & firewall simulator
├── run_zerovault.bat         # 1-click launcher for Web UI & SSH Proxy
├── run_pam_tests.bat         # 1-click launcher for test suite
├── run_pam_simulation.bat    # 1-click launcher for CLI simulator
├── requirements.txt          # Python production dependencies
├── TESTING_GUIDE.md          # Complete step-by-step testing manual
└── README.md                 # Complete system documentation
```

---

## 📜 Regulatory Compliance Mapping

ZeroVault PAM generates formal, cryptographic forensic compliance reports mapped to international cybersecurity standards:

| Compliance Standard | Requirement Reference | How ZeroVault PAM Enforces It |
| :--- | :--- | :--- |
| **PCI-DSS v4.0** | Req 7 & Req 8 | Elimination of static passwords; unique Just-In-Time identity mapping; 2FA TOTP enforcement. |
| **RBI Cyber Security Framework** | Annex 1 (Privileged Identity) | SSH protocol proxy bastion; live session DVR recording; mid-air keystroke firewall. |
| **SOC 2 Type II** | Trust Services Criteria CC6.1 - CC6.3 | Maker-Checker Dual-Approval workflow; automatic TTL account self-destruction; tamper-evident hash ledger. |
| **ISO/IEC 27001:2022** | Control A.8.2 & A.8.5 | Privileged access management; automated credential rotation; cryptographic Merkle verification trail. |

---

## 🔒 Security Best Practices Implemented

1. **Zero Static Credentials**: Administrative passwords are generated dynamically in RAM and wiped on expiration.
2. **Deterministic Tamper Detection**: Retroactive alteration of past ledger logs is mathematically impossible without breaking the SHA-256 hash chain.
3. **Defense-in-Depth**: Keystrokes are inspected *before* reaching the target shell; malicious commands are dropped in mid-air.
4. **Isolated Test Environments**: Automated tests run on an isolated sandbox database, preserving production operational data across all runs.
