# ZeroVault PAM - Step-by-Step Testing & Verification Guide

This guide gives you the **exact, copy-pasteable commands and step-by-step instructions** to test the entire ZeroVault PAM system using your real Windows terminal and web browser.

---

## 📋 Table of Contents
1. [Prerequisites & Starting the Server](#1-starting-the-zerovault-server)
2. [Step 1: Request a Just-In-Time (JIT) Lease](#2-step-1-request-a-just-in-time-jit-lease)
3. [Step 2: Connect Live via PowerShell (SSH Port 2222)](#3-step-2-connect-live-via-powershell-ssh-port-2222)
4. [Step 3: Test Safe Commands (Allowed)](#4-step-3-test-safe-commands-allowed)
5. [Step 4: Test Mid-Air Command Firewall (Blocked in Red)](#5-step-4-test-mid-air-command-firewall-blocked-in-red)
6. [Step 5: Inspect Live Session DVR (Keystroke Replay)](#6-step-5-inspect-live-session-dvr-keystroke-replay)
7. [Step 6: Test Cryptographic Tamper Detection (Merkle Hash-Chain)](#7-step-6-test-cryptographic-tamper-detection-merkle-hash-chain)
8. [Step 7: Test Automatic Account Self-Destruction (TTL Reaper)](#8-step-7-test-automatic-account-self-destruction-ttl-reaper)
9. [Automated Test Suite (13 Automated Tests)](#9-automated-test-suite)

---

## 1. Starting the ZeroVault Server

Open **Windows PowerShell** in `F:\Project 2` and run:

```powershell
.\run_zerovault.bat
```

*(Note the `.\` in front. In PowerShell, local scripts require `.\`).*

**Alternative Python Command:**
```powershell
python -m pam_backend.app
```

### What You Will See in the Console:
```
[+] Database & Genesis Block initialized.
[+] ZeroVault PAM SSH Proxy Gateway listening on 0.0.0.0:2222 (Port 2222)
[+] ZeroVault TTL Reaper Daemon started (Polling every 3s)
[*] Starting ZeroVault PAM on Web Port 5005...
```
Your browser will automatically open to: **`http://localhost:5005`**

---

## 2. Step 1: Request a Just-In-Time (JIT) Lease

1. Go to your browser at **`http://localhost:5005`**.
2. Make sure you are on the **JIT Access Console** tab.
3. In the form on the left:
   - **Target Server:** Select `Kali Linux Production Core (Primary Bastion)`.
   - **Requester Identity:** Enter your name (e.g. `rahul.verma`).
   - **Time-To-Live (TTL):** Select **5 Minutes** (or `2 Minutes` for a quick test).
   - **Reason:** Enter `Emergency DB inspection`.
4. Click the blue button: **"Issue JIT Ephemeral Lease"**.
5. A popup will appear showing your temporary **Lease ID** (e.g., `lease_74da7969`) and temporary user (e.g., `jit_u2915`).
6. In the **Active Leases** table below, you will see:
   - A live **countdown timer** ticking down (`04:59`, `04:58`...).
   - A copyable SSH command string:
     ```
     ssh -p 2222 lease_xxxxxxxx@127.0.0.1
     ```
7. Click the small **"Copy"** button next to the command.

---

## 3. Step 2: Connect Live via PowerShell (SSH Port 2222)

1. Open a **new, second Windows PowerShell window** (leave the server running in the first window).
2. Paste the copied SSH command and press **Enter**:
   ```powershell
   ssh -p 2222 <your_lease_id>@127.0.0.1
   ```
   *Example:*
   ```powershell
   ssh -p 2222 lease_74da7969@127.0.0.1
   ```
3. **First-Time Connection Prompts:**
   - If prompted: `Are you sure you want to continue connecting (yes/no/[fingerprint])?`
     👉 Type **`yes`** and press **Enter**.
   - If prompted for a password:
     👉 Just press **Enter** (or type your lease token).
4. **Expected Output in PowerShell:**
   ```
   +----------------------------------------------------------------------+
   | ZEROVAULT PAM: Zero-Trust Privileged Access Gateway (Port 2222)      |
   +----------------------------------------------------------------------+
     [+] Active JIT Lease: lease_74da7969 | User: jit_u2915
     [+] Target Host:      127.0.0.1:22 (srv_kali_prod)
     [+] Security Mode:    REAL-TIME COMMAND FIREWALL & SESSION DVR ACTIVE
     [+] Warning:          Every keystroke is cryptographically hash-chained.
   +----------------------------------------------------------------------+

   jit_u2915@kali-prod:~$
   ```
   You are now inside an interactive Linux shell session via ZeroVault's proxy without ever seeing or knowing the server's real master password!

---

## 4. Step 3: Test Safe Commands (Allowed)

Inside your PowerShell SSH session, test standard administrative commands:

### Command 1: Identity Check
```bash
whoami
```
**Expected Output:**
```
jit_u2915
```

### Command 2: Kernel & Hostname Info
```bash
uname -a
```
**Expected Output:**
```
Linux kali-prod 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.6.15-1 (2026-03-10) x86_64 GNU/Linux
```

### Command 3: Disk Utilization
```bash
df -h
```
**Expected Output:**
```
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        60G   14G   44G  25% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
```

---

## 5. Step 4: Test Mid-Air Command Firewall (Blocked in Red)

Now, test what happens when an attacker or unauthorized user tries to run forbidden commands:

### Attack Test A: Attempt to Steal OS Password Hashes
Type this in PowerShell and press **Enter**:
```bash
cat /etc/shadow
```
**Expected Output (Displayed in Bright Red in Your Terminal):**
```
cat /etc/shadow
[ZEROVAULT PAM FIREWALL] BLOCKED: Command 'cat /etc/shadow' violates Zero-Trust Policy!
  --> Reason: [Credential Access] Attempt to read sensitive OS password hash database.
  --> Rule ID: RULE-CRED-01 (CREDENTIAL_FILE_ACCESS)
jit_u2915@kali-prod:~$
```
*ZeroVault dropped the Enter key in mid-air, sent Ctrl+C to the remote buffer, and logged the violation!*

---

### Attack Test B: Attempt to Wipe the Root Filesystem
Type this in PowerShell and press **Enter**:
```bash
rm -rf /
```
**Expected Output (Displayed in Bright Red):**
```
rm -rf /
[ZEROVAULT PAM FIREWALL] BLOCKED: Command 'rm -rf /' violates Zero-Trust Policy!
  --> Reason: [Destructive Action] Attempt to execute recursive root filesystem deletion.
  --> Rule ID: RULE-DESTR-02 (DESTRUCTIVE_FILESYSTEM_WIPE)
jit_u2915@kali-prod:~$
```

---

### Attack Test C: Attempt to Escape to Permanent Root
Type this in PowerShell and press **Enter**:
```bash
sudo su
```
**Expected Output (Displayed in Bright Red):**
```
sudo su
[ZEROVAULT PAM FIREWALL] BLOCKED: Command 'sudo su' violates Zero-Trust Policy!
  --> Reason: [Privilege Escalation] Attempt to escape JIT ephemeral user boundary to permanent root shell.
  --> Rule ID: RULE-PRIVESC-03 (UNAUTHORIZED_ROOT_ESCAPE)
jit_u2915@kali-prod:~$
```

---

## 6. Step 5: Inspect Live Session DVR (Keystroke Replay)

1. Switch back to your browser window at **`http://localhost:5005`**.
2. Click the **Live Proxy & Session DVR** tab.
3. You will see your active SSH tunnel:
   - **Client IP:** `127.0.0.1`
   - **Commands Count:** Total commands you executed.
   - **Violations Count:** Number of red alerts caught (e.g. `3`).
4. Click the blue **"View DVR"** button.
5. Look at the terminal DVR viewer on the right: it displays the **complete, raw playback transcript** of every keystroke and blocked command you typed in PowerShell!

---

## 7. Step 6: Test Cryptographic Tamper Detection (Merkle Hash-Chain)

1. In the browser, click the **Merkle Audit Ledger** tab.
2. Review the table: every single command (`whoami`, `df -h`, `cat /etc/shadow [BLOCKED]`) is chained together using SHA-256 hashes:
   - Each row's **Previous SHA-256 Hash** strictly links to the **Current SHA-256 Hash** of the preceding block.
3. Click the green button: **"Verify Chain Integrity"**.
   - **Result:** A popup confirms that all blocks have been mathematically verified with unbroken hash continuity.

### Simulating a Rogue Insider Attack (Tamper Test):
1. Click the red button: **"Simulate Tampering Attack"**.
2. In the modal, leave Block # as `2` and click **"Inject Tampered Record"**.
   *(This simulates a rogue admin secretly editing SQLite to change `cat /etc/shadow` into `ls -la` to cover their tracks).*
3. Now click the green button again: **"Verify Chain Integrity"**.
4. **Expected Result:**
   - The top banner immediately turns **bright red**.
   - An alert appears:
     ```
     CRITICAL FRAUD ALERT:
     CRITICAL TAMPER DETECTED at Block #2!
     Stored SHA-256: 5f92d682... | Computed SHA-256: 4889a5ca...
     (Command was altered in database).
     ```
   This mathematically proves that retroactive log modification is impossible without detection.

---

## 8. Step 7: Test Automatic Account Self-Destruction (TTL Reaper)

1. Keep your PowerShell SSH session open.
2. Look at the countdown timer in the browser dashboard.
3. When the countdown reaches `00:00` (or if you click the red **"Revoke Lease"** button in the dashboard):
   - **Look at your PowerShell terminal:** ZeroVault immediately prints:
     ```
     [ZEROVAULT PAM] Session Terminated in mid-air!
       --> Reason: Manual Administrator Revocation via Web Console
       --> Action: SSH Tunnel Severed. Goodbye.
     Connection to 127.0.0.1 closed.
     ```
   - The connection closes immediately.
   - The temporary Linux user is wiped from the system.

---

## 9. Automated Test Suite

To run all 13 unit and integration tests across encryption, proxy, firewall, provisioner, and Merkle ledger:

```powershell
.\run_pam_tests.bat
```
*(Or run `python test_zerovault_pam.py`)*.

### Expected Output:
```
Ran 13 tests in 11.549s
OK (100% Passed)
```

---

## 🎯 Verification Checklist

| Test Case | Method | Expected Result | Pass? |
| :--- | :--- | :--- | :---: |
| **Start Server** | `.\run_zerovault.bat` | Proxy on Port 2222, Web UI on 5005 | ✅ |
| **Issue Lease** | Web UI Button | Unique token issued with live countdown | ✅ |
| **Credentialless SSH** | `ssh -p 2222 lease_xxx@127.0.0.1` | Interactive shell opened without real password | ✅ |
| **Safe Commands** | `whoami`, `df -h` | Normal execution and output | ✅ |
| **Blocked Commands** | `cat /etc/shadow`, `rm -rf /` | Intercepted in mid-air with red terminal alert | ✅ |
| **Session DVR** | Tab 2 "View DVR" | Full playback transcript rendered in UI | ✅ |
| **Merkle Hash Chain** | Tab 4 "Verify Chain Integrity" | 100% unbroken SHA-256 hash validation | ✅ |
| **Tamper Detection** | Tab 4 "Simulate Tampering" | Immediate fraud alert pinpointing altered block | ✅ |
| **TTL Auto-Reaper** | Wait for 00:00 or click Revoke | Socket severed in mid-air and user purged | ✅ |
| **Automated Tests** | `.\run_pam_tests.bat` | 13 of 13 tests passed | ✅ |
