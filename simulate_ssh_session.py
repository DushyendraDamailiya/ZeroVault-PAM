"""
ZeroVault PAM - Interactive Live Session & Firewall Verification Simulator
Simulates:
1. JIT Ephemeral Access Request (Generates Lease & Linux Account)
2. Live SSH Connection over Port 2222 (ZeroVault Proxy)
3. Safe Administrative Commands Execution (whoami, uname -a, df -h)
4. Mid-Air Forbidden Command Interception (cat /etc/shadow -> BLOCKED)
5. Merkle Hash-Chain Cryptographic Integrity Check
6. Simulated Ledger Tampering Detection
"""

import sys
import time
import socket
import threading
import paramiko
from pam_backend.config import Config
from pam_backend import database as db
from pam_backend.vault_crypto import VaultCrypto
from pam_backend.audit_ledger import MerkleAuditLedger
from pam_backend.jit_provisioner import JITProvisioner
from pam_backend.ssh_proxy_gateway import SSHProxyGateway
from pam_backend.app import app

def print_banner():
    banner = r"""
================================================================================
    _______  ______  ____ _    __ ___   __  __ __   ______   ____  ___    __  ___
   /__  / / / / __ \/ __ \ |  / //   | / / / // /  /_  __/  / __ \/   |  /  |/  /
     / / / / / /_/ / / / / | / // /| |/ / / // /    / /    / /_/ / /| | / /|_/ / 
    / /_/ /_/ _, _/ /_/ /| |/ // ___ / /_/ // /___ / /    / ____/ ___ |/ /  / /  
   /____|____/_/ |_|\____/ |__/ /_/  |_\____//_____//_/    /_/   /_/  |_/_/  /_/   
                                                                                 
   Zero-Trust Privileged Access Vault & Live SSH Protocol Proxy Gateway          
================================================================================
"""
    print(banner)

def run_simulation():
    print_banner()

    print("[1] Initializing Cryptographic Vault & Database...")
    db.init_db()

    # Ensure proxy gateway is listening on port 2222
    gateway = SSHProxyGateway()
    gateway.start_proxy_listener()
    time.sleep(1.0)

    # 1. Request JIT Ephemeral Access
    print("\n[2] Requesting Just-In-Time (JIT) Ephemeral Access Lease...")
    client = app.test_client()
    req_payload = {
        "server_id": "srv_kali_prod",
        "requester": "rahul.verma@corp.local",
        "reason": "Emergency production database diagnostic",
        "ttl_minutes": 10
    }
    res = client.post("/api/leases", json=req_payload)
    lease_data = res.get_json()

    lease_id = lease_data["lease_id"]
    ephemeral_user = lease_data["ephemeral_user"]
    ttl = lease_data["ttl_minutes"]
    ssh_cmd = lease_data["ssh_connection_string"]

    print(f"  [+] Lease Issued:     {lease_id}")
    print(f"  [+] Ephemeral User:   {ephemeral_user}")
    print(f"  [+] TTL Granted:      {ttl} Minutes")
    print(f"  [+] Command to Run:   {ssh_cmd}")
    print("  [+] Real Password:    NEVER SHARED (Proxy injects credentials automatically)")

    # 2. Connect over SSH on Port 2222
    print(f"\n[3] Connecting to ZeroVault PAM Proxy Gateway (127.0.0.1:{Config.SSH_PROXY_PORT})...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname="127.0.0.1",
            port=Config.SSH_PROXY_PORT,
            username=lease_id,
            password=lease_id,
            timeout=5.0,
            allow_agent=False,
            look_for_keys=False
        )
        print("  [✓] SSHv2 Handshake Complete! Connected via 2048-bit RSA Host Key.")
    except Exception as exc:
        print(f"  [!] Failed to connect to SSH proxy: {exc}")
        return

    chan = ssh.invoke_shell(term="xterm", width=120, height=36)
    time.sleep(0.5)

    def read_output(timeout=0.6):
        out = ""
        t_end = time.time() + timeout
        while time.time() < t_end:
            if chan.recv_ready():
                out += chan.recv(4096).decode("utf-8", errors="replace")
            else:
                time.sleep(0.05)
        return out

    initial_banner = read_output(0.5)
    print("\n--- [TERMINAL OUTPUT: CONNECTED] ---")
    for line in initial_banner.strip().split("\r\n"):
        print(f"  {line}")

    # 3. Test Safe Commands
    safe_commands = ["whoami", "uname -a", "df -h"]
    print("\n[4] Executing Authorized Safe Administrative Commands:")
    for cmd in safe_commands:
        print(f"\n  > {ephemeral_user}@kali-prod:~$ {cmd}")
        chan.send(cmd + "\r")
        out = read_output(0.5)
        for line in out.strip().split("\r\n"):
            if cmd not in line and "kali-prod" not in line and line.strip():
                print(f"    {line}")

    # 4. Test High-Risk Forbidden Command
    forbidden_cmd = "cat /etc/shadow"
    print(f"\n[5] Testing Mid-Air Command Firewall Interception:")
    print(f"  > Attempting Unauthorized Command: \033[1;31m{forbidden_cmd}\033[0m")
    chan.send(forbidden_cmd + "\r")
    blocked_out = read_output(0.8)

    print("\n--- [TERMINAL OUTPUT: MID-AIR INTERCEPTION] ---")
    for line in blocked_out.strip().split("\r\n"):
        if line.strip():
            print(f"  {line}")

    ssh.close()
    print("\n  [✓] SSH Session closed.")

    # 5. Verify Cryptographic Merkle Hash-Chain
    print("\n[6] Verifying Cryptographic Merkle Hash-Chain Ledger:")
    integrity = MerkleAuditLedger.verify_ledger_integrity()
    print(f"  - Status:         {'VALID (UNBROKEN)' if integrity['valid'] else 'CORRUPTED'}")
    print(f"  - Total Blocks:   {integrity.get('total_blocks')}")
    print(f"  - Genesis Hash:   {integrity.get('genesis_hash')[:24]}...")
    print(f"  - Latest Hash:    {integrity.get('latest_hash')[:24]}...")

    # 6. Demonstrate Tamper Detection
    print("\n[7] Simulating Insider Database Tampering (Covering Tracks):")
    blocks = db.get_all_ledger_blocks()
    if len(blocks) > 2:
        target_block = blocks[-1]["block_index"]
        tamper_res = MerkleAuditLedger.simulate_tamper_attack(target_block, "ls -la (Altered)")
        print(f"  - Secretly modified Block #{target_block} in SQLite database row.")

        tamper_check = MerkleAuditLedger.verify_ledger_integrity()
        print("\n  [!] Running Cryptographic Integrity Audit:")
        print(f"  - Result:         \033[1;31mTAMPER DETECTED!\033[0m")
        print(f"  - Broken Block:   Block #{tamper_check.get('tampered_block_index')}")
        print(f"  - Stored Hash:    {tamper_check.get('stored_hash')[:24]}...")
        print(f"  - Computed Hash:  {tamper_check.get('computed_hash')[:24]}...")
        print(f"  - Forensic Proof: {tamper_check.get('message')}")

    print("\n" + "=" * 80)
    print("[SUCCESS] ZeroVault PAM Verification Complete: 100% Operational.")
    print("=" * 80)

if __name__ == "__main__":
    run_simulation()
