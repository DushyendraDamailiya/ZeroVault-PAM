import time
import threading
from datetime import datetime, timezone
from pam_backend.config import Config
from pam_backend import database as db
from pam_backend.jit_provisioner import JITProvisioner
from pam_backend.ssh_proxy_gateway import SSHProxyGateway
from pam_backend.audit_ledger import MerkleAuditLedger

class TTLReaperDaemon:
    """
    Background Daemon that continuously inspects active JIT leases.
    When a lease's Time-To-Live (TTL) hits zero:
    1. Cuts the live SSH proxy session in mid-air (socket disconnect).
    2. Dispatches an admin SSH task to target server to kill user processes and delete the Linux account.
    3. Updates database status to EXPIRED_AND_PURGED.
    4. Records the cryptographic audit record into the Merkle Hash-Chain.
    """

    def __init__(self, interval_seconds: int = None):
        self.interval = interval_seconds or Config.REAPER_INTERVAL_SECONDS
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._reaper_loop, daemon=True, name="ZeroVault-TTLReaper-Daemon")
        self.thread.start()
        print(f"[+] ZeroVault TTL Reaper Daemon started (Polling every {self.interval}s)")

    def stop(self):
        self.running = False

    def _reaper_loop(self):
        while self.running:
            try:
                self._check_and_reap_leases()
            except Exception as e:
                print(f"[!] Error in TTL Reaper loop: {e}")
            time.sleep(self.interval)

    def _check_and_reap_leases(self):
        active_leases = db.get_active_leases()
        now_utc = datetime.now(timezone.utc)

        for lease in active_leases:
            lease_id = lease["lease_id"]
            ephemeral_user = lease["ephemeral_user"]
            server_id = lease["server_id"]
            expires_at_str = lease["expires_at"]

            try:
                expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            except Exception:
                continue

            if now_utc >= expires_at:
                print(f"[*] TTL EXPIRED for {lease_id} ({ephemeral_user} on {server_id}). Purging account...")

                # 1. Terminate any active SSH proxy session in mid-air
                SSHProxyGateway.terminate_session(
                    lease_id=lease_id,
                    reason=f"JIT Access TTL Expired ({lease['ttl_minutes']} minutes limit reached)."
                )

                # 2. Delete temporary Linux user on target host
                server = db.get_server_by_id(server_id)
                if server:
                    JITProvisioner.delete_ephemeral_account(server, ephemeral_user)

                # 3. Update database status
                db.update_lease_status(lease_id, "EXPIRED_AND_PURGED")

                # 4. Append to Cryptographic Merkle Audit Ledger
                MerkleAuditLedger.record_event(
                    lease_id=lease_id,
                    user=ephemeral_user,
                    server=server_id,
                    command=f"LEASE_EXPIRED_AND_ACCOUNT_PURGED (TTL: {lease['ttl_minutes']}m)",
                    action="EXPIRED",
                    rule_triggered="TTL_REAPER_AUTO_DESTRUCTION"
                )
                print(f"[+] Successfully purged expired lease {lease_id} and Linux account {ephemeral_user}.")


class PasswordRotatorDaemon:
    """
    Background Daemon for scheduling periodic master password rotation.
    Eliminates static credentials by automatically rotating server passwords
    and re-encrypting them in the vault.
    """

    def __init__(self, check_interval_minutes: int = 60):
        self.check_interval = check_interval_minutes * 60
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._rotator_loop, daemon=True, name="ZeroVault-PasswordRotator-Daemon")
        self.thread.start()
        print("[+] ZeroVault Master Password Rotator Daemon started")

    def stop(self):
        self.running = False

    def _rotator_loop(self):
        while self.running:
            try:
                self._check_rotation_schedules()
            except Exception as e:
                print(f"[!] Error in Password Rotator loop: {e}")
            time.sleep(self.check_interval)

    def _check_rotation_schedules(self):
        servers = db.get_all_servers()
        now_utc = datetime.now(timezone.utc)

        for srv in servers:
            last_rot_str = srv.get("last_rotated_at")
            if not last_rot_str:
                continue

            try:
                last_rot = datetime.fromisoformat(last_rot_str.replace("Z", "+00:00"))
                delta_hours = (now_utc - last_rot).total_seconds() / 3600.0
                if delta_hours >= Config.ROTATION_INTERVAL_HOURS:
                    print(f"[*] Auto-rotating master password for server '{srv['name']}'...")
                    res = JITProvisioner.rotate_master_password(srv["server_id"])
                    if res.get("success"):
                        MerkleAuditLedger.record_event(
                            lease_id="SYSTEM_AUTO_ROTATE",
                            user="ZEROVAULT_DAEMON",
                            server=srv["server_id"],
                            command=f"AUTOMATED_PASSWORD_ROTATION (Period: {Config.ROTATION_INTERVAL_HOURS}h)",
                            action="ROTATED"
                        )
            except Exception:
                continue
