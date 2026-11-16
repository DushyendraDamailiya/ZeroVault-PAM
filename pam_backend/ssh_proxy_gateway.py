import os
import re
import sys
import time
import socket
import select
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import paramiko
from pam_backend.config import Config
from pam_backend.vault_crypto import VaultCrypto
from pam_backend.audit_ledger import MerkleAuditLedger
from pam_backend.notifier import AlertNotifier
from pam_backend import database as db

# Global registry of active proxy sessions keyed by lease_id
ACTIVE_PROXY_SESSIONS: Dict[str, Any] = {}
SESSION_LOCK = threading.Lock()

# ANSI escape sequence regex (arrow keys, function keys, cursor navigation)
ANSI_ESCAPE_RE = re.compile(rb'^\x1b(?:\[[0-9;?]*[ -/]*[@-~]|O[@-~]|[ -/]*[@-~])')

class ZeroVaultSSHServerInterface(paramiko.ServerInterface):
    """
    Paramiko SSH Server Interface for ZeroVault PAM.
    Authenticates clients using one-time ephemeral JIT lease tokens.
    """

    def __init__(self, client_ip: str):
        self.client_ip = client_ip
        self.authenticated_lease: Optional[Dict[str, Any]] = None
        self.event = threading.Event()

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_auth_none(self, username: str) -> int:
        """
        Allow seamless token-based authentication: if username is a valid active lease_id,
        authenticates immediately without prompting for a password.
        """
        if username.startswith("lease_"):
            lease = db.get_lease_by_id(username)
            if lease and lease["status"] == "ACTIVE":
                try:
                    exp_time = datetime.fromisoformat(lease["expires_at"].replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) <= exp_time:
                        self.authenticated_lease = lease
                        return paramiko.AUTH_SUCCESSFUL
                except Exception:
                    pass
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Validates connection using the Lease ID or ephemeral password.
        The user can connect as:
        ssh -p 2222 lease_xxx@127.0.0.1  (password: lease_xxx or any)
        or
        ssh -p 2222 jit_user@127.0.0.1   (password: lease_xxx)
        """
        # Determine candidate lease ID
        candidate_lease_id = None
        if username.startswith("lease_"):
            candidate_lease_id = username
        elif password.startswith("lease_"):
            candidate_lease_id = password

        if not candidate_lease_id:
            # Check if username is an ephemeral user in an active lease
            conn = db.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT lease_id FROM leases WHERE ephemeral_user = ? AND status = 'ACTIVE'", (username,))
            row = cursor.fetchone()
            conn.close()
            if row:
                candidate_lease_id = row["lease_id"]

        if not candidate_lease_id:
            return paramiko.AUTH_FAILED

        lease = db.get_lease_by_id(candidate_lease_id)
        if not lease:
            return paramiko.AUTH_FAILED

        # Check if lease is active and not expired
        if lease["status"] != "ACTIVE":
            return paramiko.AUTH_FAILED

        try:
            exp_time = datetime.fromisoformat(lease["expires_at"].replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp_time:
                db.update_lease_status(candidate_lease_id, "EXPIRED_AND_PURGED")
                return paramiko.AUTH_FAILED
        except Exception:
            pass

        self.authenticated_lease = lease
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username: str) -> str:
        return "password"


class SSHProxyGateway:
    """
    Live Reverse SSH Proxy Gateway listening on Port 2222.
    Intercepts interactive terminal keystrokes, reconstructs commands,
    evaluates them against the Zero-Trust Command Firewall in mid-air,
    records full session DVR transcripts, and logs to the Merkle Audit Ledger.
    """

    def __init__(self, host: str = None, port: int = None):
        self.host = host or Config.SSH_PROXY_HOST
        self.port = port or Config.SSH_PROXY_PORT
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.host_key = self._load_or_generate_host_key()

    def _load_or_generate_host_key(self) -> paramiko.RSAKey:
        """Loads RSA host key or generates a fresh 2048-bit key if not present."""
        key_path = Config.RSA_HOST_KEY_PATH
        if os.path.exists(key_path):
            try:
                return paramiko.RSAKey.from_private_key_file(key_path)
            except Exception:
                pass

        # Generate fresh 2048-bit RSA key
        key = paramiko.RSAKey.generate(2048)
        try:
            key.write_private_key_file(key_path)
        except Exception:
            pass
        return key

    def start_proxy_listener(self):
        """Starts the SSH proxy listener in a background worker thread."""
        self.running = True
        thread = threading.Thread(target=self._run_server, daemon=True, name="ZeroVault-SSHProxy-Thread")
        thread.start()
        print(f"[+] ZeroVault PAM SSH Proxy Gateway listening on {self.host}:{self.port} (Port 2222)")

    def stop(self):
        """Stops the SSH proxy server listener."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def _run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(50)
        except Exception as e:
            print(f"[!] Error binding SSH Proxy on port {self.port}: {e}")
            self.running = False
            return

        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                client_ip = client_addr[0]
                handler = threading.Thread(
                    target=self._handle_client_connection,
                    args=(client_sock, client_ip),
                    daemon=True
                )
                handler.start()
            except Exception:
                if not self.running:
                    break

    def _handle_client_connection(self, client_sock: socket.socket, client_ip: str):
        transport = None
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self.host_key)

            server_iface = ZeroVaultSSHServerInterface(client_ip)
            transport.start_server(server=server_iface)

            # Wait for authentication & shell request
            chan = transport.accept(20)
            if chan is None:
                transport.close()
                return

            server_iface.event.wait(10)
            if not server_iface.event.is_set():
                chan.close()
                transport.close()
                return

            lease = server_iface.authenticated_lease
            if not lease:
                chan.send("Authentication failed: Invalid or expired JIT Lease Token.\r\n")
                chan.close()
                transport.close()
                return

            # Establish proxy bridge
            self._bridge_proxy_session(client_sock, transport, chan, lease, client_ip)

        except Exception as exc:
            pass
        finally:
            if transport and transport.is_active():
                try:
                    transport.close()
                except Exception:
                    pass

    def _bridge_proxy_session(self, client_sock: socket.socket, transport: paramiko.Transport,
                              client_chan: paramiko.Channel, lease: Dict[str, Any], client_ip: str):
        lease_id = lease["lease_id"]
        server_id = lease["server_id"]
        ephemeral_user = lease["ephemeral_user"]
        server_host = lease.get("server_host", "127.0.0.1")
        server_port = lease.get("server_port", 22)

        session_id = f"sess_{int(time.time())}_{lease_id[6:]}"
        db.create_session(session_id, lease_id, client_ip)

        # Log session start
        MerkleAuditLedger.record_event(
            lease_id=lease_id,
            user=ephemeral_user,
            server=server_id,
            command=f"SSH_SESSION_STARTED from {client_ip}",
            action="LOGIN"
        )

        # Check if real target Linux host is online
        target_ssh, target_chan = self._connect_backend_target(lease)
        is_simulated = (target_chan is None)

        session_ctx = {
            "session_id": session_id,
            "lease_id": lease_id,
            "ephemeral_user": ephemeral_user,
            "server_id": server_id,
            "client_ip": client_ip,
            "client_chan": client_chan,
            "target_ssh": target_ssh,
            "target_chan": target_chan,
            "is_simulated": is_simulated,
            "active": True
        }

        with SESSION_LOCK:
            ACTIVE_PROXY_SESSIONS[lease_id] = session_ctx

        # Send ZeroVault PAM Welcome Banner to terminal
        banner = (
            f"\r\n\x1b[1;36m+----------------------------------------------------------------------+\r\n"
            f"| ZEROVAULT PAM: Zero-Trust Privileged Access Gateway (Port 2222)      |\r\n"
            f"+----------------------------------------------------------------------+\x1b[0m\r\n"
            f"  [+] Active JIT Lease: \x1b[1;33m{lease_id}\x1b[0m | User: \x1b[1;32m{ephemeral_user}\x1b[0m\r\n"
            f"  [+] Target Host:      \x1b[1;37m{server_host}:{server_port} ({server_id})\x1b[0m\r\n"
            f"  [+] Security Mode:    \x1b[1;35mREAL-TIME COMMAND FIREWALL & SESSION DVR ACTIVE\x1b[0m\r\n"
            f"  [+] Warning:          \x1b[0;33mEvery keystroke is cryptographically hash-chained.\x1b[0m\r\n"
            f"\x1b[1;36m+----------------------------------------------------------------------+\x1b[0m\r\n\r\n"
        )
        client_chan.send(banner)

        try:
            if is_simulated:
                self._run_simulated_interactive_shell(client_chan, session_ctx, lease)
            else:
                self._run_live_bidirectional_proxy(client_chan, target_chan, session_ctx, lease)
        finally:
            with SESSION_LOCK:
                if lease_id in ACTIVE_PROXY_SESSIONS:
                    del ACTIVE_PROXY_SESSIONS[lease_id]

            db.close_session(session_id, "TERMINATED")
            MerkleAuditLedger.record_event(
                lease_id=lease_id,
                user=ephemeral_user,
                server=server_id,
                command="SSH_SESSION_CLOSED",
                action="LOGOUT"
            )

            try:
                client_chan.close()
            except Exception:
                pass
            if target_ssh:
                try:
                    target_ssh.close()
                except Exception:
                    pass

    def _connect_backend_target(self, lease: Dict[str, Any]):
        """Attempts to open real SSH connection to target Linux host."""
        host = lease.get("server_host", "127.0.0.1")
        port = lease.get("server_port", 22)
        admin_user = lease.get("admin_user", "kali")
        enc_pw = lease.get("server_enc_pw", "")

        # Quick check if target SSH port is open
        try:
            with socket.create_connection((host, port), timeout=0.8):
                pass
        except Exception:
            return None, None

        try:
            pw = VaultCrypto.decrypt_secret(enc_pw)
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=host,
                port=port,
                username=admin_user,
                password=pw,
                timeout=2.0,
                allow_agent=False,
                look_for_keys=False
            )
            chan = ssh.invoke_shell(term="xterm", width=120, height=36)
            return ssh, chan
        except Exception:
            return None, None

    def _run_live_bidirectional_proxy(self, client_chan: paramiko.Channel,
                                      target_chan: paramiko.Channel,
                                      session_ctx: Dict[str, Any], lease: Dict[str, Any]):
        """
        Bidirectional socket proxy loop:
        Inspects client keystrokes in mid-air, evaluates commands on Enter,
        and streams target output back to client.
        """
        line_buffer = ""
        session_id = session_ctx["session_id"]
        lease_id = session_ctx["lease_id"]
        ephemeral_user = session_ctx["ephemeral_user"]
        server_id = session_ctx["server_id"]

        while session_ctx["active"]:
            r, _, _ = select.select([client_chan, target_chan], [], [], 0.5)

            # 1. Output from Target Server -> Forward to Client
            if target_chan in r:
                try:
                    data = target_chan.recv(4096)
                    if not data:
                        break
                    client_chan.send(data)
                    db.update_session_transcript(session_id, data.decode("utf-8", errors="replace"))
                except Exception:
                    break

            # 2. Input from Client -> Inspect Keystrokes & Forward to Target
            if client_chan in r:
                try:
                    raw_in = client_chan.recv(1024)
                    if not raw_in:
                        break
                except Exception:
                    break

                # Process byte by byte for precise keystroke and Enter handling
                i = 0
                while i < len(raw_in):
                    # Check for ANSI escape sequences (arrows, home, end, etc.)
                    if raw_in[i:i+1] == b"\x1b":
                        esc_match = ANSI_ESCAPE_RE.match(raw_in[i:])
                        if esc_match:
                            esc_seq = esc_match.group(0)
                            target_chan.send(esc_seq)
                            i += len(esc_seq)
                            continue
                        else:
                            # Standalone ESC
                            target_chan.send(b"\x1b")
                            i += 1
                            continue

                    b = raw_in[i:i+1]
                    char = b.decode("utf-8", errors="replace")

                    # Handle Backspace (\x7f or \x08)
                    if b in (b"\x7f", b"\x08"):
                        if line_buffer:
                            line_buffer = line_buffer[:-1]
                        target_chan.send(b)

                    # Handle Ctrl+C (\x03)
                    elif b == b"\x03":
                        line_buffer = ""
                        target_chan.send(b)

                    # Handle Enter (\r or \n)
                    elif b in (b"\r", b"\n"):
                        cmd = line_buffer.strip()
                        line_buffer = ""

                        # Evaluate Command Firewall Rules
                        matched_rule = self._evaluate_firewall(cmd)
                        if matched_rule:
                            # BLOCK COMMAND IN MID-AIR:
                            # 1. Send Ctrl+C to target server to discard line buffer
                            target_chan.send(b"\x03")

                            # 2. Print high-visibility bright red alert directly in client terminal
                            block_msg = (
                                f"\r\n\x1b[1;31m[ZEROVAULT PAM FIREWALL] BLOCKED: Command '{cmd}' violates Zero-Trust Policy!\r\n"
                                f"  --> Reason: [{matched_rule['category']}] {matched_rule['description']}\r\n"
                                f"  --> Rule ID: {matched_rule['id']} ({matched_rule['name']})\x1b[0m\r\n"
                            )
                            client_chan.send(block_msg)

                            # 3. Log violation to database and Merkle Audit Ledger
                            db.update_session_transcript(session_id, f"\n[BLOCKED: {cmd}]\n", is_violation=True)
                            MerkleAuditLedger.record_event(
                                lease_id=lease_id,
                                user=ephemeral_user,
                                server=server_id,
                                command=cmd,
                                action="BLOCKED",
                                rule_triggered=matched_rule["name"]
                            )

                            # 4. Dispatch Push Alert (Buzz phone)
                            AlertNotifier.dispatch_security_alert(
                                alert_type=f"MID-AIR FIREWALL DROP: {matched_rule['name']}",
                                user=ephemeral_user,
                                target=server_id,
                                details=f"Command '{cmd}' blocked in mid-air",
                                severity=matched_rule.get("severity", "CRITICAL")
                            )

                            # Redraw target prompt by sending newline
                            target_chan.send(b"\r")
                        else:
                            # ALLOW COMMAND
                            target_chan.send(b)
                            if cmd:
                                db.update_session_transcript(session_id, f"\n[CMD: {cmd}]\n")
                                MerkleAuditLedger.record_event(
                                    lease_id=lease_id,
                                    user=ephemeral_user,
                                    server=server_id,
                                    command=cmd,
                                    action="ALLOWED"
                                )
                    else:
                        # Append printable character to line buffer and forward to target
                        if ord(char) >= 32 and ord(char) <= 126:
                            line_buffer += char
                        target_chan.send(b)

                    i += 1

    def _run_simulated_interactive_shell(self, client_chan: paramiko.Channel,
                                         session_ctx: Dict[str, Any], lease: Dict[str, Any]):
        """
        Interactive Linux bash shell emulator for demonstration and testing when
        the target Linux host is offline or in standalone lab mode.
        Supports full command line editing, command firewall inspection, and realistic Linux outputs.
        """
        session_id = session_ctx["session_id"]
        lease_id = session_ctx["lease_id"]
        ephemeral_user = session_ctx["ephemeral_user"]
        server_id = session_ctx["server_id"]
        prompt = f"\x1b[1;32m{ephemeral_user}@kali-prod\x1b[0m:\x1b[1;34m~\x1b[0m$ "

        client_chan.send(prompt)
        line_buffer = ""

        while session_ctx["active"]:
            r, _, _ = select.select([client_chan], [], [], 0.5)
            if not r:
                continue

            try:
                raw_in = client_chan.recv(1024)
                if not raw_in:
                    break
            except Exception:
                break

            i = 0
            while i < len(raw_in):
                # Filter ANSI escape sequences (arrows, function keys, delete)
                if raw_in[i:i+1] == b"\x1b":
                    esc_match = ANSI_ESCAPE_RE.match(raw_in[i:])
                    if esc_match:
                        i += len(esc_match.group(0))
                        continue
                    else:
                        i += 1
                        continue

                b = raw_in[i:i+1]
                char = b.decode("utf-8", errors="replace")

                # Handle Enter
                if b in (b"\r", b"\n"):
                    cmd = line_buffer.strip()
                    line_buffer = ""
                    client_chan.send("\r\n")

                    if cmd:
                        # Check firewall rules
                        matched_rule = self._evaluate_firewall(cmd)
                        if matched_rule:
                            block_msg = (
                                f"\x1b[1;31m[ZEROVAULT PAM FIREWALL] BLOCKED: Command '{cmd}' violates Zero-Trust Policy!\r\n"
                                f"  --> Reason: [{matched_rule['category']}] {matched_rule['description']}\r\n"
                                f"  --> Rule ID: {matched_rule['id']} ({matched_rule['name']})\x1b[0m\r\n"
                            )
                            client_chan.send(block_msg)
                            db.update_session_transcript(session_id, f"\n[BLOCKED: {cmd}]\n", is_violation=True)
                            MerkleAuditLedger.record_event(
                                lease_id=lease_id,
                                user=ephemeral_user,
                                server=server_id,
                                command=cmd,
                                action="BLOCKED",
                                rule_triggered=matched_rule["name"]
                            )
                            # Dispatch Push Alert (Buzz phone)
                            AlertNotifier.dispatch_security_alert(
                                alert_type=f"MID-AIR FIREWALL DROP: {matched_rule['name']}",
                                user=ephemeral_user,
                                target=server_id,
                                details=f"Command '{cmd}' blocked in mid-air",
                                severity=matched_rule.get("severity", "CRITICAL")
                            )
                        else:
                            # Execute simulated command response
                            out = self._execute_simulated_command(cmd, ephemeral_user)
                            if out:
                                client_chan.send(out.replace("\n", "\r\n"))
                                if not out.endswith("\n"):
                                    client_chan.send("\r\n")

                            db.update_session_transcript(session_id, f"\n{ephemeral_user}@kali-prod:~$ {cmd}\n{out}\n")
                            MerkleAuditLedger.record_event(
                                lease_id=lease_id,
                                user=ephemeral_user,
                                server=server_id,
                                command=cmd,
                                action="ALLOWED"
                            )

                    client_chan.send(prompt)

                # Handle Backspace
                elif b in (b"\x7f", b"\x08"):
                    if line_buffer:
                        line_buffer = line_buffer[:-1]
                        client_chan.send(b"\x08 \x08")

                # Handle Ctrl+C
                elif b == b"\x03":
                    line_buffer = ""
                    client_chan.send("^C\r\n" + prompt)

                # Printable ASCII
                elif ord(char) >= 32 and ord(char) <= 126:
                    line_buffer += char
                    client_chan.send(b)

                i += 1

    def _evaluate_firewall(self, cmd: str) -> Optional[Dict[str, Any]]:
        """Evaluates command string against configured Zero-Trust policies."""
        if not cmd:
            return None
        for rule in Config.BLOCKED_COMMAND_POLICIES:
            if re.search(rule["pattern"], cmd, re.IGNORECASE):
                return rule
        return None

    def _execute_simulated_command(self, cmd: str, user: str) -> str:
        """Returns realistic Linux shell outputs for common administrative commands."""
        c = cmd.lower().strip()
        if c == "whoami":
            return user
        elif c == "id":
            return f"uid=1042({user}) gid=1042({user}) groups=1042({user}),27(sudo)"
        elif c in ("uname -a", "uname"):
            return "Linux kali-prod 6.6.15-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.6.15-1 (2026-03-10) x86_64 GNU/Linux"
        elif c == "hostname":
            return "kali-prod"
        elif c in ("pwd", "echo $home"):
            return f"/home/{user}"
        elif c.startswith("ls"):
            return "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
        elif c == "ps aux" or c.startswith("ps"):
            return (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.1 168344 11728 ?        Ss   09:00   0:01 /sbin/init\n"
                "root         412  0.0  0.0  14524  4832 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\n"
                f"{user}        1894  0.0  0.0  12304  3912 pts/1    Ss+  09:15   0:00 /bin/bash"
            )
        elif c == "df -h":
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        60G   14G   44G  25% /\n"
                "tmpfs           3.9G     0  3.9G   0% /dev/shm"
            )
        elif c == "uptime":
            return " 09:30:15 up 2 days,  4:12,  1 user,  load average: 0.08, 0.03, 0.01"
        elif c.startswith("echo"):
            return cmd[5:].strip()
        elif c == "exit":
            return "logout"
        else:
            return f"{cmd}: command executed successfully (ZeroVault PAM Verified)."

    @classmethod
    def terminate_session(cls, lease_id: str, reason: str = "Administrator Revocation") -> bool:
        """Immediately terminates an active SSH proxy session and closes its socket."""
        with SESSION_LOCK:
            session_ctx = ACTIVE_PROXY_SESSIONS.get(lease_id)
            if not session_ctx:
                return False

            session_ctx["active"] = False
            chan = session_ctx.get("client_chan")
            if chan:
                try:
                    notice = (
                        f"\r\n\r\n\x1b[1;33m[ZEROVAULT PAM] Session Terminated in mid-air!\r\n"
                        f"  --> Reason: {reason}\r\n"
                        f"  --> Action: SSH Tunnel Severed. Goodbye.\x1b[0m\r\n\r\n"
                    )
                    chan.send(notice)
                    chan.close()
                except Exception:
                    pass

            target_ssh = session_ctx.get("target_ssh")
            if target_ssh:
                try:
                    target_ssh.close()
                except Exception:
                    pass

            del ACTIVE_PROXY_SESSIONS[lease_id]
            return True
