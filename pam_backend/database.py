import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from pam_backend.config import Config
from pam_backend.vault_crypto import VaultCrypto

DB_PATH = Config.DATABASE_PATH

def get_db_connection():
    """Returns a thread-safe connection to the SQLite database with WAL mode and busy timeout."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

def init_db():
    """Initializes the ZeroVault PAM database schema and default server credentials."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Enrolled Target Servers Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        ssh_port INTEGER NOT NULL DEFAULT 22,
        admin_user TEXT NOT NULL,
        encrypted_password TEXT NOT NULL,
        last_rotated_at TEXT,
        status TEXT DEFAULT 'ONLINE',
        created_at TEXT NOT NULL
    )
    """)

    # 2. Just-In-Time (JIT) Ephemeral Leases Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS leases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        lease_id TEXT UNIQUE NOT NULL,
        server_id TEXT NOT NULL,
        requester TEXT NOT NULL,
        reason TEXT NOT NULL,
        ephemeral_user TEXT NOT NULL,
        ephemeral_password_enc TEXT NOT NULL,
        ttl_minutes INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        revoked_at TEXT,
        FOREIGN KEY (server_id) REFERENCES servers(server_id)
    )
    """)

    # 3. Tamper-Evident Merkle Cryptographic Hash-Chain Ledger
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_ledger (
        block_index INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        lease_id TEXT NOT NULL,
        user TEXT NOT NULL,
        server TEXT NOT NULL,
        command TEXT NOT NULL,
        action TEXT NOT NULL,
        rule_triggered TEXT,
        prev_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL
    )
    """)

    # 4. Live SSH Proxy Sessions & Terminal DVR Transcripts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        lease_id TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        status TEXT DEFAULT 'ACTIVE',
        commands_count INTEGER DEFAULT 0,
        violations_count INTEGER DEFAULT 0,
        transcript TEXT DEFAULT '',
        FOREIGN KEY (lease_id) REFERENCES leases(lease_id)
    )
    """)

    # Pre-populate Genesis Block in Audit Ledger if table is empty
    cursor.execute("SELECT COUNT(*) as count FROM audit_ledger")
    if cursor.fetchone()["count"] == 0:
        now_iso = datetime.now(timezone.utc).isoformat()
        import hashlib
        genesis_prev = "0" * 64
        genesis_hash = hashlib.sha256(f"GENESIS|{now_iso}|{genesis_prev}".encode("utf-8")).hexdigest()
        cursor.execute("""
        INSERT INTO audit_ledger (
            block_index, timestamp, lease_id, user, server, command, action, rule_triggered, prev_hash, current_hash
        ) VALUES (0, ?, 'SYSTEM', 'SYSTEM', 'ZEROVAULT_CORE', 'GENESIS_BLOCK_INITIALIZED', 'GENESIS', 'NONE', ?, ?)
        """, (now_iso, genesis_prev, genesis_hash))

    # Pre-populate enrolled servers if empty
    cursor.execute("SELECT COUNT(*) as count FROM servers")
    if cursor.fetchone()["count"] == 0:
        now_str = datetime.now(timezone.utc).isoformat()
        # Default server 1: Kali Linux Production VM
        kali_enc = VaultCrypto.encrypt_secret("kali_master_root_pass_2026!")
        cursor.execute("""
        INSERT INTO servers (
            server_id, name, host, ssh_port, admin_user, encrypted_password, last_rotated_at, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "srv_kali_prod",
            "Kali Linux Production Core (Primary Bastion)",
            "127.0.0.1",
            22,
            "kali",
            kali_enc,
            now_str,
            "ONLINE",
            now_str
        ))

        # Default server 2: Ubuntu Cloud Database Server
        db_enc = VaultCrypto.encrypt_secret("postgres_admin_ultra_secure_pass!")
        cursor.execute("""
        INSERT INTO servers (
            server_id, name, host, ssh_port, admin_user, encrypted_password, last_rotated_at, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "srv_ubuntu_db",
            "Ubuntu Cloud Financial DB (PostgreSQL Host)",
            "192.168.1.150",
            22,
            "ubuntu_admin",
            db_enc,
            now_str,
            "ONLINE",
            now_str
        ))

    conn.commit()
    conn.close()

# --- Server Queries ---
def get_all_servers():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM servers ORDER BY created_at DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_server_by_id(server_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM servers WHERE server_id = ?", (server_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_server(server_id: str, name: str, host: str, ssh_port: int, admin_user: str, password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    enc_pw = VaultCrypto.encrypt_secret(password)
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO servers (
        server_id, name, host, ssh_port, admin_user, encrypted_password, last_rotated_at, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (server_id, name, host, ssh_port, admin_user, enc_pw, now_str, "ONLINE", now_str))
    conn.commit()
    conn.close()

def update_server_password(server_id: str, new_encrypted_password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    UPDATE servers SET encrypted_password = ?, last_rotated_at = ? WHERE server_id = ?
    """, (new_encrypted_password, now_str, server_id))
    conn.commit()
    conn.close()

# --- Lease Queries ---
def create_lease(lease_id: str, server_id: str, requester: str, reason: str,
                 ephemeral_user: str, ephemeral_password: str, ttl_minutes: int,
                 created_at: str, expires_at: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    enc_pw = VaultCrypto.encrypt_secret(ephemeral_password)
    cursor.execute("""
    INSERT INTO leases (
        lease_id, server_id, requester, reason, ephemeral_user, ephemeral_password_enc,
        ttl_minutes, created_at, expires_at, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
    """, (lease_id, server_id, requester, reason, ephemeral_user, enc_pw, ttl_minutes, created_at, expires_at))
    conn.commit()
    conn.close()

def get_all_leases(limit: int = 100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT l.*, s.name as server_name, s.host as server_host, s.ssh_port as server_port
    FROM leases l
    JOIN servers s ON l.server_id = s.server_id
    ORDER BY l.created_at DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_lease_by_id(lease_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT l.*, s.name as server_name, s.host as server_host, s.ssh_port as server_port, s.admin_user
    FROM leases l
    JOIN servers s ON l.server_id = s.server_id
    WHERE l.lease_id = ?
    """, (lease_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_active_leases():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT l.*, s.host as server_host, s.ssh_port as server_port, s.admin_user, s.encrypted_password as server_enc_pw
    FROM leases l
    JOIN servers s ON l.server_id = s.server_id
    WHERE l.status = 'ACTIVE'
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def update_lease_status(lease_id: str, status: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    UPDATE leases SET status = ?, revoked_at = ? WHERE lease_id = ?
    """, (status, now_str, lease_id))
    conn.commit()
    conn.close()

# --- Audit Ledger Queries ---
def get_latest_ledger_block():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_ledger ORDER BY block_index DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_ledger_blocks(limit: int = 200):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_ledger ORDER BY block_index ASC LIMIT ?", (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def append_ledger_block(timestamp: str, lease_id: str, user: str, server: str,
                        command: str, action: str, rule_triggered: str, prev_hash: str, current_hash: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO audit_ledger (
        timestamp, lease_id, user, server, command, action, rule_triggered, prev_hash, current_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, lease_id, user, server, command, action, rule_triggered, prev_hash, current_hash))
    block_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return block_id

# --- Session Queries ---
def create_session(session_id: str, lease_id: str, client_ip: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    INSERT INTO sessions (session_id, lease_id, client_ip, started_at, status)
    VALUES (?, ?, ?, ?, 'ACTIVE')
    """, (session_id, lease_id, client_ip, now_str))
    conn.commit()
    conn.close()

def update_session_transcript(session_id: str, appended_text: str, is_violation: bool = False):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE sessions
    SET transcript = transcript || ?,
        commands_count = commands_count + 1,
        violations_count = violations_count + ?
    WHERE session_id = ?
    """, (appended_text, 1 if is_violation else 0, session_id))
    conn.commit()
    conn.close()

def close_session(session_id: str, status: str = "TERMINATED"):
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now(timezone.utc).isoformat()
    cursor.execute("""
    UPDATE sessions SET ended_at = ?, status = ? WHERE session_id = ?
    """, (now_str, status, session_id))
    conn.commit()
    conn.close()

def get_active_sessions():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT s.*, l.requester, l.ephemeral_user, l.server_id, srv.name as server_name
    FROM sessions s
    JOIN leases l ON s.lease_id = l.lease_id
    JOIN servers srv ON l.server_id = srv.server_id
    WHERE s.status = 'ACTIVE'
    ORDER BY s.started_at DESC
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_session_by_id(session_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# --- KPIs ---
def get_kpis():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as count FROM servers")
    total_servers = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM leases WHERE status = 'ACTIVE'")
    active_leases = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM sessions WHERE status = 'ACTIVE'")
    active_sessions = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM audit_ledger WHERE action = 'BLOCKED'")
    blocked_commands = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM audit_ledger")
    total_ledger_blocks = cursor.fetchone()["count"]

    conn.close()
    return {
        "total_servers": total_servers,
        "active_leases": active_leases,
        "active_sessions": active_sessions,
        "blocked_commands": blocked_commands,
        "total_ledger_blocks": total_ledger_blocks,
        "ssh_proxy_port": Config.SSH_PROXY_PORT
    }
