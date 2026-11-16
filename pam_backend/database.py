import sqlite3
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from pam_backend.config import Config
from pam_backend.vault_crypto import VaultCrypto

class DBConnection:
    """
    Unified Relational Database Connection Adapter.
    Seamlessly supports both local persistent SQLite and Enterprise MySQL.
    """
    def __init__(self):
        self.db_type = getattr(Config, "DB_TYPE", "sqlite").lower()
        self.conn = None
        self.cursor_obj = None

        if self.db_type == "mysql":
            try:
                import mysql.connector
                self.conn = mysql.connector.connect(
                    host=Config.MYSQL_HOST,
                    port=Config.MYSQL_PORT,
                    user=Config.MYSQL_USER,
                    password=Config.MYSQL_PASSWORD,
                    database=Config.MYSQL_DATABASE,
                    autocommit=True
                )
                self.cursor_obj = self.conn.cursor(dictionary=True)
                return
            except Exception as e:
                print(f"[!] ZeroVault Notice: MySQL connection failed ({e}). Falling back to persistent SQLite.")
                self.db_type = "sqlite"

        # SQLite Mode (default, persistent, zero-configuration)
        db_path = getattr(Config, "DATABASE_PATH", str(Config.BASE_DIR / "zerovault_pam.db"))
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA busy_timeout=5000;")
        self.cursor_obj = self.conn.cursor()

    def cursor(self):
        return self

    def execute(self, sql: str, params: tuple = ()):
        if self.db_type == "mysql":
            # Convert SQLite placeholders and concatenation syntax to MySQL
            formatted_sql = sql.replace("?", "%s")
            if "transcript || %s" in formatted_sql or "transcript || ?" in formatted_sql:
                formatted_sql = formatted_sql.replace("transcript || %s", "CONCAT(IFNULL(transcript, ''), %s)")
                formatted_sql = formatted_sql.replace("transcript || ?", "CONCAT(IFNULL(transcript, ''), %s)")
            self.cursor_obj.execute(formatted_sql, params)
        else:
            self.cursor_obj.execute(sql, params)
        return self

    def fetchall(self):
        rows = self.cursor_obj.fetchall()
        if self.db_type == "mysql":
            return rows or []
        return [dict(r) for r in rows] if rows else []

    def fetchone(self):
        row = self.cursor_obj.fetchone()
        if not row:
            return None
        if self.db_type == "mysql":
            return row
        return dict(row)

    @property
    def lastrowid(self):
        return self.cursor_obj.lastrowid

    def commit(self):
        if self.conn:
            self.conn.commit()

    def close(self):
        try:
            if self.cursor_obj:
                self.cursor_obj.close()
        except Exception:
            pass
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass


def get_db_connection():
    """Returns a unified thread-safe connection to the active database engine."""
    return DBConnection()


def init_db():
    """Initializes the ZeroVault PAM database schema and default server credentials."""
    db_type = getattr(Config, "DB_TYPE", "sqlite").lower()

    if db_type == "mysql":
        try:
            import mysql.connector
            # Connect to MySQL server without database to ensure database exists
            raw_conn = mysql.connector.connect(
                host=Config.MYSQL_HOST,
                port=Config.MYSQL_PORT,
                user=Config.MYSQL_USER,
                password=Config.MYSQL_PASSWORD
            )
            c = raw_conn.cursor()
            c.execute(f"CREATE DATABASE IF NOT EXISTS `{Config.MYSQL_DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
            c.close()
            raw_conn.close()
        except Exception as exc:
            print(f"[!] MySQL database creation notice: {exc}")

    conn = get_db_connection()

    if conn.db_type == "mysql":
        # MySQL Schema
        conn.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            server_id VARCHAR(100) UNIQUE NOT NULL,
            name VARCHAR(255) NOT NULL,
            host VARCHAR(255) NOT NULL,
            ssh_port INT NOT NULL DEFAULT 22,
            admin_user VARCHAR(100) NOT NULL,
            encrypted_password TEXT NOT NULL,
            last_rotated_at VARCHAR(100),
            status VARCHAR(50) DEFAULT 'ONLINE',
            created_at VARCHAR(100) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS leases (
            id INT AUTO_INCREMENT PRIMARY KEY,
            lease_id VARCHAR(100) UNIQUE NOT NULL,
            server_id VARCHAR(100) NOT NULL,
            requester VARCHAR(100) NOT NULL,
            reason TEXT NOT NULL,
            ephemeral_user VARCHAR(100) NOT NULL,
            ephemeral_password_enc TEXT NOT NULL,
            ttl_minutes INT NOT NULL,
            created_at VARCHAR(100) NOT NULL,
            expires_at VARCHAR(100) NOT NULL,
            status VARCHAR(50) DEFAULT 'ACTIVE',
            revoked_at VARCHAR(100)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_ledger (
            block_index INT PRIMARY KEY,
            timestamp VARCHAR(100) NOT NULL,
            lease_id VARCHAR(100) NOT NULL,
            user VARCHAR(100) NOT NULL,
            server VARCHAR(100) NOT NULL,
            command TEXT NOT NULL,
            action VARCHAR(50) NOT NULL,
            rule_triggered VARCHAR(100),
            prev_hash VARCHAR(100) NOT NULL,
            current_hash VARCHAR(100) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id VARCHAR(100) PRIMARY KEY,
            lease_id VARCHAR(100) NOT NULL,
            client_ip VARCHAR(100) NOT NULL,
            started_at VARCHAR(100) NOT NULL,
            ended_at VARCHAR(100),
            status VARCHAR(50) DEFAULT 'ACTIVE',
            commands_count INT DEFAULT 0,
            violations_count INT DEFAULT 0,
            transcript MEDIUMTEXT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

    else:
        # SQLite Schema
        conn.execute("""
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

        conn.execute("""
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

        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_ledger (
            block_index INTEGER PRIMARY KEY,
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

        conn.execute("""
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
    conn.execute("SELECT COUNT(*) as count FROM audit_ledger")
    res = conn.fetchone()
    if res and res["count"] == 0:
        now_iso = datetime.now(timezone.utc).isoformat()
        genesis_prev = "0" * 64
        genesis_hash = hashlib.sha256(f"GENESIS|{now_iso}|{genesis_prev}".encode("utf-8")).hexdigest()
        conn.execute("""
        INSERT INTO audit_ledger (
            block_index, timestamp, lease_id, user, server, command, action, rule_triggered, prev_hash, current_hash
        ) VALUES (0, ?, 'SYSTEM', 'SYSTEM', 'ZEROVAULT_CORE', 'GENESIS_BLOCK_INITIALIZED', 'GENESIS', 'NONE', ?, ?)
        """, (now_iso, genesis_prev, genesis_hash))

    # Pre-populate enrolled servers if empty
    conn.execute("SELECT COUNT(*) as count FROM servers")
    res_srv = conn.fetchone()
    if res_srv and res_srv["count"] == 0:
        now_str = datetime.now(timezone.utc).isoformat()
        # Default server 1: Kali Linux Production VM
        kali_enc = VaultCrypto.encrypt_secret("kali_master_root_pass_2026!")
        conn.execute("""
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
        conn.execute("""
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
    conn.execute("SELECT * FROM servers ORDER BY created_at DESC")
    rows = conn.fetchall()
    conn.close()
    return rows


def get_server_by_id(server_id: str):
    conn = get_db_connection()
    conn.execute("SELECT * FROM servers WHERE server_id = ?", (server_id,))
    row = conn.fetchone()
    conn.close()
    return row


def add_server(server_id: str, name: str, host: str, ssh_port: int, admin_user: str, password: str):
    conn = get_db_connection()
    enc_pw = VaultCrypto.encrypt_secret(password)
    now_str = datetime.now(timezone.utc).isoformat()
    conn.execute("""
    INSERT INTO servers (
        server_id, name, host, ssh_port, admin_user, encrypted_password, last_rotated_at, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (server_id, name, host, ssh_port, admin_user, enc_pw, now_str, "ONLINE", now_str))
    conn.commit()
    conn.close()


def update_server_password(server_id: str, new_encrypted_password: str):
    conn = get_db_connection()
    now_str = datetime.now(timezone.utc).isoformat()
    conn.execute("""
    UPDATE servers SET encrypted_password = ?, last_rotated_at = ? WHERE server_id = ?
    """, (new_encrypted_password, now_str, server_id))
    conn.commit()
    conn.close()


# --- Lease Queries ---
def create_lease(lease_id: str, server_id: str, requester: str, reason: str,
                 ephemeral_user: str, ephemeral_password: str, ttl_minutes: int,
                 created_at: str, expires_at: str):
    conn = get_db_connection()
    enc_pw = VaultCrypto.encrypt_secret(ephemeral_password)
    conn.execute("""
    INSERT INTO leases (
        lease_id, server_id, requester, reason, ephemeral_user, ephemeral_password_enc,
        ttl_minutes, created_at, expires_at, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
    """, (lease_id, server_id, requester, reason, ephemeral_user, enc_pw, ttl_minutes, created_at, expires_at))
    conn.commit()
    conn.close()


def get_all_leases(limit: int = 100):
    """Returns all active, expired, and historical JIT leases using LEFT JOIN."""
    conn = get_db_connection()
    conn.execute("""
    SELECT l.*, COALESCE(s.name, l.server_id) as server_name, s.host as server_host, s.ssh_port as server_port
    FROM leases l
    LEFT JOIN servers s ON l.server_id = s.server_id
    ORDER BY l.created_at DESC LIMIT ?
    """, (limit,))
    rows = conn.fetchall()
    conn.close()
    return rows


def get_lease_by_id(lease_id: str):
    conn = get_db_connection()
    conn.execute("""
    SELECT l.*, COALESCE(s.name, l.server_id) as server_name, s.host as server_host, s.ssh_port as server_port, s.admin_user
    FROM leases l
    LEFT JOIN servers s ON l.server_id = s.server_id
    WHERE l.lease_id = ?
    """, (lease_id,))
    row = conn.fetchone()
    conn.close()
    return row


def get_active_leases():
    conn = get_db_connection()
    conn.execute("""
    SELECT l.*, s.host as server_host, s.ssh_port as server_port, s.admin_user, s.encrypted_password as server_enc_pw
    FROM leases l
    LEFT JOIN servers s ON l.server_id = s.server_id
    WHERE l.status = 'ACTIVE'
    """)
    rows = conn.fetchall()
    conn.close()
    return rows


def update_lease_status(lease_id: str, status: str):
    conn = get_db_connection()
    now_str = datetime.now(timezone.utc).isoformat()
    conn.execute("""
    UPDATE leases SET status = ?, revoked_at = ? WHERE lease_id = ?
    """, (status, now_str, lease_id))
    conn.commit()
    conn.close()


# --- Audit Ledger Queries ---
def get_latest_ledger_block():
    conn = get_db_connection()
    conn.execute("SELECT * FROM audit_ledger ORDER BY block_index DESC LIMIT 1")
    row = conn.fetchone()
    conn.close()
    return row


def get_all_ledger_blocks(limit: int = 200):
    conn = get_db_connection()
    conn.execute("SELECT * FROM audit_ledger ORDER BY block_index ASC LIMIT ?", (limit,))
    rows = conn.fetchall()
    conn.close()
    return rows


def append_ledger_block(timestamp: str, lease_id: str, user: str, server: str,
                        command: str, action: str, rule_triggered: str, prev_hash: str, current_hash: str):
    conn = get_db_connection()
    # Calculate next block index
    conn.execute("SELECT MAX(block_index) as max_idx FROM audit_ledger")
    row = conn.fetchone()
    next_idx = ((row["max_idx"] if row and row.get("max_idx") is not None else -1) + 1)

    conn.execute("""
    INSERT INTO audit_ledger (
        block_index, timestamp, lease_id, user, server, command, action, rule_triggered, prev_hash, current_hash
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (next_idx, timestamp, lease_id, user, server, command, action, rule_triggered, prev_hash, current_hash))
    conn.commit()
    conn.close()
    return next_idx


# --- Session Queries ---
def create_session(session_id: str, lease_id: str, client_ip: str):
    conn = get_db_connection()
    now_str = datetime.now(timezone.utc).isoformat()
    conn.execute("""
    INSERT INTO sessions (session_id, lease_id, client_ip, started_at, status)
    VALUES (?, ?, ?, ?, 'ACTIVE')
    """, (session_id, lease_id, client_ip, now_str))
    conn.commit()
    conn.close()


def update_session_transcript(session_id: str, appended_text: str, is_violation: bool = False):
    conn = get_db_connection()
    conn.execute("""
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
    now_str = datetime.now(timezone.utc).isoformat()
    conn.execute("""
    UPDATE sessions SET ended_at = ?, status = ? WHERE session_id = ?
    """, (now_str, status, session_id))
    conn.commit()
    conn.close()


def get_active_sessions():
    conn = get_db_connection()
    conn.execute("""
    SELECT s.*, l.requester, l.ephemeral_user, l.server_id, COALESCE(srv.name, l.server_id) as server_name
    FROM sessions s
    LEFT JOIN leases l ON s.lease_id = l.lease_id
    LEFT JOIN servers srv ON l.server_id = srv.server_id
    WHERE s.status = 'ACTIVE'
    ORDER BY s.started_at DESC
    """)
    rows = conn.fetchall()
    conn.close()
    return rows


def get_session_by_id(session_id: str):
    conn = get_db_connection()
    conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
    row = conn.fetchone()
    conn.close()
    return row


# --- KPIs ---
def get_kpis():
    conn = get_db_connection()

    conn.execute("SELECT COUNT(*) as count FROM servers")
    total_servers = (conn.fetchone() or {}).get("count", 0)

    conn.execute("SELECT COUNT(*) as count FROM leases WHERE status = 'ACTIVE'")
    active_leases = (conn.fetchone() or {}).get("count", 0)

    conn.execute("SELECT COUNT(*) as count FROM sessions WHERE status = 'ACTIVE'")
    active_sessions = (conn.fetchone() or {}).get("count", 0)

    conn.execute("SELECT COUNT(*) as count FROM audit_ledger WHERE action = 'BLOCKED'")
    blocked_commands = (conn.fetchone() or {}).get("count", 0)

    conn.execute("SELECT COUNT(*) as count FROM audit_ledger")
    total_ledger_blocks = (conn.fetchone() or {}).get("count", 0)

    active_db = getattr(conn, "db_type", "sqlite").upper()
    conn.close()

    return {
        "total_servers": total_servers,
        "active_leases": active_leases,
        "active_sessions": active_sessions,
        "blocked_commands": blocked_commands,
        "total_ledger_blocks": total_ledger_blocks,
        "ssh_proxy_port": Config.SSH_PROXY_PORT,
        "db_engine": f"{active_db} PERSISTENT"
    }
