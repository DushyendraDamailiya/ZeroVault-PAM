import os
from pathlib import Path
from typing import ClassVar, List, Dict, Any

BASE_DIR = Path(__file__).resolve().parent

class Config:
    BASE_DIR = BASE_DIR
    PROJECT_NAME = "ZeroVault PAM"
    PROJECT_SUBTITLE = "Zero-Trust Privileged Access Management & Live SSH Protocol Proxy"
    VERSION = "1.0.0"

    # Web Dashboard API
    PORT = int(os.environ.get("ZEROVAULT_PORT", "5005"))
    DEBUG = False

    # Live SSH Protocol Proxy Gateway
    SSH_PROXY_HOST = os.environ.get("SSH_PROXY_HOST", "0.0.0.0")
    SSH_PROXY_PORT = int(os.environ.get("SSH_PROXY_PORT", "2222"))

    # Cryptographic Vault Settings
    # Master Key Encryption Key (KEK) passphrase
    VAULT_MASTER_PASSPHRASE = os.environ.get("ZEROVAULT_MASTER_KEY", "ZeroVault-MasterSecret-Key-2026-Enterprise!")
    PBKDF2_ITERATIONS = 600000  # OWASP standard for PBKDF2-HMAC-SHA256
    
    # Database Settings: 'sqlite' (zero-setup embedded SQL) or 'mysql' (enterprise MySQL server)
    DB_TYPE = os.environ.get("ZEROVAULT_DB_TYPE", "sqlite").lower()
    DATABASE_PATH = os.environ.get("ZEROVAULT_DB_PATH", str(BASE_DIR / "zerovault_pam.db"))
    RSA_HOST_KEY_PATH = str(BASE_DIR / "zerovault_rsa.key")

    # Enterprise MySQL Connection Settings (active when ZEROVAULT_DB_TYPE=mysql)
    MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
    MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
    MYSQL_USER = os.environ.get("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
    MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "zerovault_pam")

    # JIT Ephemeral Access Settings
    DEFAULT_LEASE_TTL_MINUTES = 15
    REAPER_INTERVAL_SECONDS = 3
    ROTATION_INTERVAL_HOURS = 24

    # Real-Time Push Notification & Phone Buzz Settings
    TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN_HERE")
    TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "YOUR_TELEGRAM_CHAT_ID_HERE")
    WEBHOOK_ALERT_URL = os.environ.get("WEBHOOK_ALERT_URL", "https://discord.com/api/webhooks/1571803639922819234/61koZhaNs1J1jIBqsVgvW4xG-0FsaSQVGWQBY5Fxs4wxYtdeIor_lqOZGw-32aQz3O2z")

    # Mid-Stream Command Firewall Rules
    BLOCKED_COMMAND_POLICIES: ClassVar[List[Dict[str, Any]]] = [
        {
            "id": "RULE-CRED-01",
            "name": "CREDENTIAL_FILE_ACCESS",
            "category": "Credential Access",
            "pattern": r"\b(cat|less|more|head|tail|nano|vim|vi|awk|sed|grep)\b.*(/etc/shadow|/etc/gshadow|/etc/master\.passwd)",
            "severity": "CRITICAL",
            "description": "Attempt to read sensitive OS password hash database."
        },
        {
            "id": "RULE-DESTR-02",
            "name": "DESTRUCTIVE_FILESYSTEM_WIPE",
            "category": "Destructive Action",
            "pattern": r"\brm\s+(-[a-zA-Z]*[rfRF][a-zA-Z]*\s+|--no-preserve-root\s+)*(/|/\*|~|/\w+)",
            "severity": "CRITICAL",
            "description": "Attempt to execute recursive root filesystem deletion."
        },
        {
            "id": "RULE-PRIVESC-03",
            "name": "UNAUTHORIZED_ROOT_ESCAPE",
            "category": "Privilege Escalation",
            "pattern": r"\b(sudo\s+su(\s+-)?|sudo\s+-i|su\s+-|visudo|passwd\s+root)\b",
            "severity": "CRITICAL",
            "description": "Attempt to escape JIT ephemeral user boundary to permanent root shell."
        },
        {
            "id": "RULE-EXFIL-04",
            "name": "REVERSE_SHELL_OR_EXFILTRATION",
            "category": "Lateral Movement / Exfiltration",
            "pattern": r"(nc\s+.*-e\s+|ncat\s+.*-e\s+|/dev/tcp/|/dev/udp/|(curl|wget)\s+.*\|\s*(sudo\s+)?(bash|sh|python|perl))",
            "severity": "CRITICAL",
            "description": "Attempt to spawn an unmonitored reverse shell or pipe remote script to bash."
        },
        {
            "id": "RULE-PERM-05",
            "name": "INSECURE_PERMISSIONS_OVERWRITE",
            "category": "Defense Evasion",
            "pattern": r"\bchmod\s+(-R\s+)?(777|666)\s+(/|/etc|/bin|/sbin|/usr|/var)",
            "severity": "HIGH",
            "description": "Attempt to grant unrestricted write permissions to system directories."
        }
    ]
