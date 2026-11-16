import re
import sqlite3
from typing import Dict, Any, List, Tuple, ClassVar
from pam_backend.config import Config
from pam_backend.audit_ledger import MerkleAuditLedger
from pam_backend.notifier import AlertNotifier

class SQLFirewall:
    """
    Zero-Trust Database SQL Protocol Proxy & Mid-Air Query Firewall.
    Inspects SQL query statements in real time before execution against the database.
    Blocks destructive DDL, mass exfiltration of sensitive columns (credit cards,
    hashes, SSN), and unauthorized privilege grants.
    """

    SQL_POLICIES: ClassVar[List[Dict[str, Any]]] = [
        {
            "id": "SQL-DESTR-01",
            "name": "DESTRUCTIVE_DDL_DROP_TRUNCATE",
            "category": "Destructive Database Action",
            "pattern": r"\b(DROP\s+(TABLE|DATABASE|SCHEMA|VIEW)|TRUNCATE(\s+TABLE)?)\b",
            "severity": "CRITICAL",
            "description": "Attempt to drop or wipe production database tables/schemas."
        },
        {
            "id": "SQL-EXFIL-02",
            "name": "SENSITIVE_DATA_EXFILTRATION",
            "category": "Data Exfiltration (PII/Financial)",
            "pattern": r"\bSELECT\b.*?\b(credit_cards|card_numbers|cvv|passwords|password_hashes|ssn|auth_tokens|bank_accounts)\b",
            "severity": "CRITICAL",
            "description": "Attempt to dump unmasked payment cards, customer SSNs, or password hashes."
        },
        {
            "id": "SQL-WIPE-03",
            "name": "UNRESTRICTED_MASS_DELETE_UPDATE",
            "category": "Data Tampering",
            "pattern": r"\b(DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b(?!\s*.*\bWHERE\b\s*\w+)",
            "severity": "HIGH",
            "description": "Mass update or delete without restrictive WHERE filter clause."
        },
        {
            "id": "SQL-PRIVESC-04",
            "name": "DATABASE_PRIVILEGE_ESCALATION",
            "category": "Privilege Escalation",
            "pattern": r"\b(GRANT\s+ALL|ALTER\s+USER.*SUPERUSER|CREATE\s+USER.*WITH\s+SUPERUSER)\b",
            "severity": "CRITICAL",
            "description": "Attempt to grant DBA or superuser privileges to an unprivileged account."
        }
    ]

    @classmethod
    def evaluate_query(cls, query: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Inspects SQL query against Zero-Trust policies.
        Strips inline/block comments first to eliminate firewall evasion loopholes.
        Returns: (is_allowed: bool, matched_rule: dict or None)
        """
        # 1. Strip multiline comments /* ... */
        cleaned = re.sub(r"/\*.*?\*/", " ", query, flags=re.DOTALL)
        # 2. Strip single-line comments -- ...
        cleaned = re.sub(r"--.*$", " ", cleaned, flags=re.MULTILINE)
        # 3. Normalize whitespace
        cleaned = re.sub(r"\s+", " ", cleaned).strip()

        for policy in cls.SQL_POLICIES:
            if re.search(policy["pattern"], cleaned, re.IGNORECASE):
                return False, policy

        return True, None

    @classmethod
    def execute_inspected_query(cls, user: str, db_name: str, query: str) -> Dict[str, Any]:
        """
        Processes a database query through the SQL Firewall:
        - If allowed: executes against database and logs to Merkle ledger.
        - If blocked: drops execution, logs violation to Merkle ledger, and buzzes admin phone.
        """
        is_allowed, matched_policy = cls.evaluate_query(query)

        if not is_allowed:
            # 1. Log to Merkle Audit Ledger
            MerkleAuditLedger.record_event(
                lease_id="DB_SQL_SESSION",
                user=user,
                server=f"DATABASE:{db_name}",
                command=f"SQL: {query}",
                action="BLOCKED",
                rule_triggered=matched_policy["name"]
            )

            # 2. Dispatch Push Alert (Buzz phone)
            AlertNotifier.dispatch_security_alert(
                alert_type="DATABASE SQL FIREWALL VIOLATION",
                user=user,
                target=f"Database: {db_name}",
                details=f"Blocked query '{query[:60]}...' [Rule: {matched_policy['name']}]",
                severity=matched_policy["severity"]
            )

            return {
                "success": False,
                "status": "BLOCKED_BY_FIREWALL",
                "rule_id": matched_policy["id"],
                "rule_name": matched_policy["name"],
                "category": matched_policy["category"],
                "description": matched_policy["description"],
                "query": query,
                "message": f"[ZEROVAULT SQL FIREWALL] Query rejected: {matched_policy['description']}"
            }

        # Query is safe - execute against demonstration/in-memory database
        results, columns = cls._execute_safe_sql(query)

        if columns == ["error"]:
            return {
                "success": False,
                "status": "SQL_ERROR",
                "message": results[0]["error"] if results else "Database execution error",
                "columns": [],
                "rows": [],
                "query": query
            }

        # Log safe query to Merkle Ledger
        MerkleAuditLedger.record_event(
            lease_id="DB_SQL_SESSION",
            user=user,
            server=f"DATABASE:{db_name}",
            command=f"SQL: {query}",
            action="ALLOWED"
        )

        return {
            "success": True,
            "status": "EXECUTED",
            "columns": columns,
            "rows": results,
            "row_count": len(results),
            "query": query
        }

    @staticmethod
    def _execute_safe_sql(query: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Executes safe read-only SQL query against a mock financial schema."""
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()

        # Initialize mock financial database schema
        cursor.execute("CREATE TABLE customers (id INT, name TEXT, email TEXT, tier TEXT)")
        cursor.execute("INSERT INTO customers VALUES (1, 'Alice Smith', 'alice@corp.com', 'Enterprise')")
        cursor.execute("INSERT INTO customers VALUES (2, 'Bob Mehta', 'bob@bank.com', 'Premium')")
        cursor.execute("INSERT INTO customers VALUES (3, 'Charlie Roy', 'charlie@fintech.io', 'Standard')")

        cursor.execute("CREATE TABLE server_clusters (id INT, hostname TEXT, region TEXT, status TEXT)")
        cursor.execute("INSERT INTO server_clusters VALUES (1, 'prod-api-sg-01', 'ap-southeast-1', 'HEALTHY')")
        cursor.execute("INSERT INTO server_clusters VALUES (2, 'prod-db-us-02', 'us-east-1', 'HEALTHY')")
        cursor.execute("INSERT INTO server_clusters VALUES (3, 'backup-vault-eu', 'eu-west-1', 'STANDBY')")

        rows = []
        columns = []
        try:
            cursor.execute(query)
            if cursor.description:
                columns = [d[0] for d in cursor.description]
                for r in cursor.fetchall():
                    rows.append(dict(zip(columns, r)))
        except Exception as e:
            rows = [{"error": str(e)}]
            columns = ["error"]
        finally:
            conn.close()

        return rows, columns
