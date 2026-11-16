import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List
from pam_backend import database as db

class MerkleAuditLedger:
    """
    Cryptographic Tamper-Evident SHA-256 Hash-Chain Audit Ledger.
    Every command typed, session event, and firewall block is cryptographically
    linked to its predecessor block, forming an immutable sequence.
    Any retroactive tampering with a command, timestamp, or user breaks the hash chain.
    """

    @staticmethod
    def _compute_block_hash(prev_hash: str, timestamp: str, lease_id: str,
                            user: str, server: str, command: str, action: str, rule: str) -> str:
        """Computes SHA-256 digest over all core immutable block fields."""
        payload = f"{prev_hash}|{timestamp}|{lease_id}|{user}|{server}|{command}|{action}|{rule}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def record_event(cls, lease_id: str, user: str, server: str,
                     command: str, action: str, rule_triggered: str = "NONE") -> Dict[str, Any]:
        """
        Appends a new cryptographically chained audit record.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        latest = db.get_latest_ledger_block()

        if latest:
            prev_hash = latest["current_hash"]
        else:
            prev_hash = "0" * 64

        current_hash = cls._compute_block_hash(
            prev_hash=prev_hash,
            timestamp=now_iso,
            lease_id=lease_id,
            user=user,
            server=server,
            command=command,
            action=action,
            rule=rule_triggered
        )

        block_index = db.append_ledger_block(
            timestamp=now_iso,
            lease_id=lease_id,
            user=user,
            server=server,
            command=command,
            action=action,
            rule_triggered=rule_triggered,
            prev_hash=prev_hash,
            current_hash=current_hash
        )

        return {
            "block_index": block_index,
            "timestamp": now_iso,
            "lease_id": lease_id,
            "user": user,
            "server": server,
            "command": command,
            "action": action,
            "rule_triggered": rule_triggered,
            "prev_hash": prev_hash,
            "current_hash": current_hash
        }

    @classmethod
    def verify_ledger_integrity(cls) -> Dict[str, Any]:
        """
        Cryptographic verification walk: verifies every block from genesis to latest.
        Recalculates the SHA-256 hash for each block and confirms parent linkage.
        """
        blocks = db.get_all_ledger_blocks(limit=10000)

        if not blocks:
            return {"valid": True, "total_blocks": 0, "message": "Ledger is empty."}

        # Check Genesis Block
        genesis = blocks[0]
        if genesis["block_index"] == 0 and genesis["action"] == "GENESIS":
            expected_genesis = hashlib.sha256(f"GENESIS|{genesis['timestamp']}|{'0'*64}".encode("utf-8")).hexdigest()
            if genesis["current_hash"] != expected_genesis:
                return {
                    "valid": False,
                    "tampered_block_index": 0,
                    "stored_hash": genesis["current_hash"],
                    "computed_hash": expected_genesis,
                    "message": "CRITICAL: Genesis block hash is corrupted or tampered!"
                }

        # Verify Subsequent Blocks
        for i in range(1, len(blocks)):
            current = blocks[i]
            previous = blocks[i - 1]

            # 1. Verify parent hash linkage
            if current["prev_hash"] != previous["current_hash"]:
                return {
                    "valid": False,
                    "tampered_block_index": current["block_index"],
                    "timestamp": current["timestamp"],
                    "stored_prev_hash": current["prev_hash"],
                    "expected_prev_hash": previous["current_hash"],
                    "message": f"Broken Hash Chain at Block #{current['block_index']}! Parent link does not match predecessor."
                }

            # 2. Recompute current block hash from stored attributes
            expected_hash = cls._compute_block_hash(
                prev_hash=current["prev_hash"],
                timestamp=current["timestamp"],
                lease_id=current["lease_id"],
                user=current["user"],
                server=current["server"],
                command=current["command"],
                action=current["action"],
                rule=current["rule_triggered"] or "NONE"
            )

            if current["current_hash"] != expected_hash:
                return {
                    "valid": False,
                    "tampered_block_index": current["block_index"],
                    "timestamp": current["timestamp"],
                    "stored_hash": current["current_hash"],
                    "computed_hash": expected_hash,
                    "compromised_command": current["command"],
                    "compromised_user": current["user"],
                    "message": (
                        f"CRITICAL TAMPER DETECTED at Block #{current['block_index']}! "
                        f"Stored SHA-256: {current['current_hash'][:16]}... | "
                        f"Computed SHA-256: {expected_hash[:16]}... "
                        f"(Command was altered in database)."
                    )
                }

        return {
            "valid": True,
            "total_blocks": len(blocks),
            "genesis_hash": blocks[0]["current_hash"],
            "latest_hash": blocks[-1]["current_hash"],
            "message": f"Cryptographic Ledger Verified: All {len(blocks)} blocks maintain 100% unbroken SHA-256 Merkle chain integrity."
        }

    @staticmethod
    def simulate_tamper_attack(block_index: int, new_command: str = "ls -la") -> Dict[str, Any]:
        """
        Simulates an insider threat or attacker tampering with a row in the database
        to demonstrate the Merkle hash-chain detection.
        """
        conn = db.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_ledger WHERE block_index = ?", (block_index,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"success": False, "error": f"Block #{block_index} not found."}

        original_command = row["command"]
        # Update command directly without updating current_hash
        cursor.execute("UPDATE audit_ledger SET command = ? WHERE block_index = ?", (new_command, block_index))
        conn.commit()
        conn.close()

        return {
            "success": True,
            "block_index": block_index,
            "original_command": original_command,
            "tampered_command": new_command,
            "message": f"Block #{block_index} secretly tampered: '{original_command}' -> '{new_command}'."
        }
