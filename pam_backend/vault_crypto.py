import os
import json
import secrets
import string
from typing import Dict, Any
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pam_backend.config import Config

class VaultCrypto:
    """
    AES-256-GCM Envelope Encryption & Cryptographic Key Management Engine.
    Implements NIST SP 800-57 & OWASP Key Derivation Standards:
    - Master Key Encryption Key (KEK) derived via PBKDF2-HMAC-SHA256 (600,000 iterations).
    - Unique 256-bit Data Encryption Key (DEK) generated per secret.
    - Secret encrypted with AES-256-GCM (12-byte nonce + 128-bit authentication tag).
    - DEK wrapped using KEK via AES-256-GCM envelope.
    """

    @staticmethod
    def derive_kek(salt: bytes, passphrase: str = None) -> bytes:
        """Derives a 256-bit Key Encryption Key (KEK) from the master passphrase."""
        if passphrase is None:
            passphrase = Config.VAULT_MASTER_PASSPHRASE

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=Config.PBKDF2_ITERATIONS
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @classmethod
    def encrypt_secret(cls, plaintext: str, passphrase: str = None) -> str:
        """
        Encrypts a secret using AES-256-GCM envelope encryption.
        Returns serialized JSON envelope containing hex-encoded parameters.
        """
        if not plaintext:
            plaintext = ""

        # 1. Generate salt and derive KEK
        salt = os.urandom(16)
        kek = cls.derive_kek(salt, passphrase)

        # 2. Generate per-secret Data Encryption Key (DEK)
        dek = os.urandom(32)

        # 3. Encrypt plaintext with DEK using AES-256-GCM
        dek_nonce = os.urandom(12)
        aesgcm_dek = AESGCM(dek)
        ciphertext = aesgcm_dek.encrypt(dek_nonce, plaintext.encode("utf-8"), None)

        # 4. Wrap (encrypt) DEK with KEK using AES-256-GCM
        kek_nonce = os.urandom(12)
        aesgcm_kek = AESGCM(kek)
        encrypted_dek = aesgcm_kek.encrypt(kek_nonce, dek, None)

        envelope = {
            "version": "1.0",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": Config.PBKDF2_ITERATIONS,
            "cipher": "AES-256-GCM",
            "salt": salt.hex(),
            "kek_nonce": kek_nonce.hex(),
            "encrypted_dek": encrypted_dek.hex(),
            "dek_nonce": dek_nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

        return json.dumps(envelope)

    @classmethod
    def decrypt_secret(cls, envelope_json: str, passphrase: str = None) -> str:
        """
        Decrypts an envelope-encrypted secret using the master passphrase.
        """
        try:
            envelope = json.loads(envelope_json)
            salt = bytes.fromhex(envelope["salt"])
            kek_nonce = bytes.fromhex(envelope["kek_nonce"])
            encrypted_dek = bytes.fromhex(envelope["encrypted_dek"])
            dek_nonce = bytes.fromhex(envelope["dek_nonce"])
            ciphertext = bytes.fromhex(envelope["ciphertext"])

            # 1. Derive KEK
            kek = cls.derive_kek(salt, passphrase)

            # 2. Unwrap DEK with KEK
            aesgcm_kek = AESGCM(kek)
            dek = aesgcm_kek.decrypt(kek_nonce, encrypted_dek, None)

            # 3. Decrypt ciphertext with DEK
            aesgcm_dek = AESGCM(dek)
            plaintext_bytes = aesgcm_dek.decrypt(dek_nonce, ciphertext, None)

            return plaintext_bytes.decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Cryptographic decryption failed: Invalid key or corrupted envelope: {exc}")

    @staticmethod
    def generate_secure_password(length: int = 32) -> str:
        """Generates a high-entropy cryptographically random password."""
        charset = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
        return "".join(secrets.choice(charset) for _ in range(length))

    @staticmethod
    def generate_lease_id() -> str:
        """Generates a unique random lease token (e.g. lease_9f8a2b)."""
        return f"lease_{secrets.token_hex(4)}"

    @staticmethod
    def generate_ephemeral_username() -> str:
        """Generates an ephemeral Linux OS username (e.g. jit_u8421)."""
        return f"jit_u{secrets.randbelow(9000) + 1000}"
