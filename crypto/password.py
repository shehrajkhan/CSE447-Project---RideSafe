"""
crypto/password.py

Salted + Hashed password routine implemented from scratch using a custom
iterated hashing loop (incorporating salt + password + counter over SHA-256)
without relying on built-in PBKDF2 / Bcrypt / Argon2 functions.
"""

import hashlib
import os
import secrets

ITERATIONS = 10_000


def _custom_salt_hash(password: str, salt_bytes: bytes) -> str:
    """
    Custom iterated salted-hash construction built from scratch.
    Repeatedly transforms the digest together with salt and iteration counter.
    """
    pwd_bytes = password.encode("utf-8")
    digest = hashlib.sha256(salt_bytes + pwd_bytes).digest()
    for i in range(ITERATIONS):
        digest = hashlib.sha256(digest + salt_bytes + i.to_bytes(4, "big")).digest()
    return digest.hex()


def hash_password(password: str) -> tuple:
    """
    Generates a random 16-byte salt and returns (hash_hex, salt_hex).
    """
    salt_bytes = os.urandom(16)
    salt_hex = salt_bytes.hex()
    hash_hex = _custom_salt_hash(password, salt_bytes)
    return hash_hex, salt_hex


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """
    Verifies a plaintext password against stored_hash and salt using constant-time comparison.
    """
    try:
        salt_bytes = bytes.fromhex(salt)
    except ValueError:
        return False
    check_hex = _custom_salt_hash(password, salt_bytes)
    return secrets.compare_digest(check_hex, stored_hash)
