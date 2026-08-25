"""
crypto/password.py

TEMPORARY password hashing so the app is runnable end-to-end right now.

This uses Python's built-in hashlib.pbkdf2_hmac, which IS a built-in
cryptographic function - the assignment requires the salted hash to be
hand-implemented from scratch, with no built-in hashing/crypto calls.

This file exists only so there's a working login flow to build and test
against today. Before submission, replace hash_password/verify_password
below with a hand-rolled iterated-hash construction (build your own
digest-and-salt loop rather than calling pbkdf2_hmac).
"""

import hashlib
import os


def hash_password(password: str) -> tuple:
    """Returns (hash_hex, salt_hex)."""
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), 100_000
    ).hex()
    return digest, salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    check = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), 100_000
    ).hex()
    return check == stored_hash
