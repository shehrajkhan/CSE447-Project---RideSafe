"""
crypto/rsa.py - RSA, implemented from scratch.

Used for: registration data, profile fields (email, phone, address, vehicle info).

TODO (build in this order):
    1. Miller-Rabin primality test
    2. Large prime generation (e.g. 1024-bit primes p, q)
    3. Keypair generation: n = p*q, phi = (p-1)(q-1), e = 65537, d = e^-1 mod phi
    4. Encrypt/decrypt: c = m^e mod n , m = c^d mod n
       (chunk plaintext into blocks smaller than n, since RSA has a max
       message size per operation)

Do NOT change the function signatures below without updating crypto/__init__.py
and telling the team - the auth/profile routes call these directly.
"""

from typing import Tuple, Dict


def generate_keypair() -> Tuple[str, str]:
    """
    Generate an RSA keypair.

    Returns:
        (private_key, public_key) - suggest serializing as "n:d" and "n:e"
        hex/decimal strings so they drop straight into a text column.

    TODO: replace with real Miller-Rabin + keygen implementation.
    """
    return _generate_keypair_stub()


def encrypt(plaintext: bytes, public_key: str) -> Dict[str, str]:
    """
    RSA-encrypt plaintext under the recipient's public key.

    Returns a dict matching the shared format:
        {"scheme": "rsa", "ciphertext": ..., "mac": ""}

    Note: "mac" is left empty here - whoever owns sessions/RBAC's crypto/mac.py fills the
    real MAC tag over the ciphertext before storage.

    TODO: replace with real RSA encryption (remember to chunk long plaintext).
    """
    return _encrypt_stub(plaintext, public_key)


def decrypt(ciphertext_blob: Dict[str, str], private_key: str) -> bytes:
    """
    RSA-decrypt a blob produced by encrypt(), given the recipient's private key.

    TODO: replace with real RSA decryption.
    """
    return _decrypt_stub(ciphertext_blob, private_key)


# ---------------------------------------------------------------------------
# STUBS - used by the rest of the team until the real implementation above
# is ready. Pass-through only, NOT secure. Delete once real RSA is done.
# ---------------------------------------------------------------------------

def _generate_keypair_stub() -> Tuple[str, str]:
    return ("stub-rsa-private-key", "stub-rsa-public-key")


def _encrypt_stub(plaintext: bytes, public_key: str) -> Dict[str, str]:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    return {
        "scheme": "rsa-stub",
        "ciphertext": plaintext.decode("utf-8", errors="ignore"),
        "mac": "",
    }


def _decrypt_stub(ciphertext_blob: Dict[str, str], private_key: str) -> bytes:
    return ciphertext_blob.get("ciphertext", "").encode("utf-8")
