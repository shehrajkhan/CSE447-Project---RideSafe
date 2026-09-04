"""
crypto/key_wrap.py - Private Key Encryption & Wrapping Module.

Derives a Key Encryption Key (KEK) from the user's password + salt to securely
encrypt RSA and ECC private keys before storing them in Supabase.
"""

import hashlib


def derive_kek(password: str, salt: str) -> bytes:
    """Derive a 32-byte Key Encryption Key (KEK) using iterated SHA-256."""
    salt_bytes = bytes.fromhex(salt) if isinstance(salt, str) else salt
    digest = hashlib.sha256(salt_bytes + password.encode("utf-8")).digest()
    for i in range(2_000):
        digest = hashlib.sha256(digest + salt_bytes + i.to_bytes(4, "big")).digest()
    return digest


def wrap_private_key(privkey_str: str, password: str, salt: str) -> str:
    """Encrypt a private key string using XOR keystream derived from KEK."""
    if not privkey_str:
        return ""
    kek = derive_kek(password, salt)
    plain_bytes = privkey_str.encode("utf-8")

    keystream = bytearray()
    counter = 0
    while len(keystream) < len(plain_bytes):
        keystream.extend(hashlib.sha256(kek + counter.to_bytes(4, "big")).digest())
        counter += 1

    cipher = bytes(p ^ k for p, k in zip(plain_bytes, keystream[: len(plain_bytes)]))
    return cipher.hex()


def unwrap_private_key(wrapped_hex: str, password: str, salt: str) -> str:
    """Decrypt a private key hex string using XOR keystream derived from KEK."""
    if not wrapped_hex:
        return ""
    kek = derive_kek(password, salt)
    cipher_bytes = bytes.fromhex(wrapped_hex)

    keystream = bytearray()
    counter = 0
    while len(keystream) < len(cipher_bytes):
        keystream.extend(hashlib.sha256(kek + counter.to_bytes(4, "big")).digest())
        counter += 1

    plain = bytes(c ^ k for c, k in zip(cipher_bytes, keystream[: len(cipher_bytes)]))
    return plain.decode("utf-8", errors="replace")
