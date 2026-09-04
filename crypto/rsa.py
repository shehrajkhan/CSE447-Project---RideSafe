"""
crypto/rsa.py - RSA Cryptosystem implemented completely FROM SCRATCH.

Includes:
  1. Extended Euclidean Algorithm (modular inverse)
  2. Miller-Rabin Primality Testing
  3. Large Prime Generation
  4. RSA Keypair Generation (n, e, d)
  5. Chunked RSA Encryption and Decryption
"""

import math
import secrets
from typing import Tuple, Dict, List


# ---------------------------------------------------------------------------
# 1. Modular Arithmetic & Extended Euclidean Algorithm
# ---------------------------------------------------------------------------
def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Greatest Common Divisor algorithm."""
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def mod_inverse(a: int, m: int) -> int:
    """Computes modular inverse of a modulo m: (a * inv) % m == 1."""
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return x % m


# ---------------------------------------------------------------------------
# 2. Miller-Rabin Primality Testing
# ---------------------------------------------------------------------------
def is_prime(n: int, k: int = 20) -> bool:
    """
    Miller-Rabin primality test.
    Returns True if n is probabilistically prime, False if composite.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as 2^s * d
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    # Perform k rounds of testing
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # random a in [2, n - 2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break

        if composite:
            return False

    return True


def generate_prime(bits: int = 256) -> int:
    """Generate a random prime of specified bit-length."""
    while True:
        # Generate random odd integer of bit-length `bits`
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1  # ensure highest bit and lowest bit are 1
        if is_prime(p):
            return p


# ---------------------------------------------------------------------------
# 3. RSA Keypair Generation
# ---------------------------------------------------------------------------
def generate_keypair(key_size: int = 512) -> Tuple[str, str]:
    """
    Generate an RSA keypair.
    key_size: total modulus size in bits (default 512 bits for fast performance).

    Returns:
        (private_key, public_key) as hex string pairs "n_hex:d_hex" and "n_hex:e_hex"
    """
    prime_bits = key_size // 2
    e = 65537

    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if math.gcd(e, phi) == 1:
            d = mod_inverse(e, phi)
            break

    priv_str = f"{n:x}:{d:x}"
    pub_str = f"{n:x}:{e:x}"
    return priv_str, pub_str


# ---------------------------------------------------------------------------
# 4. RSA Encryption & Decryption
# ---------------------------------------------------------------------------
def encrypt(plaintext: bytes, public_key: str) -> Dict[str, str]:
    """
    RSA-encrypt plaintext under the recipient's public key (n:e).
    Chunks plaintext into blocks smaller than n.

    Returns dict matching shared contract:
        {"scheme": "rsa", "ciphertext": "<hex_blocks>", "mac": ""}
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    try:
        n_hex, e_hex = public_key.split(":")
        n = int(n_hex, 16)
        e = int(e_hex, 16)
    except Exception as err:
        raise ValueError(f"Invalid RSA public key format: {err}")

    # Maximum chunk size in bytes (leaving room so integer representation < n)
    key_byte_len = (n.bit_length() + 7) // 8
    block_size = max(1, key_byte_len - 2)

    blocks: List[str] = []
    for i in range(0, len(plaintext), block_size):
        chunk = plaintext[i : i + block_size]
        # Append a 0x01 marker byte to preserve leading zero bytes in plaintext
        m_int = int.from_bytes(b"\x01" + chunk, "big")
        c_int = pow(m_int, e, n)
        blocks.append(f"{c_int:x}")

    ciphertext_str = ",".join(blocks)
    return {
        "scheme": "rsa",
        "ciphertext": ciphertext_str,
        "mac": "",
    }


def decrypt(ciphertext_blob: Dict[str, str], private_key: str) -> bytes:
    """
    RSA-decrypt a blob produced by encrypt(), given the recipient's private key (n:d).
    """
    try:
        n_hex, d_hex = private_key.split(":")
        n = int(n_hex, 16)
        d = int(d_hex, 16)
    except Exception as err:
        raise ValueError(f"Invalid RSA private key format: {err}")

    ciphertext_str = ciphertext_blob.get("ciphertext", "")
    if not ciphertext_str:
        return b""

    blocks = ciphertext_str.split(",")
    decrypted_bytes = bytearray()

    for c_hex in blocks:
        if not c_hex:
            continue
        c_int = int(c_hex, 16)
        m_int = pow(c_int, d, n)
        
        # Convert integer back to bytes
        m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")
        # Strip the 0x01 marker byte
        if m_bytes.startswith(b"\x01"):
            decrypted_bytes.extend(m_bytes[1:])
        else:
            decrypted_bytes.extend(m_bytes)

    return bytes(decrypted_bytes)
