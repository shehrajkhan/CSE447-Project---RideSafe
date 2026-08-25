"""
crypto/ecc.py
-------------
Elliptic Curve Cryptography implemented FROM SCRATCH (no cryptography /
pycryptodome / ecdsa libraries). Used for: ride requests, trip logs, and
in-app chat messages (Rider <-> Driver).

Curve: secp256k1 - y^2 = x^3 + 7 (mod p)

Only hashlib.sha256 is used, purely as a KDF hash primitive (not an
encryption function). No symmetric cipher (AES/DES/etc.) is used anywhere -
encryption is an XOR keystream derived from ECDH + repeated hashing, which
is the asymmetric-only ECIES construction agreed on for this project.

Function-signature contract (matches crypto/__init__.py - do not change
without telling the team):

    generate_keypair() -> (private_key: str, public_key: str)
    encrypt(plaintext: bytes, public_key: str) -> dict
    decrypt(ciphertext_blob: dict, private_key: str) -> bytes

encrypt() returns:
    {
        "scheme": "ecies",
        "ciphertext": "<hex>",
        "ephemeral_pubkey": "<hex>",
        "mac": ""            # filled in by whoever owns sessions/RBAC's crypto/mac.py before storage
    }
"""

import hashlib
import secrets

# ---------------------------------------------------------------------------
# secp256k1 domain parameters
# ---------------------------------------------------------------------------
P = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_FFFFFC2F
A = 0
B = 7
Gx = 0x79BE667E_F9DCBBAC_55A06295_CE870B07_029BFCDB_2DCE28D9_59F2815B_16F81798
Gy = 0x483ADA77_26A3C465_5DA4FBFC_0E1108A8_FD17B448_A6855419_9C47D08F_FB10D4B8
N = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141
G = (Gx, Gy)

INFINITY = None  # point at infinity / identity element


# ---------------------------------------------------------------------------
# Modular arithmetic
# ---------------------------------------------------------------------------
def mod_inverse(k, m):
    """Extended Euclidean algorithm - modular inverse of k mod m."""
    if k == 0:
        raise ZeroDivisionError("division by zero in mod_inverse")
    if k < 0:
        return m - mod_inverse(-k, m)
    old_r, r = k, m
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % m


# ---------------------------------------------------------------------------
# Point arithmetic
# ---------------------------------------------------------------------------
def is_on_curve(point):
    if point is INFINITY:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def point_add(p1, p2):
    if p1 is INFINITY:
        return p2
    if p2 is INFINITY:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % P == 0:
        return INFINITY

    if p1 == p2:
        m = (3 * x1 * x1 + A) * mod_inverse(2 * y1, P) % P
    else:
        m = (y2 - y1) * mod_inverse(x2 - x1, P) % P

    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    """Double-and-add scalar multiplication: computes k * point."""
    if point is INFINITY or k % N == 0:
        return INFINITY
    if k < 0:
        x, y = point
        return scalar_mult(-k, (x, (-y) % P))

    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# Serialization helpers (point <-> hex, since the shared contract uses
# hex-encoded strings so it can drop straight into a JSON/Postgres column)
# ---------------------------------------------------------------------------
def _point_to_hex(point) -> str:
    x, y = point
    return f"{x:064x}{y:064x}"  # 32 bytes x || 32 bytes y


def _hex_to_point(hexstr: str):
    x = int(hexstr[:64], 16)
    y = int(hexstr[64:128], 16)
    return (x, y)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------
def generate_keypair() -> tuple:
    """Returns (private_key_hex, public_key_hex)."""
    private_key = secrets.randbelow(N - 1) + 1  # in [1, N-1]
    public_key = scalar_mult(private_key, G)
    return f"{private_key:064x}", _point_to_hex(public_key)


# ---------------------------------------------------------------------------
# KDF - derive an XOR keystream of arbitrary length from the ECDH shared
# secret. This is the asymmetric-only substitute for a symmetric cipher.
# ---------------------------------------------------------------------------
def _derive_keystream(shared_x: int, length: int) -> bytes:
    stream = b""
    counter = 0
    seed = shared_x.to_bytes(32, "big")
    while len(stream) < length:
        stream += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return stream[:length]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# ECIES encrypt / decrypt (public contract functions)
# ---------------------------------------------------------------------------
def encrypt(plaintext: bytes, public_key: str) -> dict:
    """
    ECIES-style encryption against a hex-encoded public key:
      1. Generate an ephemeral keypair (r, R = r*G)
      2. Compute shared secret S = r * recipient_pub  (ECDH)
      3. Derive a keystream from S, XOR with plaintext
      4. Return ciphertext + ephemeral public key (needed to decrypt)

    A fresh ephemeral key is used on every call, so encrypting the same
    plaintext twice produces different ciphertext - important for things
    like fares/timestamps where repeated values shouldn't be fingerprintable.
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    recipient_pub = _hex_to_point(public_key)
    if not is_on_curve(recipient_pub):
        raise ValueError("public_key is not a valid point on the curve")

    r = secrets.randbelow(N - 1) + 1
    R = scalar_mult(r, G)
    shared_point = scalar_mult(r, recipient_pub)
    if shared_point is INFINITY:
        raise ValueError("invalid shared point - bad public key?")
    shared_x = shared_point[0]

    keystream = _derive_keystream(shared_x, len(plaintext))
    ciphertext = _xor_bytes(plaintext, keystream)

    return {
        "scheme": "ecies",
        "ciphertext": ciphertext.hex(),
        "ephemeral_pubkey": _point_to_hex(R),
        "mac": "",  # whoever owns sessions/RBAC fills this in before storage
    }


def decrypt(ciphertext_blob: dict, private_key: str) -> bytes:
    """Reverses encrypt(): recompute the shared secret via ECDH, regenerate
    the identical keystream, and XOR it back off."""
    R = _hex_to_point(ciphertext_blob["ephemeral_pubkey"])
    ciphertext = bytes.fromhex(ciphertext_blob["ciphertext"])
    priv_int = int(private_key, 16)

    shared_point = scalar_mult(priv_int, R)
    if shared_point is INFINITY:
        raise ValueError("invalid shared point during decryption")
    shared_x = shared_point[0]

    keystream = _derive_keystream(shared_x, len(ciphertext))
    return _xor_bytes(ciphertext, keystream)


if __name__ == "__main__":
    # Quick manual sanity check - move to tests/test_ecc.py for the real suite
    priv, pub = generate_keypair()
    msg = b"pickup: 23.78,90.41 dropoff: 23.81,90.42 time: 14:32"
    enc = encrypt(msg, pub)
    dec = decrypt(enc, priv)
    assert dec == msg, "round-trip failed!"
    print("ECC/ECIES round-trip OK")
    print("private_key:", priv)
    print("public_key :", pub)
    print("ciphertext :", enc["ciphertext"][:60], "...")
