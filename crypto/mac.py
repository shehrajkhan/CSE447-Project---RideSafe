"""
crypto/mac.py - HMAC / CBC-MAC, implemented from scratch.

Used for: integrity tags over every encrypted field (ECC or RSA), and as the
building block for crypto/otp.py's HOTP/TOTP two-factor codes.

TODO (build in this order):
    1. A hash primitive if not reusing hashlib.sha256 directly for the HMAC
       construction (HMAC itself must be hand-built: do not use hmac.new()
       from Python's stdlib - the assignment requires MAC "implemented from
       scratch", i.e. build the HMAC(K, m) = H((K' xor opad) || H((K' xor
       ipad) || m)) construction yourself using only a raw hash function).
    2. compute_mac(data, key) -> tag
    3. verify_mac(data, tag, key) -> bool  (constant-time comparison!)
    4. (optional alternative) CBC-MAC if you'd rather build it on a block
       cipher structure instead of HMAC - pick one and document why in the
       report.

Do NOT change the function signatures below without updating crypto/__init__.py
and telling the team - every route that stores encrypted data calls these.
"""


def compute_mac(data: bytes, key: str) -> str:
    """
    Compute a MAC tag over `data` using `key`.

    Returns:
        hex-encoded MAC tag (string) to store alongside the ciphertext.

    TODO: replace with real hand-built HMAC (or CBC-MAC) implementation.
    """
    return _compute_mac_stub(data, key)


def verify_mac(data: bytes, tag: str, key: str) -> bool:
    """
    Recompute the MAC over `data` and compare against `tag`.
    MUST use a constant-time comparison to avoid timing attacks
    (e.g. compare byte-by-byte with a running XOR, don't use `==` on the
    whole string directly for the final decision).

    Returns:
        True if the tag matches (data is untampered), False otherwise.

    TODO: replace with real implementation once compute_mac() is done.
    """
    return _verify_mac_stub(data, tag, key)


# ---------------------------------------------------------------------------
# STUBS - used by the rest of the team until the real implementation above
# is ready. NOT secure - always "passes" verification. Delete once real
# HMAC/CBC-MAC is done.
# ---------------------------------------------------------------------------

def _compute_mac_stub(data: bytes, key: str) -> str:
    return "stub-mac-tag"


def _verify_mac_stub(data: bytes, tag: str, key: str) -> bool:
    return True
