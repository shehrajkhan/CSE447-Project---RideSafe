"""
crypto/mac.py

HMAC-SHA256 implemented from scratch.

Python's hmac.new() is NOT used.

hashlib.sha256 is used only as the underlying hash primitive.
"""

import hashlib


_BLOCK_SIZE = 64
_DIGEST_SIZE = hashlib.sha256().digest_size


# ============================================================
# Helpers
# ============================================================

def _to_bytes(value) -> bytes:
    """
    Convert supported input types into bytes.
    """

    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, str):
        return value.encode("utf-8")

    raise TypeError(
        "data and key must be bytes, bytearray, or str"
    )


def _prepare_key(key: bytes) -> bytes:
    """
    Prepare HMAC key to exactly one SHA-256 block.
    """

    # If key is longer than the block size, hash it first.
    if len(key) > _BLOCK_SIZE:
        key = hashlib.sha256(key).digest()

    # Pad with zero bytes until 64 bytes.
    key = key.ljust(
        _BLOCK_SIZE,
        b"\x00"
    )

    return key


def _xor_block(block: bytes, value: int) -> bytes:
    """
    XOR every byte in a block with the supplied value.
    """

    return bytes(
        byte ^ value
        for byte in block
    )


# ============================================================
# HMAC
# ============================================================

def compute_mac(data: bytes, key: str) -> str:
    """
    Compute HMAC-SHA256 manually.

    HMAC(K, m) =
        H((K' XOR opad) || H((K' XOR ipad) || m))

    Returns:
        Hexadecimal MAC tag.
    """

    message = _to_bytes(data)
    key_bytes = _to_bytes(key)

    key_block = _prepare_key(key_bytes)

    # HMAC inner and outer pads
    ipad = _xor_block(
        key_block,
        0x36
    )

    opad = _xor_block(
        key_block,
        0x5C
    )

    # Inner hash
    inner_hash = hashlib.sha256(
        ipad + message
    ).digest()

    # Outer hash
    final_hash = hashlib.sha256(
        opad + inner_hash
    ).hexdigest()

    return final_hash


# ============================================================
# Constant-time comparison
# ============================================================

def _constant_time_equal(
    left: bytes,
    right: bytes
) -> bool:

    difference = len(left) ^ len(right)

    max_len = max(
        len(left),
        len(right)
    )

    for index in range(max_len):

        left_byte = (
            left[index]
            if index < len(left)
            else 0
        )

        right_byte = (
            right[index]
            if index < len(right)
            else 0
        )

        difference |= (
            left_byte ^ right_byte
        )

    return difference == 0


# ============================================================
# MAC Verification
# ============================================================

def verify_mac(
    data: bytes,
    tag: str,
    key: str
) -> bool:

    if not isinstance(tag, str):
        return False

    try:
        supplied_tag = bytes.fromhex(tag)
    except ValueError:
        return False

    if len(supplied_tag) != _DIGEST_SIZE:
        return False

    try:
        expected_tag = bytes.fromhex(
            compute_mac(
                data,
                key
            )
        )
    except (
        TypeError,
        ValueError
    ):
        return False

    return _constant_time_equal(
        expected_tag,
        supplied_tag
    )