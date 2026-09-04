"""
crypto/otp.py - OTP functionality for RideSafe.

This module contains:

1. HOTP/TOTP implementation built on RideSafe's own HMAC primitive.
2. Email OTP implementation for login 2FA.

Email OTP design:
    - Random 6-digit OTP
    - Valid for exactly 60 seconds
    - OTP is NEVER stored in the database
    - OTP is NEVER stored in the Flask session
    - Only an HMAC hash of the OTP is stored temporarily in server memory
    - OTP can be used only once
"""

import secrets
import time
import threading

from config import Config
from . import mac


# ---------------------------------------------------------------------------
# General OTP configuration
# ---------------------------------------------------------------------------

OTP_DIGITS = 6


# ---------------------------------------------------------------------------
# Existing HOTP/TOTP configuration
# ---------------------------------------------------------------------------

TIME_STEP = 30
SECRET_BYTES = 20
MAX_COUNTER = (1 << 64) - 1


# ---------------------------------------------------------------------------
# Email OTP configuration
# ---------------------------------------------------------------------------

# Email OTP is valid for exactly 60 seconds.
EMAIL_OTP_LIFETIME = 60


# ---------------------------------------------------------------------------
# Temporary server-side OTP storage
# ---------------------------------------------------------------------------
#
# IMPORTANT:
# The actual OTP is NOT stored here.
#
# Each entry contains:
#
# {
#     "user_id": "...",
#     "otp_hash": "...",
#     "expires_at": 1234567890.0
# }
#
# The key is a random challenge ID.
#
# The Flask session stores ONLY that challenge ID.
#
# This is intentionally in server memory, not in the database.
# ---------------------------------------------------------------------------

_PENDING_EMAIL_OTPS = {}

_OTP_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Secret generation
# ---------------------------------------------------------------------------

def generate_secret() -> str:
    """
    Generate a random per-user OTP secret.

    This function is retained for the existing HOTP/TOTP implementation.
    Email OTP login does not require a persistent OTP secret.
    """

    return secrets.token_hex(SECRET_BYTES)


# ---------------------------------------------------------------------------
# HOTP
# ---------------------------------------------------------------------------

def hotp(secret: str, counter: int) -> str:
    """
    Generate a 6-digit HOTP code.

    HOTP algorithm:

        1. Convert counter to an 8-byte big-endian value.
        2. Compute HMAC(secret, counter).
        3. Apply dynamic truncation.
        4. Reduce modulo 10^6.
        5. Return a zero-padded 6-digit string.
    """

    if not isinstance(secret, str):
        raise TypeError("secret must be a string")

    if not isinstance(counter, int):
        raise TypeError("counter must be an integer")

    if counter < 0 or counter > MAX_COUNTER:
        raise ValueError(
            "counter must fit in an unsigned 64-bit integer"
        )

    counter_bytes = counter.to_bytes(
        8,
        byteorder="big",
        signed=False,
    )

    mac_hex = mac.compute_mac(
        counter_bytes,
        secret,
    )

    mac_bytes = bytes.fromhex(mac_hex)

    offset = mac_bytes[-1] & 0x0F

    truncated = mac_bytes[
        offset:offset + 4
    ]

    binary_code = int.from_bytes(
        truncated,
        byteorder="big",
        signed=False,
    )

    binary_code &= 0x7FFFFFFF

    otp_value = binary_code % (10 ** OTP_DIGITS)

    return f"{otp_value:0{OTP_DIGITS}d}"


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------

from typing import Optional

def totp(
    secret: str,
    timestamp: Optional[int] = None
) -> str:
    """
    Generate the current TOTP code.

    TOTP uses a 30-second time step.
    """

    if not isinstance(secret, str):
        raise TypeError("secret must be a string")

    if timestamp is None:
        timestamp = int(time.time())

    if not isinstance(timestamp, int):
        raise TypeError("timestamp must be an integer")

    if timestamp < 0:
        raise ValueError("timestamp cannot be negative")

    counter = timestamp // TIME_STEP

    return hotp(
        secret,
        counter,
    )


def generate_otp(secret: str) -> str:
    """
    Generate the current TOTP code.

    Retained for compatibility with the existing project.
    """

    return totp(secret)


def verify_otp(
    secret: str,
    code: str
) -> bool:
    """
    Verify a TOTP code using the existing +/- 1 time-step window.

    This function is retained for compatibility.

    Email login uses verify_email_otp() instead.
    """

    if not isinstance(secret, str):
        return False

    if not isinstance(code, str):
        return False

    if len(code) != OTP_DIGITS:
        return False

    if not code.isdigit():
        return False

    try:
        current_time = int(time.time())
        current_counter = current_time // TIME_STEP

        for counter_offset in (-1, 0, 1):

            counter = current_counter + counter_offset

            if counter < 0:
                continue

            expected_code = hotp(
                secret,
                counter,
            )

            if expected_code == code:
                return True

        return False

    except (
        TypeError,
        ValueError,
        OverflowError,
    ):
        return False


# ===========================================================================
# EMAIL OTP
# ===========================================================================


def generate_email_otp() -> str:
    """
    Generate a cryptographically random 6-digit OTP.

    The OTP is not stored anywhere by this function.
    """

    value = secrets.randbelow(1_000_000)

    return f"{value:06d}"


def _otp_hash(code: str) -> str:
    """
    Create an HMAC-based verifier for an email OTP.

    The actual OTP is never stored.

    The application's RIDESAFE_MAC_KEY is used as the HMAC key.
    """

    if not isinstance(code, str):
        raise TypeError("OTP code must be a string")

    if not code.isdigit() or len(code) != OTP_DIGITS:
        raise ValueError("OTP must contain exactly 6 digits")

    if not Config.MAC_KEY:
        raise RuntimeError(
            "RIDESAFE_MAC_KEY is not configured"
        )

    return mac.compute_mac(
        code.encode("utf-8"),
        Config.MAC_KEY,
    )


def create_email_otp_challenge(
    user_id: str,
    otp_code: str
) -> str:
    """
    Create a temporary email-OTP challenge.

    The actual OTP is NOT stored.

    Only:
        - user_id
        - HMAC hash of OTP
        - expiration timestamp

    are stored in server memory.

    Returns:
        Random challenge ID.
    """

    if not isinstance(user_id, str):
        user_id = str(user_id)

    otp_hash = _otp_hash(otp_code)

    challenge_id = secrets.token_urlsafe(32)

    expires_at = time.time() + EMAIL_OTP_LIFETIME

    with _OTP_LOCK:

        _cleanup_expired_challenges()

        _PENDING_EMAIL_OTPS[challenge_id] = {
            "user_id": user_id,
            "otp_hash": otp_hash,
            "expires_at": expires_at,
        }

    return challenge_id


def verify_email_otp(
    challenge_id: str,
    otp_code: str
):
    """
    Verify an email OTP.

    Returns:
        user_id if the OTP is valid.

        None if:
            - challenge doesn't exist
            - OTP is incorrect
            - OTP has expired
            - OTP format is invalid

    A successful OTP is immediately consumed and cannot be reused.
    """

    if not isinstance(challenge_id, str):
        return None

    if not isinstance(otp_code, str):
        return None

    otp_code = otp_code.strip()

    if (
        len(otp_code) != OTP_DIGITS
        or not otp_code.isdigit()
    ):
        return None

    with _OTP_LOCK:

        challenge = _PENDING_EMAIL_OTPS.get(
            challenge_id
        )

        if challenge is None:
            return None

        current_time = time.time()

        # OTP has expired.
        if current_time >= challenge["expires_at"]:

            del _PENDING_EMAIL_OTPS[challenge_id]

            return None

        try:

            expected_hash = challenge["otp_hash"]

            valid = mac.verify_mac(
                otp_code.encode("utf-8"),
                expected_hash,
                Config.MAC_KEY,
            )

        except (
            TypeError,
            ValueError,
            RuntimeError,
        ):
            valid = False

        if not valid:
            return None

        # Successful verification.
        # Delete immediately so the OTP cannot be reused.
        user_id = challenge["user_id"]

        del _PENDING_EMAIL_OTPS[challenge_id]

        return user_id


def discard_email_otp_challenge(
    challenge_id: str
) -> None:
    """
    Delete an email OTP challenge.

    Used when sending the email fails or when login is cancelled.
    """

    if not isinstance(challenge_id, str):
        return

    with _OTP_LOCK:
        _PENDING_EMAIL_OTPS.pop(
            challenge_id,
            None,
        )


def get_email_otp_remaining_seconds(
    challenge_id: str
):
    """
    Return the number of seconds remaining for a challenge.

    Returns None if the challenge does not exist or has expired.
    """

    if not isinstance(challenge_id, str):
        return None

    with _OTP_LOCK:

        challenge = _PENDING_EMAIL_OTPS.get(
            challenge_id
        )

        if challenge is None:
            return None

        remaining = challenge["expires_at"] - time.time()

        if remaining <= 0:

            del _PENDING_EMAIL_OTPS[challenge_id]

            return None

        return int(remaining)


def _cleanup_expired_challenges():
    """
    Remove expired OTP challenges.

    Caller must hold _OTP_LOCK.
    """

    current_time = time.time()

    expired = [
        challenge_id
        for challenge_id, challenge
        in _PENDING_EMAIL_OTPS.items()
        if current_time >= challenge["expires_at"]
    ]

    for challenge_id in expired:
        del _PENDING_EMAIL_OTPS[challenge_id]