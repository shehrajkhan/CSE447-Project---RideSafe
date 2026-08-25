"""
crypto/otp.py - HOTP/TOTP two-factor codes, built on crypto/mac.py's HMAC.

Reference: RFC 4226 (HOTP), RFC 6238 (TOTP - adds a time-based counter).

TODO (build in this order):
    1. generate_secret() - random per-user secret, base32-encode for
       display/QR if you want a real authenticator-app flow, or just show
       the raw code if that's out of scope for the demo.
    2. hotp(secret, counter) -> 6-digit code, using compute_mac() from
       crypto/mac.py as the HMAC step, then RFC 4226's dynamic truncation.
    3. totp(secret) -> hotp(secret, counter=int(time.time() // 30))
    4. verify_otp(secret, code) -> bool, allowing +/-1 time-step of drift.

Do NOT change the function signatures below without updating crypto/__init__.py
and telling the team - the auth routes (login step 2) call these directly.
"""

from . import mac


def generate_secret() -> str:
    """
    Generate a new per-user OTP secret at registration time.

    TODO: replace with a real random secret (e.g. secrets.token_hex(20)).
    """
    return _generate_secret_stub()


def generate_otp(secret: str) -> str:
    """
    Generate the current 6-digit time-based OTP code for this secret.

    TODO: replace with real HOTP/TOTP built on mac.compute_mac().
    """
    return _generate_otp_stub(secret)


def verify_otp(secret: str, code: str) -> bool:
    """
    Verify a user-submitted OTP code against the secret, allowing a small
    time-step drift window.

    TODO: replace with real verification once generate_otp() is done.
    """
    return _verify_otp_stub(secret, code)


# ---------------------------------------------------------------------------
# STUBS - used by the rest of the team until the real implementation above
# is ready. NOT secure - always "passes" verification. Delete once real
# HOTP/TOTP is done.
# ---------------------------------------------------------------------------

def _generate_secret_stub() -> str:
    return "stub-otp-secret"


def _generate_otp_stub(secret: str) -> str:
    return "000000"


def _verify_otp_stub(secret: str, code: str) -> bool:
    return True
