"""
crypto/ - Shared cryptography contract for RideSafe.

SHARED DATA FORMAT (agreed convention - do not deviate):
Every encrypted field stored in the database is a JSON-serializable dict:

    ECC-encrypted field (ECIES):
        {
            "scheme": "ecies",
            "ciphertext": "<hex or base64 string>",
            "ephemeral_pubkey": "<hex or base64 string>",
            "mac": "<hex or base64 string>"
        }

    RSA-encrypted field:
        {
            "scheme": "rsa",
            "ciphertext": "<hex or base64 string>",
            "mac": "<hex or base64 string>"
        }

Every encrypted record also carries its own MAC tag over the ciphertext
(computed by whoever owns sessions/RBAC's hmac_mac module) so tampering is detectable
independently of who encrypted the field.

MODULE OWNERSHIP (see project roadmap):
    - crypto/ecc.py   -> whoever owns the skeleton/ECC work     - ECC / ECIES from scratch
    - crypto/rsa.py   -> whoever owns auth/keys     - RSA from scratch
    - crypto/mac.py   -> whoever owns sessions/RBAC     - HMAC / CBC-MAC from scratch
    - crypto/otp.py   -> whoever owns sessions/RBAC     - HOTP/TOTP built on mac.py's HMAC

Until your own primitive is implemented, use the *_stub functions in each
file so the rest of the team can build against real function signatures
immediately. Replace the stub body only - do not change the signature
without updating this file and telling the team.
"""
