"""
crypto/integrity.py

Shared helper for MAC protection of encrypted RideSafe data.

The actual HMAC construction remains in crypto/mac.py.
"""

import json

from config import Config
from crypto import mac


def _get_mac_key():
    """
    Return the server-side integrity key.
    """

    key = Config.MAC_KEY

    if not key:
        raise RuntimeError(
            "RIDESAFE_MAC_KEY is not configured"
        )

    return key


def canonical_payload(payload: dict) -> bytes:
    if not isinstance(payload, dict):
        raise TypeError(
            "payload must be a dictionary"
        )

    data = {
        key: value
        for key, value in payload.items()
        if key != "mac"
    }

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def attach_mac(payload: dict) -> dict:
    protected_data = canonical_payload(
        payload
    )

    tag = mac.compute_mac(
        protected_data,
        _get_mac_key()
    )

    result = dict(payload)

    result["mac"] = tag

    return result


def verify_payload_mac(payload: dict) -> bool:

    if not isinstance(payload, dict):
        return False

    tag = payload.get("mac")

    if not isinstance(tag, str):
        return False

    try:

        protected_data = canonical_payload(
            payload
        )

        return mac.verify_mac(
            protected_data,
            tag,
            _get_mac_key()
        )

    except (
        TypeError,
        ValueError,
        RuntimeError,
    ):
        return False