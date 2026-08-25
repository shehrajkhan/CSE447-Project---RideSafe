"""
routes/sessions.py - Session token issuance, validation, expiry, hijack
prevention.

Session tokens should be generated with a cryptographically random,
unpredictable scheme (e.g. secrets.token_hex(32)) - not a sequential ID.
"""

from flask import Blueprint, jsonify

sessions_bp = Blueprint("sessions", __name__, url_prefix="/sessions")


def issue_session(user_id: str) -> str:
    """
    TODO:
      1. Generate a random, unpredictable token (e.g. secrets.token_hex(32))
      2. Store {token, user_id, created_at, expires_at} in Supabase
      3. Return the token to be set as an httponly cookie
    """
    raise NotImplementedError


def validate_session(token: str):
    """
    TODO:
      1. Look up the token in Supabase
      2. Check it hasn't expired
      3. Return the associated user_id, or None if invalid/expired
    """
    raise NotImplementedError


def revoke_session(token: str) -> None:
    """TODO: delete/invalidate the session row (logout, password change)."""
    raise NotImplementedError


@sessions_bp.route("/validate", methods=["POST"])
def validate():
    """TODO: endpoint wrapper around validate_session() for client checks."""
    return jsonify({"status": "not_implemented", "route": "validate_session"}), 501
