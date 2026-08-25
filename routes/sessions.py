"""
routes/sessions.py - Session token issuance, validation, expiry.

Working implementation for now: random tokens stored in the `sessions`
table. This satisfies "random, unpredictable tokens" from the assignment,
but does not yet include hijacking-prevention extras (device binding,
mid-ride re-validation) - that layer is still open to build on top of this.
"""

import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Blueprint, request, redirect, url_for, g

import db

sessions_bp = Blueprint("sessions", __name__, url_prefix="/sessions")

SESSION_LIFETIME_HOURS = 24 * 7  # 1 week


def issue_session(user_id: str) -> str:
    token = secrets.token_hex(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_LIFETIME_HOURS)
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s, %s, %s)",
                (token, user_id, expires_at),
            )
        conn.commit()
    return token


def validate_session(token: str):
    if not token:
        return None
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id FROM sessions
                WHERE token = %s AND revoked = false AND expires_at > now()
                """,
                (token,),
            )
            row = cur.fetchone()
    return str(row[0]) if row else None


def revoke_session(token: str) -> None:
    if not token:
        return
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE sessions SET revoked = true WHERE token = %s", (token,))
        conn.commit()


def require_login(view_func):
    """Decorator: redirects to /auth/login if there's no valid session cookie."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        token = request.cookies.get("session_token")
        user_id = validate_session(token)
        if not user_id:
            return redirect(url_for("auth.login"))
        g.user_id = user_id
        return view_func(*args, **kwargs)
    return wrapped


@sessions_bp.route("/validate", methods=["POST"])
def validate():
    token = request.cookies.get("session_token")
    user_id = validate_session(token)
    return {"valid": bool(user_id)}
