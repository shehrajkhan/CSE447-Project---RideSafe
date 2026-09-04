"""
routes/admin.py

Admin-only account management.

Admins can:
    - View user account metadata
    - Suspend users
    - Activate users
    - Revoke a user's active sessions

Admins cannot decrypt private trip/chat data through these routes.
"""

from flask import Blueprint, jsonify, g

import db

from routes.sessions import (
    require_login,
    require_role,
    revoke_user_sessions,
)


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/admin"
)


# ============================================================
# List Users
# ============================================================

@admin_bp.route(
    "/users",
    methods=["GET"]
)
@require_login
@require_role("admin")
def list_users():
    """
    Return user account metadata.

    No passwords, OTP secrets, private keys, or decrypted
    sensitive information are returned.
    """

    with db.get_conn() as conn:
        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    id,
                    username,
                    role,
                    status,
                    created_at
                FROM users
                ORDER BY created_at DESC
                """
            )

            rows = cur.fetchall()

    users = []

    for row in rows:

        users.append(
            {
                "id": str(row[0]),
                "username": row[1],
                "role": row[2],
                "status": row[3],
                "created_at": (
                    row[4].isoformat()
                    if row[4]
                    else None
                ),
            }
        )

    return jsonify(
        {
            "users": users
        }
    )


# ============================================================
# Suspend User
# ============================================================

@admin_bp.route(
    "/users/<user_id>/suspend",
    methods=["POST"]
)
@require_login
@require_role("admin")
def suspend_user(user_id):
    """
    Suspend a user and immediately revoke all of that user's
    active sessions.
    """

    current_user_id = getattr(
        g,
        "user_id",
        None
    )

    # Prevent an administrator from accidentally locking
    # themselves out.
    if str(user_id) == str(current_user_id):

        return jsonify(
            {
                "error":
                    "An administrator cannot suspend "
                    "their own account"
            }
        ), 400

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                UPDATE users
                SET status = 'suspended'
                WHERE id = %s
                RETURNING id, username, status
                """,
                (user_id,)
            )

            row = cur.fetchone()

        conn.commit()

    if not row:

        return jsonify(
            {
                "error": "User not found"
            }
        ), 404

    # Existing sessions must stop working immediately.
    revoke_user_sessions(
        str(user_id)
    )

    return jsonify(
        {
            "message": "User suspended",
            "user": {
                "id": str(row[0]),
                "username": row[1],
                "status": row[2],
            },
        }
    )


# ============================================================
# Activate User
# ============================================================

@admin_bp.route(
    "/users/<user_id>/activate",
    methods=["POST"]
)
@require_login
@require_role("admin")
def activate_user(user_id):
    """
    Reactivate a suspended account.
    """

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                UPDATE users
                SET status = 'active'
                WHERE id = %s
                RETURNING id, username, status
                """,
                (user_id,)
            )

            row = cur.fetchone()

        conn.commit()

    if not row:

        return jsonify(
            {
                "error": "User not found"
            }
        ), 404

    return jsonify(
        {
            "message": "User account activated",
            "user": {
                "id": str(row[0]),
                "username": row[1],
                "status": row[2],
            },
        }
    )


# ============================================================
# Revoke User Sessions
# ============================================================

@admin_bp.route(
    "/users/<user_id>/revoke-sessions",
    methods=["POST"]
)
@require_login
@require_role("admin")
def revoke_sessions(user_id):
    """
    Revoke every active session belonging to a user.
    """

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT id
                FROM users
                WHERE id = %s
                """,
                (user_id,)
            )

            row = cur.fetchone()

    if not row:

        return jsonify(
            {
                "error": "User not found"
            }
        ), 404

    revoke_user_sessions(
        str(user_id)
    )

    return jsonify(
        {
            "message": "All user sessions revoked",
            "user_id": str(user_id),
        }
    )