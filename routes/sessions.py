import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Blueprint, request, redirect, url_for, g, abort

import db


# ============================================================
# Blueprint
# ============================================================

sessions_bp = Blueprint(
    "sessions",
    __name__,
    url_prefix="/sessions"
)


# ============================================================
# Session Configuration
# ============================================================

# ------------------------------------------------------------
# Session inactivity timeout
# ------------------------------------------------------------
#
# The session will expire if the user has no activity for
# 1 hour.
#
# Every valid request to a protected route refreshes the
# expiration time by another 1 hour.
# ------------------------------------------------------------

SESSION_INACTIVITY_HOURS = 1


# ------------------------------------------------------------
# Session token configuration
# ------------------------------------------------------------
#
# 32 random bytes = 256-bit session token
# ------------------------------------------------------------

SESSION_TOKEN_BYTES = 32


# ============================================================
# Create / Issue Session
# ============================================================

def issue_session(
    user_id: str,
    role: str | None = None
) -> str:
    """
    Create a new secure session for an active user.

    The session initially expires 1 hour after login.

    The expiration time is refreshed whenever the user makes
    valid activity through a protected route.

    Args:
        user_id:
            ID of the authenticated user.

        role:
            Optional role supplied by auth.py.

            The role stored in the database remains authoritative.

    Returns:
        str:
            Secure random session token.
    """

    if not user_id:
        raise ValueError(
            "user_id is required"
        )

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            # ----------------------------------------------------
            # Get authoritative role and account status
            # ----------------------------------------------------

            cur.execute(
                """
                SELECT role, status
                FROM users
                WHERE id = %s
                """,
                (user_id,)
            )

            user_row = cur.fetchone()

            if not user_row:
                raise ValueError(
                    "User does not exist"
                )

            database_role, status = user_row

            # ----------------------------------------------------
            # Suspended users cannot receive new sessions
            # ----------------------------------------------------

            if status != "active":
                raise ValueError(
                    "User account is not active"
                )

            # ----------------------------------------------------
            # Check supplied role against database role
            # ----------------------------------------------------

            if (
                role is not None
                and role != database_role
            ):
                raise ValueError(
                    "User role mismatch"
                )

            # ----------------------------------------------------
            # Generate secure random session token
            # ----------------------------------------------------

            token = secrets.token_hex(
                SESSION_TOKEN_BYTES
            )

            # ----------------------------------------------------
            # Initial expiration:
            #
            # Current time + 1 hour
            # ----------------------------------------------------

            expires_at = (
                datetime.now(timezone.utc)
                + timedelta(
                    hours=SESSION_INACTIVITY_HOURS
                )
            )

            # ----------------------------------------------------
            # Store session
            # ----------------------------------------------------

            cur.execute(
                """
                INSERT INTO sessions
                    (
                        token,
                        user_id,
                        expires_at,
                        revoked
                    )
                VALUES
                    (
                        %s,
                        %s,
                        %s,
                        false
                    )
                """,
                (
                    token,
                    user_id,
                    expires_at
                )
            )

        conn.commit()

    return token


# ============================================================
# Validate Session
# ============================================================

def validate_session(
    token: str
):
    """
    Validate a session token.

    A session is valid only when:

        1. The token exists.
        2. The session is not revoked.
        3. The inactivity timeout has not expired.
        4. The associated user is active.

    IMPORTANT:

    Whenever a valid session is used, its expiration time is
    refreshed to one hour from the current activity.

    Returns:
        (user_id, role)

    if valid.

    Returns:
        None

    if invalid, expired, revoked, or suspended.
    """

    if not token:
        return None

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            # ----------------------------------------------------
            # First check whether the session is valid.
            #
            # We use FOR UPDATE so another simultaneous request
            # cannot update the same session inconsistently.
            # ----------------------------------------------------

            cur.execute(
                """
                SELECT
                    s.user_id,
                    u.role,
                    u.status
                FROM sessions s
                JOIN users u
                    ON s.user_id = u.id
                WHERE
                    s.token = %s
                    AND s.revoked = false
                    AND s.expires_at > now()
                FOR UPDATE
                """,
                (token,)
            )

            row = cur.fetchone()

            # ----------------------------------------------------
            # Session doesn't exist / expired / revoked
            # ----------------------------------------------------

            if not row:
                return None

            user_id, role, status = row

            # ----------------------------------------------------
            # Suspended users immediately lose access.
            # ----------------------------------------------------

            if status != "active":
                return None

            # ----------------------------------------------------
            # Refresh inactivity timeout.
            #
            # The user has just performed valid activity, so
            # give them another 1 hour.
            # ----------------------------------------------------

            new_expires_at = (
                datetime.now(timezone.utc)
                + timedelta(
                    hours=SESSION_INACTIVITY_HOURS
                )
            )

            cur.execute(
                """
                UPDATE sessions
                SET expires_at = %s
                WHERE token = %s
                """,
                (
                    new_expires_at,
                    token
                )
            )

        conn.commit()

    return (
        str(user_id),
        role
    )


# ============================================================
# Revoke One Session
# ============================================================

def revoke_session(
    token: str
) -> None:
    """
    Revoke a single session token.

    After revocation, the token can no longer be used.
    """

    if not token:
        return

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                UPDATE sessions
                SET revoked = true
                WHERE token = %s
                """,
                (token,)
            )

        conn.commit()


# ============================================================
# Revoke All Sessions of a User
# ============================================================

def revoke_user_sessions(
    user_id: str
) -> None:
    """
    Revoke every active session belonging to a user.

    This is useful when an administrator suspends a user.
    """

    if not user_id:
        return

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                UPDATE sessions
                SET revoked = true
                WHERE
                    user_id = %s
                    AND revoked = false
                """,
                (user_id,)
            )

        conn.commit()


# ============================================================
# Login Protection Decorator
# ============================================================

def require_login(view_func):
    """
    Require a valid logged-in session before accessing a route.

    The session token is read from the browser cookie.

    If the session is valid:

        g.user_id
        g.user_role
        g.session_token

    are populated.

    IMPORTANT:

    validate_session() also refreshes the 1-hour inactivity
    timeout whenever the protected route is accessed.
    """

    @wraps(view_func)
    def wrapped(*args, **kwargs):

        # --------------------------------------------------------
        # Get session token from browser cookie
        # --------------------------------------------------------

        token = request.cookies.get(
            "session_token"
        )

        # --------------------------------------------------------
        # Validate session
        #
        # This also refreshes the 1-hour inactivity timer.
        # --------------------------------------------------------

        session_data = validate_session(
            token
        )

        # --------------------------------------------------------
        # Invalid / expired / revoked / suspended session
        # --------------------------------------------------------

        if not session_data:

            response = redirect(
                url_for("auth.login")
            )

            # ----------------------------------------------------
            # Delete invalid cookie from browser
            # ----------------------------------------------------

            response.delete_cookie(
                "session_token"
            )

            return response

        # --------------------------------------------------------
        # Store authenticated information in Flask g
        # --------------------------------------------------------

        g.user_id = session_data[0]
        g.user_role = session_data[1]
        g.session_token = token

        return view_func(
            *args,
            **kwargs
        )

    return wrapped


# ============================================================
# RBAC: Require One Specific Role
# ============================================================

def require_role(
    required_role: str
):
    """
    Restrict a route to one specific role.

    Example:

        @require_login
        @require_role("admin")
        def admin_page():
            ...

    Only users whose role is exactly "admin" can access it.
    """

    if not required_role:
        raise ValueError(
            "required_role cannot be empty"
        )

    def decorator(view_func):

        @wraps(view_func)
        def wrapped(*args, **kwargs):

            # ----------------------------------------------------
            # g.user_role is populated by require_login()
            # ----------------------------------------------------

            user_role = getattr(
                g,
                "user_role",
                None
            )

            # ----------------------------------------------------
            # Deny access if role doesn't match
            # ----------------------------------------------------

            if user_role != required_role:
                abort(403)

            return view_func(
                *args,
                **kwargs
            )

        return wrapped

    return decorator


# ============================================================
# RBAC: Require One of Several Roles
# ============================================================

def require_roles(
    *required_roles: str
):
    """
    Restrict a route to one of several allowed roles.

    Example:

        @require_login
        @require_roles("admin", "driver")
        def driver_or_admin_page():
            ...

    A user is allowed if their role appears in required_roles.
    """

    if not required_roles:
        raise ValueError(
            "At least one role is required"
        )

    allowed_roles = set(
        required_roles
    )

    def decorator(view_func):

        @wraps(view_func)
        def wrapped(*args, **kwargs):

            user_role = getattr(
                g,
                "user_role",
                None
            )

            # ----------------------------------------------------
            # Deny access if role is not allowed
            # ----------------------------------------------------

            if user_role not in allowed_roles:
                abort(403)

            return view_func(
                *args,
                **kwargs
            )

        return wrapped

    return decorator


# ============================================================
# Session Validation Endpoint
# ============================================================

@sessions_bp.route(
    "/validate",
    methods=["POST"]
)
def validate():
    """
    API endpoint used to check whether the current session
    is still valid.

    A valid request also refreshes the 1-hour inactivity
    timeout.
    """

    token = request.cookies.get(
        "session_token"
    )

    session_data = validate_session(
        token
    )

    if not session_data:

        return {
            "valid": False
        }

    return {
        "valid": True,
        "user_id": session_data[0],
        "role": session_data[1]
    }