"""
routes/admin.py - RBAC-protected admin routes (account management, disputes).

Admins can manage account status but must NOT be able to decrypt trip/chat
data without the affected user's own key material - enforce that boundary
here, don't just rely on the frontend hiding buttons.
"""

from flask import Blueprint, jsonify

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def require_admin(session_user):
    """TODO: RBAC check - raise/abort(403) if session_user.role != 'admin'."""
    raise NotImplementedError


@admin_bp.route("/users", methods=["GET"])
def list_users():
    """TODO: list user account metadata only (no decrypted trip/chat content)."""
    return jsonify({"status": "not_implemented", "route": "list_users"}), 501


@admin_bp.route("/users/<user_id>/suspend", methods=["POST"])
def suspend_user(user_id):
    """TODO: suspend/reactivate an account; also revoke their active sessions."""
    return jsonify({"status": "not_implemented", "route": "suspend_user", "user_id": user_id}), 501
