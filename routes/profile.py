"""
routes/profile.py - View/update user profile.

Uses: crypto/rsa.py to encrypt/decrypt profile fields.
"""

from flask import Blueprint, jsonify

profile_bp = Blueprint("profile", __name__, url_prefix="/profile")


@profile_bp.route("/", methods=["GET"])
def view_profile():
    """
    TODO:
      1. Require a valid session (routes/sessions.py)
      2. Fetch the user's encrypted profile row from Supabase
      3. Decrypt with crypto.rsa.decrypt() using the user's private key
      4. Return the decrypted profile (never log/print decrypted fields)
    """
    return jsonify({"status": "not_implemented", "route": "view_profile"}), 501


@profile_bp.route("/update", methods=["POST"])
def update_profile():
    """
    TODO:
      1. Require a valid session
      2. Encrypt the updated fields with crypto.rsa.encrypt()
      3. Compute a MAC over the ciphertext (crypto.mac.compute_mac(), whoever owns sessions/RBAC's module)
      4. Store {ciphertext, mac} in Supabase
    """
    return jsonify({"status": "not_implemented", "route": "update_profile"}), 501
