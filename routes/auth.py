"""
routes/auth.py - Registration, login, 2FA verification.

Uses: crypto/rsa.py (encrypt contact info), crypto/otp.py (2FA), and a
hand-built salted-hash routine for passwords (do not use werkzeug's
generate_password_hash/hashlib directly wrapped as-is without documenting
your own salting scheme - the assignment wants passwords "hashed and salted"
by your own logic, not just a library call).
"""

from flask import Blueprint, request, jsonify

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    TODO:
      1. Collect username, password, email, contact info from the form
      2. Salt + hash the password (from scratch)
      3. Encrypt email/contact info with crypto.rsa.encrypt()
      4. Generate RSA + ECC keypairs (crypto.rsa / crypto.ecc) via the
         Key Management Module (routes/keys.py)
      5. Generate an OTP secret (crypto.otp.generate_secret())
      6. Insert the user row into Supabase
    """
    return jsonify({"status": "not_implemented", "route": "register"}), 501


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    TODO:
      1. Step 1: verify username + hashed password
      2. Step 2: verify OTP code (crypto.otp.verify_otp())
      3. On success, hand off to routes/sessions.py to issue a session token
    """
    return jsonify({"status": "not_implemented", "route": "login"}), 501


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """TODO (whoever owns auth/keys / C): invalidate the session token (routes/sessions.py)."""
    return jsonify({"status": "not_implemented", "route": "logout"}), 501
