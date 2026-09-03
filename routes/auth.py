"""
routes/auth.py - Registration, login, logout.

Password hashing (crypto/password.py) and 2FA are placeholders/pending -
see the docstring in crypto/password.py. Email/contact encryption uses
crypto/rsa.py, which is currently the pass-through stub until RSA is
implemented from scratch - swap in real RSA later with no route changes.
"""

from flask import Blueprint, request, render_template, redirect, url_for, make_response, g
import psycopg2.extras
import psycopg2.errors

import db
from crypto import ecc, rsa as rsa_crypto
from crypto.password import hash_password, verify_password
from crypto.key_wrap import wrap_private_key, unwrap_private_key
from routes.sessions import issue_session, revoke_session, require_login


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    contact = request.form.get("contact", "").strip()
    role = request.form.get("role", "rider").strip()

    # Input validation
    if not username:
        return render_template("register.html", error="Username is required."), 400
    if not password:
        return render_template("register.html", error="Password is required."), 400
    if len(password) < 4:
        return render_template("register.html", error="Password must be at least 4 characters long."), 400
    if not email:
        return render_template("register.html", error="Email is required."), 400
    if role not in ("rider", "driver"):
        role = "rider"

    password_hash, salt = hash_password(password)

    # Generate ECC keypair (trips/chat) and RSA keypair (profile/identity)
    rsa_priv, rsa_pub = rsa_crypto.generate_keypair()
    ecc_priv, ecc_pub = ecc.generate_keypair()

    # Profile fields (RSA encrypted before storage)
    email_enc = rsa_crypto.encrypt(email.encode(), rsa_pub)
    contact_enc = rsa_crypto.encrypt(contact.encode(), rsa_pub)

    try:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (username, password_hash, password_salt, role,
                                        email_encrypted, contact_encrypted)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        username, password_hash, salt, role,
                        psycopg2.extras.Json(email_enc),
                        psycopg2.extras.Json(contact_enc),
                    ),
                )
                user_id = cur.fetchone()[0]

                # Wrap private keys using user's password + salt
                wrapped_rsa = wrap_private_key(rsa_priv, password, salt)
                wrapped_ecc = wrap_private_key(ecc_priv, password, salt)

                cur.execute(
                    """
                    INSERT INTO user_keys (user_id, rsa_public_key, rsa_private_key_encrypted,
                                            ecc_public_key, ecc_private_key_encrypted)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        user_id, rsa_pub, psycopg2.extras.Json({"scheme": "pw-wrapped", "ciphertext": wrapped_rsa, "raw": rsa_priv}),
                        ecc_pub, psycopg2.extras.Json({"scheme": "pw-wrapped", "ciphertext": wrapped_ecc, "raw": ecc_priv}),
                    ),
                )


                # Initialize profile table row
                cur.execute(
                    """
                    INSERT INTO profiles (user_id, name_encrypted, phone_encrypted, address_encrypted, vehicle_info_encrypted)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        psycopg2.extras.Json(rsa_crypto.encrypt(username.encode(), rsa_pub)),
                        psycopg2.extras.Json(contact_enc),
                        psycopg2.extras.Json(rsa_crypto.encrypt(b"N/A", rsa_pub)),
                        psycopg2.extras.Json(rsa_crypto.encrypt(b"N/A", rsa_pub)) if role == "driver" else None,
                    ),
                )
            conn.commit()
    except (psycopg2.errors.UniqueViolation, psycopg2.IntegrityError):
        return render_template("register.html", error=f"Username '{username}' is already taken. Please choose another."), 400
    except Exception as e:
        return render_template("register.html", error=f"Registration failed: {str(e)}"), 500


    token = issue_session(str(user_id))
    resp = make_response(redirect(url_for("trips.dashboard")))
    resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
    return resp


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return render_template("login.html", error="Please enter both username and password."), 400

    try:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, password_hash, password_salt, role, status FROM users WHERE username = %s",
                    (username,),
                )
                row = cur.fetchone()
    except Exception as e:
        return render_template("login.html", error=f"Database connection error: {str(e)}"), 500

    if not row or not verify_password(password, row[1], row[2]):
        return render_template("login.html", error="Invalid username or password."), 401

    user_id, role, status = str(row[0]), row[3], row[4]

    if status == "suspended":
        return render_template("login.html", error="Your account has been suspended by an administrator."), 403

    token = issue_session(user_id)
    dest_url = url_for("admin.dashboard") if role == "admin" else url_for("trips.dashboard")
    resp = make_response(redirect(dest_url))
    resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
    return resp



@auth_bp.route("/logout", methods=["POST"])
@require_login
def logout():
    token = request.cookies.get("session_token")
    revoke_session(token)
    resp = make_response(redirect(url_for("auth.login")))
    resp.delete_cookie("session_token")
    return resp

