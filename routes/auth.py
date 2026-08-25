"""
routes/auth.py - Registration, login, logout.

Password hashing (crypto/password.py) and 2FA are placeholders/pending -
see the docstring in crypto/password.py. Email/contact encryption uses
crypto/rsa.py, which is currently the pass-through stub until RSA is
implemented from scratch - swap in real RSA later with no route changes.
"""

from flask import Blueprint, request, render_template, redirect, url_for, make_response, g
import psycopg2.extras

import db
from crypto import ecc, rsa as rsa_crypto
from crypto.password import hash_password, verify_password
from routes.sessions import issue_session, revoke_session, require_login

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form["username"].strip()
    password = request.form["password"]
    email = request.form["email"].strip()
    contact = request.form.get("contact", "").strip()
    role = request.form.get("role", "rider")

    password_hash, salt = hash_password(password)

    # Profile fields (RSA - currently the stub) encrypted before storage
    email_enc = rsa_crypto.encrypt(email.encode(), "placeholder-until-rsa-keys-exist")
    contact_enc = rsa_crypto.encrypt(contact.encode(), "placeholder-until-rsa-keys-exist")

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

            # Generate real ECC keypair (used for trips/chat encryption)
            ecc_priv, ecc_pub = ecc.generate_keypair()
            # RSA keypair - still the stub until RSA is implemented from scratch
            rsa_priv, rsa_pub = rsa_crypto.generate_keypair()

            # NOTE: private keys should be wrapped/encrypted with a key derived
            # from the user's password before storage (Key Management Module,
            # still pending). Stored as a flagged placeholder dict for now so
            # the jsonb columns are satisfied without pretending this is secure.
            cur.execute(
                """
                INSERT INTO user_keys (user_id, rsa_public_key, rsa_private_key_encrypted,
                                        ecc_public_key, ecc_private_key_encrypted)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    user_id, rsa_pub, psycopg2.extras.Json({"_todo": "wrap with password-derived key", "raw": rsa_priv}),
                    ecc_pub, psycopg2.extras.Json({"_todo": "wrap with password-derived key", "raw": ecc_priv}),
                ),
            )
        conn.commit()

    token = issue_session(str(user_id))
    resp = make_response(redirect(url_for("trips.dashboard")))
    resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
    return resp


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form["username"].strip()
    password = request.form["password"]

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, password_hash, password_salt FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()

    if not row or not verify_password(password, row[1], row[2]):
        return render_template("login.html", error="Invalid username or password"), 401

    user_id = str(row[0])
    token = issue_session(user_id)
    resp = make_response(redirect(url_for("trips.dashboard")))
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
