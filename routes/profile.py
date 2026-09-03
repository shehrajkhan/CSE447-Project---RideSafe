"""
routes/profile.py - View and Edit profile module using scratch RSA encryption.

Stores sensitive identity/contact and vehicle info encrypted with the user's RSA primitive.
"""

from flask import Blueprint, request, render_template, redirect, url_for, g
import psycopg2.extras

import db
from crypto import rsa as rsa_crypto
from routes.sessions import require_login

profile_bp = Blueprint("profile", __name__, url_prefix="/profile")


def _get_rsa_keys(user_id):
    """Retrieve user's RSA public key and private key from storage. Auto-upgrades stub keys."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT rsa_public_key, rsa_private_key_encrypted FROM user_keys WHERE user_id = %s",
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        return None, None

    public_key = row[0]
    private_key = row[1].get("raw") if isinstance(row[1], dict) else None

    # Check if key is a legacy stub or missing expected ":" colon divider
    if not public_key or ":" not in str(public_key) or not private_key or ":" not in str(private_key):
        priv_str, pub_str = rsa_crypto.generate_keypair()
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO user_keys (user_id, rsa_public_key, rsa_private_key_encrypted)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE
                    SET rsa_public_key = EXCLUDED.rsa_public_key,
                        rsa_private_key_encrypted = EXCLUDED.rsa_private_key_encrypted
                    """,
                    (
                        user_id,
                        pub_str,
                        psycopg2.extras.Json({"raw": priv_str, "scheme": "upgraded-real-rsa"}),
                    ),
                )
            conn.commit()
        public_key = pub_str
        private_key = priv_str

    return public_key, private_key



@profile_bp.route("/", methods=["GET"])
@require_login
def view_profile():
    user_id = g.user_id
    pub_key, priv_key = _get_rsa_keys(user_id)

    if not priv_key:
        return render_template("profile.html", error="Encryption keys not found for user."), 500

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, role, email_encrypted, contact_encrypted FROM users WHERE id = %s",
                (user_id,),
            )
            user_row = cur.fetchone()

            cur.execute(
                "SELECT name_encrypted, phone_encrypted, address_encrypted, vehicle_info_encrypted FROM profiles WHERE user_id = %s",
                (user_id,),
            )
            profile_row = cur.fetchone()

    if not user_row:
        return redirect(url_for("auth.login"))

    username, role, email_enc, contact_enc = user_row[0], user_row[1], user_row[2], user_row[3]

    # Decrypt encrypted fields using user's RSA private key
    try:
        email = rsa_crypto.decrypt(email_enc, priv_key).decode("utf-8", errors="replace") if email_enc else "N/A"
    except Exception:
        email = "[Decryption Failed]"

    try:
        contact = rsa_crypto.decrypt(contact_enc, priv_key).decode("utf-8", errors="replace") if contact_enc else "N/A"
    except Exception:
        contact = "[Decryption Failed]"

    name, phone, address, vehicle_info = username, contact, "N/A", "N/A"

    if profile_row:
        name_enc, phone_enc, address_enc, vehicle_enc = profile_row[0], profile_row[1], profile_row[2], profile_row[3]
        if name_enc:
            try:
                name = rsa_crypto.decrypt(name_enc, priv_key).decode("utf-8", errors="replace")
            except Exception:
                pass
        if phone_enc:
            try:
                phone = rsa_crypto.decrypt(phone_enc, priv_key).decode("utf-8", errors="replace")
            except Exception:
                pass
        if address_enc:
            try:
                address = rsa_crypto.decrypt(address_enc, priv_key).decode("utf-8", errors="replace")
            except Exception:
                pass
        if vehicle_enc:
            try:
                vehicle_info = rsa_crypto.decrypt(vehicle_enc, priv_key).decode("utf-8", errors="replace")
            except Exception:
                pass

    profile_data = {
        "username": username,
        "role": role,
        "name": name,
        "email": email,
        "phone": phone,
        "address": address,
        "vehicle_info": vehicle_info,
    }

    return render_template("profile.html", profile=profile_data)


@profile_bp.route("/edit", methods=["GET", "POST"])
@require_login
def edit_profile():
    user_id = g.user_id
    pub_key, priv_key = _get_rsa_keys(user_id)

    default_profile = {
        "username": "",
        "role": g.user_role,
        "name": "",
        "email": "",
        "phone": "",
        "address": "",
        "vehicle_info": "",
    }

    if not pub_key or not priv_key:
        return render_template("edit_profile.html", profile=default_profile, error="Encryption keys not found for user."), 500

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        vehicle_info = request.form.get("vehicle_info", "").strip()

        # RSA encrypt all updated profile fields before writing to database
        name_enc = rsa_crypto.encrypt(name.encode("utf-8"), pub_key)
        email_enc = rsa_crypto.encrypt(email.encode("utf-8"), pub_key)
        phone_enc = rsa_crypto.encrypt(phone.encode("utf-8"), pub_key)
        address_enc = rsa_crypto.encrypt(address.encode("utf-8"), pub_key)
        vehicle_enc = rsa_crypto.encrypt(vehicle_info.encode("utf-8"), pub_key) if g.user_role == "driver" else None

        with db.get_conn() as conn:
            with conn.cursor() as cur:
                # Update users table
                cur.execute(
                    """
                    UPDATE users
                    SET email_encrypted = %s, contact_encrypted = %s
                    WHERE id = %s
                    """,
                    (
                        psycopg2.extras.Json(email_enc),
                        psycopg2.extras.Json(phone_enc),
                        user_id,
                    ),
                )

                # Check if profile row exists
                cur.execute("SELECT id FROM profiles WHERE user_id = %s", (user_id,))
                existing_prof = cur.fetchone()

                if existing_prof:
                    cur.execute(
                        """
                        UPDATE profiles
                        SET name_encrypted = %s,
                            phone_encrypted = %s,
                            address_encrypted = %s,
                            vehicle_info_encrypted = %s,
                            updated_at = NOW()
                        WHERE user_id = %s
                        """,
                        (
                            psycopg2.extras.Json(name_enc),
                            psycopg2.extras.Json(phone_enc),
                            psycopg2.extras.Json(address_enc),
                            psycopg2.extras.Json(vehicle_enc) if vehicle_enc else None,
                            user_id,
                        ),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO profiles (user_id, name_encrypted, phone_encrypted, address_encrypted, vehicle_info_encrypted, updated_at)
                        VALUES (%s, %s, %s, %s, %s, NOW())
                        """,
                        (
                            user_id,
                            psycopg2.extras.Json(name_enc),
                            psycopg2.extras.Json(phone_enc),
                            psycopg2.extras.Json(address_enc),
                            psycopg2.extras.Json(vehicle_enc) if vehicle_enc else None,
                        ),
                    )
            conn.commit()

        return redirect(url_for("profile.view_profile"))

    # GET request: fetch current profile data for form pre-filling
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT username, role, email_encrypted, contact_encrypted FROM users WHERE id = %s",
                (user_id,),
            )
            user_row = cur.fetchone()

            cur.execute(
                "SELECT name_encrypted, phone_encrypted, address_encrypted, vehicle_info_encrypted FROM profiles WHERE user_id = %s",
                (user_id,),
            )
            profile_row = cur.fetchone()

    if not user_row:
        return redirect(url_for("auth.login"))

    username, role = user_row[0], user_row[1]

    email = ""
    if user_row[2]:
        try:
            email = rsa_crypto.decrypt(user_row[2], priv_key).decode("utf-8", errors="replace")
        except Exception:
            email = ""

    phone = ""
    if user_row[3]:
        try:
            phone = rsa_crypto.decrypt(user_row[3], priv_key).decode("utf-8", errors="replace")
        except Exception:
            phone = ""

    name, address, vehicle_info = username, "", ""

    if profile_row:
        if profile_row[0]:
            try:
                name = rsa_crypto.decrypt(profile_row[0], priv_key).decode("utf-8", errors="replace")
            except Exception:
                pass
        if profile_row[1]:
            try:
                phone = rsa_crypto.decrypt(profile_row[1], priv_key).decode("utf-8", errors="replace")
            except Exception:
                pass
        if profile_row[2]:
            try:
                address = rsa_crypto.decrypt(profile_row[2], priv_key).decode("utf-8", errors="replace")
            except Exception:
                pass
        if profile_row[3]:
            try:
                vehicle_info = rsa_crypto.decrypt(profile_row[3], priv_key).decode("utf-8", errors="replace")
            except Exception:
                pass

    profile_data = {
        "username": username,
        "role": role,
        "name": name,
        "email": email,
        "phone": phone,
        "address": address,
        "vehicle_info": vehicle_info,
    }

    return render_template("edit_profile.html", profile=profile_data)

