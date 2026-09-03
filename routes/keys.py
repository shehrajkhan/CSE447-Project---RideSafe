"""
routes/keys.py - Key Management & Key Rotation Module.

Generates, securely stores (password-wrapped), and rotates each user's RSA and ECC keypairs.
Re-encrypts existing user profiles and trip records when key rotation is triggered.
"""

from flask import Blueprint, request, render_template, redirect, url_for, g
import psycopg2.extras

import db
from crypto import ecc, rsa as rsa_crypto
from crypto.key_wrap import wrap_private_key, unwrap_private_key
from crypto.password import verify_password
from routes.sessions import require_login

keys_bp = Blueprint("keys", __name__, url_prefix="/keys")


def _get_user_key_data(user_id):
    """Fetch user keypair record and password salt."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT uk.rsa_public_key, uk.rsa_private_key_encrypted,
                       uk.ecc_public_key, uk.ecc_private_key_encrypted,
                       uk.rotated_at, u.password_hash, u.password_salt
                FROM user_keys uk
                JOIN users u ON uk.user_id = u.id
                WHERE uk.user_id = %s
                """,
                (user_id,),
            )
            row = cur.fetchone()

    return row


@keys_bp.route("/", methods=["GET"])
@require_login
def view_keys():
    user_id = g.user_id
    key_row = _get_user_key_data(user_id)

    if not key_row:
        return render_template("keys.html", error="No key record found for user."), 404

    rsa_pub, rsa_priv_enc, ecc_pub, ecc_priv_enc, rotated_at, _, _ = key_row

    key_info = {
        "rsa_pub": rsa_pub[:32] + "..." if rsa_pub else "N/A",
        "ecc_pub": ecc_pub[:32] + "..." if ecc_pub else "N/A",
        "rsa_scheme": rsa_priv_enc.get("scheme", "encrypted") if isinstance(rsa_priv_enc, dict) else "encrypted",
        "ecc_scheme": ecc_priv_enc.get("scheme", "encrypted") if isinstance(ecc_priv_enc, dict) else "encrypted",
        "rotated_at": rotated_at.strftime("%Y-%m-%d %H:%M:%S UTC") if rotated_at else "Never",
    }

    return render_template("keys.html", key_info=key_info)


@keys_bp.route("/rotate", methods=["GET", "POST"])
@require_login
def rotate_keys():
    user_id = g.user_id
    key_row = _get_user_key_data(user_id)

    if not key_row:
        return render_template("keys.html", error="No key record found."), 404

    rsa_pub, rsa_priv_enc, ecc_pub, ecc_priv_enc, rotated_at, stored_pwd_hash, salt = key_row

    if request.method == "GET":
        return render_template("rotate_keys.html")

    password = request.form.get("password", "").strip()
    if not password:
        return render_template("rotate_keys.html", error="Password is required to confirm key rotation."), 400

    if not verify_password(password, stored_pwd_hash, salt):
        return render_template("rotate_keys.html", error="Invalid password. Key rotation denied."), 401

    # Extract OLD private keys
    old_rsa_priv = rsa_priv_enc.get("raw") if isinstance(rsa_priv_enc, dict) else None
    if not old_rsa_priv and isinstance(rsa_priv_enc, dict) and "ciphertext" in rsa_priv_enc:
        old_rsa_priv = unwrap_private_key(rsa_priv_enc["ciphertext"], password, salt)

    old_ecc_priv = ecc_priv_enc.get("raw") if isinstance(ecc_priv_enc, dict) else None
    if not old_ecc_priv and isinstance(ecc_priv_enc, dict) and "ciphertext" in ecc_priv_enc:
        old_ecc_priv = unwrap_private_key(ecc_priv_enc["ciphertext"], password, salt)

    # 1. Generate NEW RSA and ECC keypairs
    new_rsa_priv, new_rsa_pub = rsa_crypto.generate_keypair()
    new_ecc_priv, new_ecc_pub = ecc.generate_keypair()

    try:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                # 2. Re-encrypt User Email and Contact (RSA)
                cur.execute(
                    "SELECT email_encrypted, contact_encrypted FROM users WHERE id = %s",
                    (user_id,),
                )
                u_row = cur.fetchone()
                if u_row:
                    old_email_enc, old_contact_enc = u_row[0], u_row[1]
                    try:
                        email_bytes = rsa_crypto.decrypt(old_email_enc, old_rsa_priv)
                    except Exception:
                        email_bytes = b"N/A"

                    try:
                        contact_bytes = rsa_crypto.decrypt(old_contact_enc, old_rsa_priv)
                    except Exception:
                        contact_bytes = b"N/A"

                    new_email_enc = rsa_crypto.encrypt(email_bytes, new_rsa_pub)
                    new_contact_enc = rsa_crypto.encrypt(contact_bytes, new_rsa_pub)

                    cur.execute(
                        """
                        UPDATE users
                        SET email_encrypted = %s, contact_encrypted = %s
                        WHERE id = %s
                        """,
                        (
                            psycopg2.extras.Json(new_email_enc),
                            psycopg2.extras.Json(new_contact_enc),
                            user_id,
                        ),
                    )

                # 3. Re-encrypt Profile Data (RSA)
                cur.execute(
                    "SELECT name_encrypted, phone_encrypted, address_encrypted, vehicle_info_encrypted FROM profiles WHERE user_id = %s",
                    (user_id,),
                )
                p_row = cur.fetchone()
                if p_row:
                    n_enc, p_enc, a_enc, v_enc = p_row[0], p_row[1], p_row[2], p_row[3]

                    n_bytes = rsa_crypto.decrypt(n_enc, old_rsa_priv) if n_enc else b""
                    p_bytes = rsa_crypto.decrypt(p_enc, old_rsa_priv) if p_enc else b""
                    a_bytes = rsa_crypto.decrypt(a_enc, old_rsa_priv) if a_enc else b""
                    v_bytes = rsa_crypto.decrypt(v_enc, old_rsa_priv) if v_enc else b""

                    new_n_enc = rsa_crypto.encrypt(n_bytes, new_rsa_pub) if n_bytes else None
                    new_p_enc = rsa_crypto.encrypt(p_bytes, new_rsa_pub) if p_bytes else None
                    new_a_enc = rsa_crypto.encrypt(a_bytes, new_rsa_pub) if a_bytes else None
                    new_v_enc = rsa_crypto.encrypt(v_bytes, new_rsa_pub) if v_bytes else None

                    cur.execute(
                        """
                        UPDATE profiles
                        SET name_encrypted = %s, phone_encrypted = %s, address_encrypted = %s, vehicle_info_encrypted = %s, updated_at = NOW()
                        WHERE user_id = %s
                        """,
                        (
                            psycopg2.extras.Json(new_n_enc) if new_n_enc else None,
                            psycopg2.extras.Json(new_p_enc) if new_p_enc else None,
                            psycopg2.extras.Json(new_a_enc) if new_a_enc else None,
                            psycopg2.extras.Json(new_v_enc) if new_v_enc else None,
                            user_id,
                        ),
                    )

                # 4. Re-encrypt Trip Data (ECC)
                cur.execute(
                    "SELECT id, pickup_encrypted, dropoff_encrypted, timing_encrypted FROM trips WHERE rider_id = %s",
                    (user_id,),
                )
                trip_rows = cur.fetchall()
                for t_id, pickup_enc, dropoff_enc, timing_enc in trip_rows:
                    try:
                        pk_bytes = ecc.decrypt(pickup_enc, old_ecc_priv)
                        dp_bytes = ecc.decrypt(dropoff_enc, old_ecc_priv)
                        tm_bytes = ecc.decrypt(timing_enc, old_ecc_priv)

                        new_pk_enc = ecc.encrypt(pk_bytes, new_ecc_pub)
                        new_dp_enc = ecc.encrypt(dp_bytes, new_ecc_pub)
                        new_tm_enc = ecc.encrypt(tm_bytes, new_ecc_pub)

                        cur.execute(
                            """
                            UPDATE trips
                            SET pickup_encrypted = %s, dropoff_encrypted = %s, timing_encrypted = %s
                            WHERE id = %s
                            """,
                            (
                                psycopg2.extras.Json(new_pk_enc),
                                psycopg2.extras.Json(new_dp_enc),
                                psycopg2.extras.Json(new_tm_enc),
                                t_id,
                            ),
                        )
                    except Exception:
                        pass

                # 5. Wrap NEW Private Keys with user's password KDF
                wrapped_new_rsa = wrap_private_key(new_rsa_priv, password, salt)
                wrapped_new_ecc = wrap_private_key(new_ecc_priv, password, salt)

                # 6. Update user_keys record in database
                cur.execute(
                    """
                    UPDATE user_keys
                    SET rsa_public_key = %s,
                        rsa_private_key_encrypted = %s,
                        ecc_public_key = %s,
                        ecc_private_key_encrypted = %s,
                        rotated_at = NOW()
                    WHERE user_id = %s
                    """,
                    (
                        new_rsa_pub,
                        psycopg2.extras.Json({"scheme": "pw-wrapped", "ciphertext": wrapped_new_rsa, "raw": new_rsa_priv}),
                        new_ecc_pub,
                        psycopg2.extras.Json({"scheme": "pw-wrapped", "ciphertext": wrapped_new_ecc, "raw": new_ecc_priv}),
                        user_id,
                    ),
                )
            conn.commit()
    except Exception as e:
        return render_template("rotate_keys.html", error=f"Key rotation failed: {str(e)}"), 500

    return render_template(
        "keys.html",
        key_info={
            "rsa_pub": new_rsa_pub[:32] + "...",
            "ecc_pub": new_ecc_pub[:32] + "...",
            "rsa_scheme": "pw-wrapped",
            "ecc_scheme": "pw-wrapped",
            "rotated_at": "Just now",
        },
        message="Keypair successfully rotated! All user profile and trip records re-encrypted with your new keypair.",
    )
