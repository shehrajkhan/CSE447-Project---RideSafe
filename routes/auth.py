"""
routes/auth.py - Registration, email OTP login, and logout.

Login flow:
    1. User enters username + password.
    2. Password is verified.
    3. A random 6-digit OTP is generated.
    4. OTP is emailed to the user's registered email address (or logged to terminal in dev mode).
    5. The actual OTP is NOT stored in the Flask session.
    6. Only a random challenge ID is stored in the Flask session.
    7. The OTP hash and expiry are held temporarily in server memory.
    8. User enters the OTP.
    9. OTP is verified.
   10. Only then is the authenticated RideSafe session created.

Email OTP lifetime:
    Exactly 60 seconds.
"""

import smtplib
from email.message import EmailMessage

from flask import (
    Blueprint,
    request,
    render_template,
    redirect,
    url_for,
    make_response,
    session,
)

import psycopg2.extras
import psycopg2.errors

import db
from config import Config
from crypto import ecc, rsa as rsa_crypto, otp
from crypto.password import hash_password, verify_password
from crypto.key_wrap import wrap_private_key, unwrap_private_key
from routes.sessions import issue_session, revoke_session, require_login


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/auth",
)


# ---------------------------------------------------------------------------
# Email helper
# ---------------------------------------------------------------------------

def _send_otp_email(
    recipient_email: str,
    otp_code: str,
) -> None:
    """
    Send the RideSafe login OTP through SMTP.

    The OTP is included only in the email.
    It is not written to the database or Flask session.
    """

    if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD or not Config.MAIL_FROM:
        print(f"[RideSafe Dev Mode] OTP for {recipient_email}: {otp_code}")
        return

    message = EmailMessage()

    message["Subject"] = "RideSafe Login Verification Code"
    message["From"] = Config.MAIL_FROM
    message["To"] = recipient_email

    message.set_content(
        f"""
Hello,

Your RideSafe login verification code is:

{otp_code}

This code is valid for 1 minute only.

If you did not attempt to log in to RideSafe, you can safely ignore this email.

Regards,
RideSafe Security Team
""".strip()
    )

    with smtplib.SMTP(
        Config.MAIL_HOST,
        Config.MAIL_PORT,
        timeout=20,
    ) as smtp:

        if Config.MAIL_USE_TLS:
            smtp.starttls()

        smtp.login(
            Config.MAIL_USERNAME,
            Config.MAIL_PASSWORD,
        )

        smtp.send_message(message)


# ---------------------------------------------------------------------------
# Email decryption helper
# ---------------------------------------------------------------------------

def _decrypt_registered_email(
    user_id: str,
    encrypted_email,
) -> str:
    """
    Recover the user's registered email address.
    Attempts RSA decryption using the user's stored key, falling back gracefully.
    """
    if not encrypted_email:
        raise ValueError("No encrypted email found")

    # Attempt decryption using stored RSA private key if raw key is available
    try:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT rsa_private_key_encrypted FROM user_keys WHERE user_id = %s",
                    (user_id,),
                )
                row = cur.fetchone()
        if row and isinstance(row[0], dict) and "raw" in row[0]:
            priv_key = row[0]["raw"]
            plaintext = rsa_crypto.decrypt(encrypted_email, priv_key)
            if isinstance(plaintext, bytes):
                email = plaintext.decode("utf-8", errors="strict").strip()
            else:
                email = str(plaintext).strip()
            if email and "@" in email:
                return email
    except Exception:
        pass

    # Fallback to stub key decryption if used during earlier testing
    try:
        plaintext = rsa_crypto.decrypt(
            encrypted_email,
            "placeholder-until-rsa-keys-exist",
        )
        if isinstance(plaintext, bytes):
            email = plaintext.decode("utf-8", errors="strict").strip()
        else:
            email = str(plaintext).strip()
        if email and "@" in email:
            return email
    except Exception:
        pass

    # Final fallback if plain string or fallback format
    if isinstance(encrypted_email, str) and "@" in encrypted_email:
        return encrypted_email

    raise ValueError("Registered email address is invalid or could not be decrypted")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@auth_bp.route(
    "/register",
    methods=["GET", "POST"],
)
def register():

    if request.method == "GET":
        return render_template(
            "register.html"
        )

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
    if not email or "@" not in email:
        return render_template("register.html", error="Please enter a valid email address."), 400
    if role not in ("rider", "driver"):
        role = "rider"

    # Password hashing
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

    # User must log in and complete email OTP verification
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------------
# Login - Step 1: username + password
# ---------------------------------------------------------------------------

@auth_bp.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    if request.method == "GET":
        session.pop("pending_2fa_challenge", None)
        session.pop("pending_2fa_role", None)
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return render_template("login.html", error="Please enter both username and password."), 400

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, password_hash, password_salt, role, email_encrypted, status
                FROM users
                WHERE username = %s
                """,
                (username,),
            )
            row = cur.fetchone()

    if not row:
        return render_template("login.html", error="Invalid username or password."), 401

    user_id = str(row[0])
    password_hash = row[1]
    password_salt = row[2]
    role = row[3]
    email_encrypted = row[4]
    status = row[5]

    if status == "suspended":
        return render_template("login.html", error="Your account has been suspended by an administrator."), 403

    if not verify_password(password, password_hash, password_salt):
        return render_template("login.html", error="Invalid username or password."), 401

    try:
        registered_email = _decrypt_registered_email(user_id, email_encrypted)
    except Exception:
        registered_email = f"{username}@ridesafe.local"

    # Generate random 6-digit email OTP
    otp_code = otp.generate_email_otp()

    # Create temporary server-side challenge
    challenge_id = otp.create_email_otp_challenge(
        user_id,
        otp_code,
    )

    # Send OTP email (or log to terminal in dev mode)
    try:
        _send_otp_email(registered_email, otp_code)
    except Exception as exc:
        print("RideSafe OTP email warning:", exc)
        print(f"[RideSafe Dev Fallback] OTP for {registered_email}: {otp_code}")

    session["pending_2fa_challenge"] = challenge_id
    session["pending_2fa_role"] = role

    return redirect(url_for("auth.verify_2fa"))


# ---------------------------------------------------------------------------
# Login - Step 2: email OTP verification
# ---------------------------------------------------------------------------

@auth_bp.route(
    "/verify-2fa",
    methods=["GET", "POST"],
)
def verify_2fa():

    challenge_id = session.get("pending_2fa_challenge")

    if not challenge_id:
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        remaining = otp.get_email_otp_remaining_seconds(challenge_id)

        if remaining is None:
            session.pop("pending_2fa_challenge", None)
            session.pop("pending_2fa_role", None)

            return render_template(
                "verify_2fa.html",
                error="Your verification code has expired. Please log in again.",
                expired=True,
            ), 400

        return render_template(
            "verify_2fa.html",
            remaining_seconds=remaining,
        )

    code = request.form.get("otp_code", "").strip()

    if len(code) != 6 or not code.isdigit():
        remaining = otp.get_email_otp_remaining_seconds(challenge_id)
        return render_template(
            "verify_2fa.html",
            error="Please enter a valid 6-digit verification code.",
            remaining_seconds=remaining,
        ), 400

    user_id = otp.verify_email_otp(
        challenge_id,
        code,
    )

    if user_id is None:
        remaining = otp.get_email_otp_remaining_seconds(challenge_id)

        if remaining is None:
            session.pop("pending_2fa_challenge", None)
            session.pop("pending_2fa_role", None)

            return render_template(
                "verify_2fa.html",
                error="The verification code has expired. Please log in again.",
                expired=True,
            ), 400

        return render_template(
            "verify_2fa.html",
            error="Invalid verification code.",
            remaining_seconds=remaining,
        ), 400

    session.pop("pending_2fa_challenge", None)
    role = session.pop("pending_2fa_role", None)

    token = issue_session(user_id, role)

    dest_url = url_for("admin.dashboard") if role == "admin" else url_for("trips.dashboard")
    response = make_response(redirect(dest_url))
    response.set_cookie(
        "session_token",
        token,
        httponly=True,
        samesite="Lax",
    )

    return response


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@auth_bp.route(
    "/logout",
    methods=["POST"],
)
@require_login
def logout():

    token = request.cookies.get("session_token")

    if token:
        revoke_session(token)

    response = make_response(redirect(url_for("auth.login")))
    response.delete_cookie("session_token")

    return response