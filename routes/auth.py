"""
routes/auth.py - Registration, email OTP login, and logout.

Login flow:

    1. User enters username + password.
    2. Password is verified.
    3. A random 6-digit OTP is generated.
    4. OTP is emailed to the user's registered email address.
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

import db

from config import Config

from crypto import (
    ecc,
    rsa as rsa_crypto,
    otp,
)

from crypto.password import (
    hash_password,
    verify_password,
)

from routes.sessions import (
    issue_session,
    revoke_session,
    require_login,
)


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

    if not Config.MAIL_USERNAME:
        raise RuntimeError(
            "MAIL_USERNAME is not configured"
        )

    if not Config.MAIL_PASSWORD:
        raise RuntimeError(
            "MAIL_PASSWORD is not configured"
        )

    if not Config.MAIL_FROM:
        raise RuntimeError(
            "MAIL_FROM is not configured"
        )

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
    encrypted_email
) -> str:
    """
    Recover the user's registered email.

    The current RideSafe RSA implementation is still a pass-through
    stub, so it can decrypt the JSON blob using the same placeholder
    key currently used during registration.

    When the team's real RSA implementation is completed, this helper
    should use the proper private-key handling.
    """

    plaintext = rsa_crypto.decrypt(
        encrypted_email,
        "placeholder-until-rsa-keys-exist",
    )

    if isinstance(plaintext, bytes):
        email = plaintext.decode(
            "utf-8",
            errors="strict",
        )
    else:
        email = str(plaintext)

    email = email.strip()

    if not email or "@" not in email:
        raise ValueError(
            "Registered email address is invalid"
        )

    return email


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

    username = request.form[
        "username"
    ].strip()

    password = request.form[
        "password"
    ]

    email = request.form[
        "email"
    ].strip()

    contact = request.form.get(
        "contact",
        "",
    ).strip()

    role = request.form.get(
        "role",
        "rider",
    )

    # ---------------------------------------------------------------
    # Validate basic input
    # ---------------------------------------------------------------

    if not username:
        return render_template(
            "register.html",
            error="Username is required.",
        ), 400

    if not password:
        return render_template(
            "register.html",
            error="Password is required.",
        ), 400

    if not email or "@" not in email:
        return render_template(
            "register.html",
            error="Please enter a valid email address.",
        ), 400

    if role not in {
        "rider",
        "driver",
    }:
        return render_template(
            "register.html",
            error="Invalid role.",
        ), 400

    # ---------------------------------------------------------------
    # Password hashing
    # ---------------------------------------------------------------

    password_hash, salt = hash_password(
        password
    )

    # ---------------------------------------------------------------
    # Encrypt profile fields
    # ---------------------------------------------------------------

    email_enc = rsa_crypto.encrypt(
        email.encode(),
        "placeholder-until-rsa-keys-exist",
    )

    contact_enc = rsa_crypto.encrypt(
        contact.encode(),
        "placeholder-until-rsa-keys-exist",
    )

    # ---------------------------------------------------------------
    # Store user
    # ---------------------------------------------------------------

    try:

        with db.get_conn() as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO users (
                        username,
                        password_hash,
                        password_salt,
                        role,
                        email_encrypted,
                        contact_encrypted
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    RETURNING id
                    """,
                    (
                        username,
                        password_hash,
                        salt,
                        role,
                        psycopg2.extras.Json(
                            email_enc
                        ),
                        psycopg2.extras.Json(
                            contact_enc
                        ),
                    ),
                )

                user_id = cur.fetchone()[0]

                # ---------------------------------------------------
                # ECC keypair
                # ---------------------------------------------------

                ecc_priv, ecc_pub = (
                    ecc.generate_keypair()
                )

                # ---------------------------------------------------
                # RSA keypair
                # ---------------------------------------------------

                rsa_priv, rsa_pub = (
                    rsa_crypto.generate_keypair()
                )

                # ---------------------------------------------------
                # Store keys
                # ---------------------------------------------------

                cur.execute(
                    """
                    INSERT INTO user_keys (
                        user_id,
                        rsa_public_key,
                        rsa_private_key_encrypted,
                        ecc_public_key,
                        ecc_private_key_encrypted
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        user_id,
                        rsa_pub,
                        psycopg2.extras.Json(
                            {
                                "_todo":
                                    "wrap with password-derived key",
                                "raw":
                                    rsa_priv,
                            }
                        ),
                        ecc_pub,
                        psycopg2.extras.Json(
                            {
                                "_todo":
                                    "wrap with password-derived key",
                                "raw":
                                    ecc_priv,
                            }
                        ),
                    ),
                )

            conn.commit()

    except Exception:
        return render_template(
            "register.html",
            error=(
                "Registration failed. "
                "The username may already exist."
            ),
        ), 400

    # ---------------------------------------------------------------
    # IMPORTANT:
    #
    # DO NOT issue a session here.
    #
    # The user must log in and complete email OTP verification.
    # ---------------------------------------------------------------

    return redirect(
        url_for("auth.login")
    )


# ---------------------------------------------------------------------------
# Login - Step 1: username + password
# ---------------------------------------------------------------------------

@auth_bp.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    if request.method == "GET":

        # If an old pending challenge exists,
        # remove it before showing login again.
        session.pop(
            "pending_2fa_challenge",
            None,
        )

        return render_template(
            "login.html"
        )

    username = request.form[
        "username"
    ].strip()

    password = request.form[
        "password"
    ]

    # ---------------------------------------------------------------
    # Find user
    # ---------------------------------------------------------------

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    id,
                    password_hash,
                    password_salt,
                    role,
                    email_encrypted,
                    status
                FROM users
                WHERE username = %s
                """,
                (username,),
            )

            row = cur.fetchone()

    # ---------------------------------------------------------------
    # Username/password validation
    # ---------------------------------------------------------------

    if not row:

        return render_template(
            "login.html",
            error="Invalid username or password.",
        ), 401

    user_id = str(row[0])
    password_hash = row[1]
    password_salt = row[2]
    role = row[3]
    email_encrypted = row[4]
    status = row[5]

    if status != "active":

        return render_template(
            "login.html",
            error="Your account is suspended.",
        ), 403

    if not verify_password(
        password,
        password_hash,
        password_salt,
    ):

        return render_template(
            "login.html",
            error="Invalid username or password.",
        ), 401

    # ---------------------------------------------------------------
    # Password is correct.
    #
    # DO NOT create the authenticated session yet.
    # ---------------------------------------------------------------

    try:

        registered_email = (
            _decrypt_registered_email(
                email_encrypted
            )
        )

    except Exception:

        return render_template(
            "login.html",
            error=(
                "Unable to retrieve your "
                "registered email address."
            ),
        ), 500

    # ---------------------------------------------------------------
    # Generate random 6-digit email OTP
    # ---------------------------------------------------------------

    otp_code = otp.generate_email_otp()

    # ---------------------------------------------------------------
    # Create temporary server-side challenge
    #
    # The OTP itself is NOT stored.
    # Only its HMAC hash is stored in memory.
    # ---------------------------------------------------------------

    challenge_id = (
        otp.create_email_otp_challenge(
            user_id,
            otp_code,
        )
    )

    # ---------------------------------------------------------------
    # Send OTP to registered email
    # ---------------------------------------------------------------

    try:

        _send_otp_email(
            registered_email,
            otp_code,
        )

    except Exception as exc:

        # Remove the temporary challenge if email delivery fails.
        otp.discard_email_otp_challenge(
            challenge_id
        )

        print(
            "RideSafe OTP email error:",
            exc,
        )

        return render_template(
            "login.html",
            error=(
                "We could not send the "
                "verification email. "
                "Please try again."
            ),
        ), 500

    # ---------------------------------------------------------------
    # Store ONLY the random challenge ID.
    #
    # The OTP itself is NOT stored in Flask session.
    # The OTP hash is NOT stored in Flask session.
    # The OTP secret is NOT stored in Flask session.
    # ---------------------------------------------------------------

    session["pending_2fa_challenge"] = (
        challenge_id
    )

    # Store role separately only if needed by your existing flow.
    # This is NOT sensitive authentication material.
    session["pending_2fa_role"] = role

    # ---------------------------------------------------------------
    # Go to OTP page
    # ---------------------------------------------------------------

    return redirect(
        url_for("auth.verify_2fa")
    )


# ---------------------------------------------------------------------------
# Login - Step 2: email OTP verification
# ---------------------------------------------------------------------------

@auth_bp.route(
    "/verify-2fa",
    methods=["GET", "POST"],
)
def verify_2fa():

    challenge_id = session.get(
        "pending_2fa_challenge"
    )

    if not challenge_id:

        return redirect(
            url_for("auth.login")
        )

    # ---------------------------------------------------------------
    # GET
    # ---------------------------------------------------------------

    if request.method == "GET":

        remaining = (
            otp.get_email_otp_remaining_seconds(
                challenge_id
            )
        )

        if remaining is None:

            session.pop(
                "pending_2fa_challenge",
                None,
            )

            session.pop(
                "pending_2fa_role",
                None,
            )

            return render_template(
                "verify_2fa.html",
                error=(
                    "Your verification code "
                    "has expired. Please log in again."
                ),
                expired=True,
            ), 400

        return render_template(
            "verify_2fa.html",
            remaining_seconds=remaining,
        )

    # ---------------------------------------------------------------
    # POST
    # ---------------------------------------------------------------

    code = request.form.get(
        "otp_code",
        "",
    ).strip()

    if (
        len(code) != 6
        or not code.isdigit()
    ):

        remaining = (
            otp.get_email_otp_remaining_seconds(
                challenge_id
            )
        )

        return render_template(
            "verify_2fa.html",
            error=(
                "Please enter the "
                "6-digit verification code."
            ),
            remaining_seconds=remaining,
        ), 400

    # ---------------------------------------------------------------
    # Verify OTP
    #
    # Successful verification consumes the challenge.
    # ---------------------------------------------------------------

    user_id = otp.verify_email_otp(
        challenge_id,
        code,
    )

    if user_id is None:

        remaining = (
            otp.get_email_otp_remaining_seconds(
                challenge_id
            )
        )

        if remaining is None:

            session.pop(
                "pending_2fa_challenge",
                None,
            )

            session.pop(
                "pending_2fa_role",
                None,
            )

            return render_template(
                "verify_2fa.html",
                error=(
                    "The verification code has "
                    "expired. Please log in again."
                ),
                expired=True,
            ), 400

        return render_template(
            "verify_2fa.html",
            error=(
                "Invalid verification code."
            ),
            remaining_seconds=remaining,
        ), 400

    # ---------------------------------------------------------------
    # OTP is correct.
    #
    # Remove temporary login information.
    # ---------------------------------------------------------------

    session.pop(
        "pending_2fa_challenge",
        None,
    )

    role = session.pop(
        "pending_2fa_role",
        None,
    )

    # ---------------------------------------------------------------
    # NOW create the real authenticated session.
    # ---------------------------------------------------------------

    token = issue_session(
        user_id,
        role,
    )

    response = make_response(
        redirect(
            url_for("trips.dashboard")
        )
    )

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

    token = request.cookies.get(
        "session_token"
    )

    if token:
        revoke_session(token)

    response = make_response(
        redirect(
            url_for("auth.login")
        )
    )

    response.delete_cookie(
        "session_token"
    )

    return response