"""
App configuration.

Secrets are loaded from environment variables / .env.
Real credentials must never be committed to Git.
"""

import os
from dotenv import load_dotenv

# Load variables from .env file into os.environ (override cached process env vars)
load_dotenv(override=True)


from dotenv import load_dotenv


# Load .env from the project root.
load_dotenv()


class Config:

    # -----------------------------------------------------------------------
    # Flask
    # -----------------------------------------------------------------------

    SECRET_KEY = os.environ.get(
        "FLASK_SECRET_KEY",
        "dev-key-change-me",
    )

    # -----------------------------------------------------------------------
    # Supabase / PostgreSQL
    # -----------------------------------------------------------------------

    SUPABASE_URL = os.environ.get(
        "SUPABASE_URL",
        "",
    )

    SUPABASE_KEY = os.environ.get(
        "SUPABASE_KEY",
        "",
    )

    DATABASE_URL = os.environ.get(
        "DATABASE_URL",
        "",
    )

    # -----------------------------------------------------------------------
    # RideSafe HMAC key
    # -----------------------------------------------------------------------

    MAC_KEY = os.environ.get(
        "RIDESAFE_MAC_KEY",
        "dev-mac-key-ridesafe-integrity-256bit",
    )

    # -----------------------------------------------------------------------
    # Email / SMTP
    # -----------------------------------------------------------------------

    MAIL_HOST = os.environ.get(
        "MAIL_HOST",
        "smtp.gmail.com",
    )

    MAIL_PORT = int(
        os.environ.get(
            "MAIL_PORT",
            "587",
        )
    )

    MAIL_USERNAME = os.environ.get(
        "MAIL_USERNAME",
        "",
    )

    MAIL_PASSWORD = os.environ.get(
        "MAIL_PASSWORD",
        "",
    )

    MAIL_FROM = os.environ.get(
        "MAIL_FROM",
        MAIL_USERNAME,
    )

    MAIL_USE_TLS = (
        os.environ.get(
            "MAIL_USE_TLS",
            "true",
        ).lower()
        == "true"
    )

    # -----------------------------------------------------------------------
    # Cookie security
    # -----------------------------------------------------------------------

    SESSION_COOKIE_HTTPONLY = True

    SESSION_COOKIE_SAMESITE = "Lax"