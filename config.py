"""
App configuration. Reads secrets from environment variables - never commit
real credentials. Each teammate creates their own local .env (see .env.example).
"""

import os
from dotenv import load_dotenv

# Load variables from .env file into os.environ (override cached process env vars)
load_dotenv(override=True)



class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "dev-key-change-me")

    # Supabase / Postgres connection (from Supabase project settings -> Database)
    SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
    SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
    DATABASE_URL = os.environ.get("DATABASE_URL", "")  # postgres connection string

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
