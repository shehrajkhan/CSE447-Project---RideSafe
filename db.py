"""
db.py - Supabase/Postgres connection helper.

Uses psycopg2 directly (not an ORM), matching the DATABASE_URL from .env.
"""

import psycopg2
from config import Config


def get_conn():
    """Open a new connection to the Supabase Postgres database."""
    return psycopg2.connect(Config.DATABASE_URL)
