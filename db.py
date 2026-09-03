"""
db.py - Supabase/Postgres connection helper.

Uses psycopg2 directly (not an ORM), matching the DATABASE_URL from .env.
"""

import os
import psycopg2
from config import Config


def get_conn():
    """Open a new connection to the Supabase Postgres database."""
    url = os.environ.get("DATABASE_URL") or Config.DATABASE_URL
    return psycopg2.connect(url)

