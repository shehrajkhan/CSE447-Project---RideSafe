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


def ensure_emergencies_table():
    """Create emergencies table if it does not exist."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS emergencies (
                        id uuid primary key default gen_random_uuid(),
                        trip_id uuid not null references trips(id) on delete cascade,
                        rider_id uuid not null references users(id),
                        driver_id uuid references users(id),
                        driver_name text,
                        driver_phone text,
                        driver_vehicle text,
                        status text not null default 'active' check (status in ('active', 'resolved')),
                        created_at timestamptz not null default now(),
                        resolved_at timestamptz
                    );
                """)
            conn.commit()
    except Exception as e:
        print("ensure_emergencies_table error:", e)


