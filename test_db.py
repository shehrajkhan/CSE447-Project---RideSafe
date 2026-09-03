"""
Helper script to test Supabase PostgreSQL database connection.
Run with: python test_db.py
"""

import psycopg2
from config import Config


def test_connection():
    print("Connecting to Supabase PostgreSQL...")
    try:
        conn = psycopg2.connect(Config.DATABASE_URL, connect_timeout=5)
        cur = conn.cursor()
        cur.execute("SELECT current_database(), current_user;")
        db_name, user_name = cur.fetchone()
        print(f"\nSUCCESS! Connected to database '{db_name}' as '{user_name}'.\n")

        # Check existing tables
        cur.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public';
        """)
        tables = [t[0] for t in cur.fetchall()]
        print(f"Tables in database ({len(tables)} found):")
        for table in sorted(tables):
            print(f" - {table}")

        conn.close()
        return True
    except Exception as e:
        print(f"\nCONNECTION ERROR: {e}\n")
        return False


if __name__ == "__main__":
    test_connection()
