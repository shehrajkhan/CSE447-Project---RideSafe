"""
routes/admin.py - RBAC-protected admin routes & Uber-style Admin Dashboard.

Provides full administrative control (user account suspension/reactivation,
role overview, trip logs monitoring) while enforcing zero-knowledge boundaries:
Admins can manage platform infrastructure but cannot decrypt private user data.
"""

from functools import wraps
from flask import Blueprint, request, render_template, redirect, url_for, g, make_response
import psycopg2.extras

import db
from crypto import rsa as rsa_crypto, ecc
from crypto.password import hash_password, verify_password
from crypto.key_wrap import wrap_private_key
from routes.sessions import issue_session, require_login

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def require_admin(f):
    @wraps(f)
    @require_login
    def decorated_function(*args, **kwargs):
        if g.user_role != "admin":
            return render_template("error.html", error="Access Denied: Administrator privileges required."), 403
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route("/login", methods=["GET", "POST"])
def admin_login():
    """Admin Login Panel."""
    if request.method == "GET":
        return render_template("admin_login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return render_template("admin_login.html", error="Username and password are required."), 400

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, password_hash, password_salt, role, status FROM users WHERE username = %s",
                (username,),
            )
            row = cur.fetchone()

    # Allow creating/initializing an admin account if action is register_admin
    if not row:
        if request.form.get("action") == "register_admin":
            email = f"{username}@admin.ridesafe.com"
            password_hash, salt = hash_password(password)
            rsa_priv, rsa_pub = rsa_crypto.generate_keypair()
            ecc_priv, ecc_pub = ecc.generate_keypair()
            email_enc = rsa_crypto.encrypt(email.encode(), rsa_pub)
            contact_enc = rsa_crypto.encrypt(b"ADMIN-DIRECT", rsa_pub)

            try:
                with db.get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO users (username, password_hash, password_salt, role, email_encrypted, contact_encrypted, status)
                            VALUES (%s, %s, %s, 'admin', %s, %s, 'active')
                            RETURNING id
                            """,
                            (username, password_hash, salt, psycopg2.extras.Json(email_enc), psycopg2.extras.Json(contact_enc)),
                        )
                        user_id = cur.fetchone()[0]

                        wrapped_rsa = wrap_private_key(rsa_priv, password, salt)
                        wrapped_ecc = wrap_private_key(ecc_priv, password, salt)
                        cur.execute(
                            """
                            INSERT INTO user_keys (user_id, rsa_public_key, rsa_private_key_encrypted, ecc_public_key, ecc_private_key_encrypted)
                            VALUES (%s, %s, %s, %s, %s)
                            """,
                            (
                                user_id, rsa_pub, psycopg2.extras.Json({"scheme": "pw-wrapped", "ciphertext": wrapped_rsa, "raw": rsa_priv}),
                                ecc_pub, psycopg2.extras.Json({"scheme": "pw-wrapped", "ciphertext": wrapped_ecc, "raw": ecc_priv}),
                            ),
                        )
                        cur.execute(
                            """
                            INSERT INTO profiles (user_id, name_encrypted, phone_encrypted, address_encrypted)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (
                                user_id,
                                psycopg2.extras.Json(rsa_crypto.encrypt(username.encode(), rsa_pub)),
                                psycopg2.extras.Json(contact_enc),
                                psycopg2.extras.Json(rsa_crypto.encrypt(b"System Admin", rsa_pub)),
                            ),
                        )
                    conn.commit()

                token = issue_session(str(user_id))
                resp = make_response(redirect(url_for("admin.dashboard")))
                resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
                return resp
            except Exception as err:
                return render_template("admin_login.html", error=f"Admin creation failed: {err}"), 500

        return render_template("admin_login.html", error="Admin account not found. Toggle 'Create Admin Account' below to initialize."), 401

    user_id, stored_hash, salt, role, status = str(row[0]), row[1], row[2], row[3], row[4]

    if role != "admin":
        return render_template("admin_login.html", error="Access Denied: This account is not an Administrator."), 403

    if status == "suspended":
        return render_template("admin_login.html", error="Account is suspended. Contact system administrator."), 403

    if not verify_password(password, stored_hash, salt):
        return render_template("admin_login.html", error="Invalid admin password."), 401

    token = issue_session(user_id)
    resp = make_response(redirect(url_for("admin.dashboard")))
    resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
    return resp


@admin_bp.route("/dashboard", methods=["GET"])
@require_admin
def dashboard():
    """Uber-style Admin Dashboard."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            # Stats count
            cur.execute("SELECT COUNT(*) FROM users")
            total_users = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM users WHERE role = 'rider'")
            total_riders = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM users WHERE role = 'driver'")
            total_drivers = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM trips")
            total_trips = cur.fetchone()[0]

            # Fetch all user metadata
            cur.execute("SELECT id, username, role, status, created_at FROM users ORDER BY created_at DESC")
            users_rows = cur.fetchall()
            users_list = [
                {
                    "id": str(r[0]),
                    "username": r[1],
                    "role": r[2],
                    "status": r[3],
                    "created_at": r[4].strftime("%Y-%m-%d %H:%M") if r[4] else "N/A",
                }
                for r in users_rows
            ]

            # Fetch all trips metadata
            cur.execute(
                """
                SELECT t.id, t.status, t.created_at, u_r.username as rider, COALESCE(u_d.username, 'Unassigned') as driver
                FROM trips t
                JOIN users u_r ON t.rider_id = u_r.id
                LEFT JOIN users u_d ON t.driver_id = u_d.id
                ORDER BY t.created_at DESC
                """
            )
            trips_rows = cur.fetchall()
            trips_list = [
                {
                    "id": str(r[0]),
                    "status": r[1],
                    "created_at": r[2].strftime("%Y-%m-%d %H:%M") if r[2] else "N/A",
                    "rider": r[3],
                    "driver": r[4],
                }
                for r in trips_rows
            ]

            # Fetch all blogs/ads
            cur.execute("SELECT id, title, category, content, image_url, created_at FROM blogs ORDER BY created_at DESC")
            blogs_rows = cur.fetchall()
            blogs_list = [
                {
                    "id": str(r[0]),
                    "title": r[1],
                    "category": r[2],
                    "content": r[3],
                    "image_url": r[4] or "",
                    "created_at": r[5].strftime("%Y-%m-%d %H:%M") if r[5] else "N/A",
                }
                for r in blogs_rows
            ]

    stats = {
        "total_users": total_users,
        "total_riders": total_riders,
        "total_drivers": total_drivers,
        "total_trips": total_trips,
    }

    return render_template("admin_dashboard.html", stats=stats, users=users_list, trips=trips_list, blogs=blogs_list)


@admin_bp.route("/users/<user_id>/toggle-status", methods=["POST"])
@require_admin
def toggle_user_status(user_id):
    """Suspend or Reactivate a user account."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status, role FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            if not row:
                return redirect(url_for("admin.dashboard"))
            
            curr_status, role = row[0], row[1]
            new_status = "suspended" if curr_status == "active" else "active"

            cur.execute("UPDATE users SET status = %s WHERE id = %s", (new_status, user_id))
            
            # If suspended, revoke all active sessions
            if new_status == "suspended":
                cur.execute("UPDATE sessions SET revoked = TRUE WHERE user_id = %s", (user_id,))

        conn.commit()

    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/blogs/create", methods=["POST"])
@require_admin
def create_blog():
    """Create a new Blog or Advertisement."""
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "PROMO").strip().upper()
    content = request.form.get("content", "").strip()
    image_url = request.form.get("image_url", "").strip()

    if not image_url:
        image_url = "https://images.unsplash.com/photo-1544620347-c4fd4a3d5957?auto=format&fit=crop&w=600&q=80"

    if title and content:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO blogs (title, category, content, image_url) VALUES (%s, %s, %s, %s)",
                    (title, category, content, image_url),
                )
            conn.commit()

    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/blogs/<blog_id>/edit", methods=["POST"])
@require_admin
def edit_blog(blog_id):
    """Update an existing Blog or Advertisement."""
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "PROMO").strip().upper()
    content = request.form.get("content", "").strip()
    image_url = request.form.get("image_url", "").strip()

    if title and content:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE blogs SET title = %s, category = %s, content = %s, image_url = %s WHERE id = %s",
                    (title, category, content, image_url, blog_id),
                )
            conn.commit()

    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/blogs/<blog_id>/delete", methods=["POST"])
@require_admin
def delete_blog(blog_id):
    """Delete a Blog or Advertisement."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM blogs WHERE id = %s", (blog_id,))
        conn.commit()

    return redirect(url_for("admin.dashboard"))

