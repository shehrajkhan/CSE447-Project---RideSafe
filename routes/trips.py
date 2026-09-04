"""
routes/trips.py - Ride requests, driver acceptance, and ride lifecycle management encrypted with ECC.
"""

from flask import Blueprint, request, render_template, redirect, url_for, g
import psycopg2.extras

import db
from crypto import ecc, rsa as rsa_crypto
from routes.sessions import require_login

trips_bp = Blueprint("trips", __name__, url_prefix="/trips")


def _get_ecc_keys(user_id):
    """Retrieve user's ECC public and private key."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ecc_public_key, ecc_private_key_encrypted FROM user_keys WHERE user_id = %s",
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        return None, None
    public_key = row[0]
    private_key = row[1]["raw"]
    return public_key, private_key


def _get_rsa_private_key(user_id):
    """Retrieve user's RSA private key."""
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT rsa_private_key_encrypted FROM user_keys WHERE user_id = %s",
                (user_id,),
            )
            row = cur.fetchone()
    if row and isinstance(row[0], dict) and "raw" in row[0]:
        return row[0]["raw"]
    return None


def _get_decrypted_user_profile(user_id):
    """Fetch and RSA-decrypt user profile details (Name, Phone, Vehicle Info)."""
    priv_key = _get_rsa_private_key(user_id)
    if not priv_key:
        return {"name": "User", "phone": "N/A", "vehicle_info": "N/A"}

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.name_encrypted, p.phone_encrypted, p.vehicle_info_encrypted, u.contact_encrypted, u.username
                FROM users u
                LEFT JOIN profiles p ON u.id = p.user_id
                WHERE u.id = %s
                """,
                (user_id,),
            )
            row = cur.fetchone()

    if not row:
        return {"name": "User", "phone": "N/A", "vehicle_info": "N/A"}

    name_enc, phone_enc, veh_enc, contact_enc, username = row[0], row[1], row[2], row[3], row[4]

    name = username
    if name_enc:
        try:
            name = rsa_crypto.decrypt(name_enc, priv_key).decode("utf-8", errors="replace")
        except Exception:
            pass

    phone = "N/A"
    if phone_enc:
        try:
            phone = rsa_crypto.decrypt(phone_enc, priv_key).decode("utf-8", errors="replace")
        except Exception:
            pass
    elif contact_enc:
        try:
            phone = rsa_crypto.decrypt(contact_enc, priv_key).decode("utf-8", errors="replace")
        except Exception:
            pass

    vehicle_info = "N/A"
    if veh_enc:
        try:
            vehicle_info = rsa_crypto.decrypt(veh_enc, priv_key).decode("utf-8", errors="replace")
        except Exception:
            pass

    return {
        "name": name,
        "phone": phone,
        "vehicle_info": vehicle_info
    }


@trips_bp.route("/dashboard", methods=["GET"])
@require_login
def dashboard():
    public_key, private_key = _get_ecc_keys(g.user_id)
    trips = []

    sos_triggered_id = request.args.get("sos_alert")

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            if g.user_role == "driver":
                # Driver view: Unassigned requests OR trips assigned to this driver
                cur.execute(
                    """
                    SELECT id, rider_id, driver_id, pickup_encrypted, dropoff_encrypted, 
                           timing_encrypted, status, created_at
                    FROM trips 
                    WHERE status = 'requested' OR driver_id = %s
                    ORDER BY created_at DESC
                    """,
                    (g.user_id,),
                )
                rows = cur.fetchall()

                for trip_id, rider_id, driver_id, pickup_enc, dropoff_enc, timing_enc, status, created_at in rows:
                    rider_details = None
                    if driver_id == g.user_id:
                        # Decrypt trip using the associated rider's key
                        _, rider_privkey = _get_ecc_keys(rider_id)
                        try:
                            pickup = ecc.decrypt(pickup_enc, rider_privkey).decode("utf-8", errors="replace")
                            dropoff = ecc.decrypt(dropoff_enc, rider_privkey).decode("utf-8", errors="replace")
                            timing = ecc.decrypt(timing_enc, rider_privkey).decode("utf-8", errors="replace")
                        except Exception:
                            pickup, dropoff, timing = "[Decryption Error]", "[Decryption Error]", "N/A"

                        # Decrypt rider personal details for assigned driver
                        rider_details = _get_decrypted_user_profile(rider_id)
                    else:
                        # Placeholder state for unassigned requests before acceptance
                        pickup, dropoff, timing = "Encrypted Ride Request", "Destination Hidden", "ASAP"

                    trips.append({
                        "id": trip_id, "rider_id": rider_id, "driver_id": driver_id,
                        "pickup": pickup, "dropoff": dropoff, "timing": timing,
                        "status": status, "created_at": created_at,
                        "rider_details": rider_details
                    })

            else:
                # Rider view: Trips requested by this rider (decrypt using rider's own key)
                cur.execute(
                    """
                    SELECT id, driver_id, pickup_encrypted, dropoff_encrypted, timing_encrypted, status, created_at
                    FROM trips 
                    WHERE rider_id = %s 
                    ORDER BY created_at DESC
                    """,
                    (g.user_id,),
                )
                rows = cur.fetchall()

                for trip_id, driver_id, pickup_enc, dropoff_enc, timing_enc, status, created_at in rows:
                    try:
                        pickup = ecc.decrypt(pickup_enc, private_key).decode("utf-8", errors="replace")
                        dropoff = ecc.decrypt(dropoff_enc, private_key).decode("utf-8", errors="replace")
                        timing = ecc.decrypt(timing_enc, private_key).decode("utf-8", errors="replace")
                    except Exception:
                        pickup, dropoff, timing = "[Decryption Error]", "[Decryption Error]", "N/A"

                    driver_details = None
                    if driver_id:
                        driver_details = _get_decrypted_user_profile(driver_id)

                    trips.append({
                        "id": trip_id, "driver_id": driver_id, "pickup": pickup, "dropoff": dropoff,
                        "timing": timing, "status": status, "created_at": created_at,
                        "driver_details": driver_details
                    })

            # Fetch blogs and promotions
            cur.execute("SELECT id, title, category, content, image_url, created_at FROM blogs ORDER BY created_at DESC")
            blog_rows = cur.fetchall()
            blogs = [
                {
                    "id": str(r[0]),
                    "title": r[1],
                    "category": r[2],
                    "content": r[3],
                    "image_url": r[4] or "https://images.unsplash.com/photo-1544620347-c4fd4a3d5957?auto=format&fit=crop&w=600&q=80",
                    "created_at": r[5].strftime("%b %d, %Y") if r[5] else ""
                }
                for r in blog_rows
            ]

    return render_template("dashboard.html", trips=trips, blogs=blogs, user_role=g.user_role, sos_triggered_id=sos_triggered_id)




@trips_bp.route("/request", methods=["GET", "POST"])
@require_login
def request_ride():
    if g.user_role != "rider":
        return redirect(url_for("trips.dashboard"))
    
    saved_locations = [
        "Gulshan",
        "Banani",
        "Dhanmondi",
        "Mirpur",
        "Hazrat Shahjalal International Airport",
        "Kamalapur Railway Station",
        "Mohakhali Bus Terminal"
        "Sayedabad Bus Terminal",
        "Gabtoli Bus Terminal",
        "Agargaon Metro Rail Station",
        "Uttara North Metro Station",
        "Dhaka University - TSC",
        "BUET - Plassy Gate",
        "NSU / IUB - Bashundhara R/A",
        "BRAC University - Merul Badda",
        "AIUB - Kuratoli",
        "Daffodil International University - Dhanmondi",
        "Jamuna Future Park - Kuril",
        "Bashundhara City Shopping Complex - Panthapath",
        "Shimanto Square - Dhanmondi",
        "New Market - Azimpur",
        "Police Plaza Concord - Gulshan 1",
        "Chef's Table Courtside - Madani Avenue",
        "Square Hospital - Panthapath",
        "Evercare Hospital - Bashundhara",
        "United Hospital - Gulshan 2",
        "Labaid Hospital - Dhanmondi",
        "BSMMU (PGB Hospital) - Shahbagh",
        "Hatirjheel - Rampura Bridge",
        "Dhanmondi Lake - Rabindra Sarobar",
        "Ramna Park - Shahbagh",
        "Old Dhaka - Ahsan Manzil",
        "Old Dhaka - Star Mosque"
        "Motijheel C/A",
        "Kawran Bazar",
        "Gulshan Avenue",
        "Tejgaon Industrial Area",
        "Agargaon Passport Office / Admin Zone",
    ]

    if request.method == "GET":
        return render_template("request_ride.html", saved_locations=saved_locations)

    pickup = request.form["pickup"].strip()
    dropoff = request.form["dropoff"].strip()
    timing = request.form.get("timing", "Now").strip()

    public_key, _ = _get_ecc_keys(g.user_id)

    # Encrypt trip data for rider using ECC
    pickup_enc = ecc.encrypt(pickup.encode(), public_key)
    dropoff_enc = ecc.encrypt(dropoff.encode(), public_key)
    timing_enc = ecc.encrypt(timing.encode(), public_key)

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO trips (rider_id, pickup_encrypted, dropoff_encrypted, timing_encrypted, status)
                VALUES (%s, %s, %s, %s, 'requested')
                """,
                (
                    g.user_id, 
                    psycopg2.extras.Json(pickup_enc),
                    psycopg2.extras.Json(dropoff_enc), 
                    psycopg2.extras.Json(timing_enc),
                ),
            )
        conn.commit()

    return redirect(url_for("trips.dashboard"))


@trips_bp.route("/<uuid:trip_id>/accept", methods=["POST"])
@require_login
def accept_ride(trip_id):
    if g.user_role != "driver":
        return redirect(url_for("trips.dashboard"))

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            # Assign driver and transition status without modifying encrypted rider fields
            cur.execute(
                """
                UPDATE trips 
                SET driver_id = %s, status = 'accepted'
                WHERE id = %s AND status = 'requested'
                """,
                (g.user_id, str(trip_id))
            )
        conn.commit()

    return redirect(url_for("trips.dashboard"))


@trips_bp.route("/<uuid:trip_id>/status", methods=["POST"])
@require_login
def update_status(trip_id):
    if g.user_role != "driver":
        return redirect(url_for("trips.dashboard"))

    new_status = request.form.get("status")
    allowed_transitions = {
        "accepted": "arrived",
        "arrived": "in_progress",
        "in_progress": "completed"
    }

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status FROM trips WHERE id = %s AND driver_id = %s", (str(trip_id), g.user_id))
            row = cur.fetchone()
            
            if row and allowed_transitions.get(row[0]) == new_status:
                cur.execute(
                    "UPDATE trips SET status = %s WHERE id = %s AND driver_id = %s",
                    (new_status, str(trip_id), g.user_id)
                )
        conn.commit()

    return redirect(url_for("trips.dashboard"))


@trips_bp.route("/<uuid:trip_id>/sos", methods=["POST"])
@require_login
def trigger_sos(trip_id):
    if g.user_role != "rider":
        return redirect(url_for("trips.dashboard"))

    return redirect(url_for("trips.dashboard", sos_alert=str(trip_id)))
