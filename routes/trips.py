"""
routes/trips.py - Ride requests, driver acceptance, and ride lifecycle management encrypted with ECC.
"""

from flask import Blueprint, request, render_template, redirect, url_for, g
import psycopg2.extras

import db
from crypto import ecc
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


@trips_bp.route("/dashboard", methods=["GET"])
@require_login
def dashboard():
    public_key, private_key = _get_ecc_keys(g.user_id)
    trips = []

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
                    if driver_id == g.user_id:
                        # Decrypt trip using the associated rider's key
                        _, rider_privkey = _get_ecc_keys(rider_id)
                        try:
                            pickup = ecc.decrypt(pickup_enc, rider_privkey).decode("utf-8", errors="replace")
                            dropoff = ecc.decrypt(dropoff_enc, rider_privkey).decode("utf-8", errors="replace")
                            timing = ecc.decrypt(timing_enc, rider_privkey).decode("utf-8", errors="replace")
                        except Exception:
                            pickup, dropoff, timing = "[Decryption Error]", "[Decryption Error]", "N/A"
                    else:
                        # Placeholder state for unassigned requests before acceptance
                        pickup, dropoff, timing = "Encrypted Ride Request", "Destination Hidden", "ASAP"

                    trips.append({
                        "id": trip_id, "rider_id": rider_id, "driver_id": driver_id,
                        "pickup": pickup, "dropoff": dropoff, "timing": timing,
                        "status": status, "created_at": created_at
                    })

            else:
                # Rider view: Trips requested by this rider (decrypt using rider's own key)
                cur.execute(
                    """
                    SELECT id, pickup_encrypted, dropoff_encrypted, timing_encrypted, status, created_at
                    FROM trips 
                    WHERE rider_id = %s 
                    ORDER BY created_at DESC
                    """,
                    (g.user_id,),
                )
                rows = cur.fetchall()

                for trip_id, pickup_enc, dropoff_enc, timing_enc, status, created_at in rows:
                    try:
                        pickup = ecc.decrypt(pickup_enc, private_key).decode("utf-8", errors="replace")
                        dropoff = ecc.decrypt(dropoff_enc, private_key).decode("utf-8", errors="replace")
                        timing = ecc.decrypt(timing_enc, private_key).decode("utf-8", errors="replace")
                    except Exception:
                        pickup, dropoff, timing = "[Decryption Error]", "[Decryption Error]", "N/A"

                    trips.append({
                        "id": trip_id, "pickup": pickup, "dropoff": dropoff,
                        "timing": timing, "status": status, "created_at": created_at
                    })

    return render_template("dashboard.html", trips=trips, user_role=g.user_role)


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