"""
routes/trips.py - Ride requests & trip logs, encrypted with real ECC.

This is the module that actually exercises the finished crypto/ecc.py -
pickup, drop-off, and timing are genuinely encrypted before storage and
decrypted only for the requesting user.
"""

from flask import Blueprint, request, render_template, redirect, url_for, g
import psycopg2.extras

import db
from crypto import ecc
from routes.sessions import require_login

trips_bp = Blueprint("trips", __name__, url_prefix="/trips")


def _get_ecc_keys(user_id):
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT ecc_public_key, ecc_private_key_encrypted FROM user_keys WHERE user_id = %s",
                (user_id,),
            )
            row = cur.fetchone()
    public_key = row[0]
    # NOTE: private key is stored unwrapped (flagged _todo) until the Key
    # Management Module wraps it with a password-derived key - so for now
    # we just read the raw value straight out.
    private_key = row[1]["raw"]
    return public_key, private_key


@trips_bp.route("/dashboard", methods=["GET"])
@require_login
def dashboard():
    public_key, private_key = _get_ecc_keys(g.user_id)

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, pickup_encrypted, dropoff_encrypted, timing_encrypted, status, created_at
                FROM trips WHERE rider_id = %s ORDER BY created_at DESC
                """,
                (g.user_id,),
            )
            rows = cur.fetchall()

    trips = []
    for trip_id, pickup_enc, dropoff_enc, timing_enc, status, created_at in rows:
        pickup = ecc.decrypt(pickup_enc, private_key).decode("utf-8", errors="replace")
        dropoff = ecc.decrypt(dropoff_enc, private_key).decode("utf-8", errors="replace")
        timing = ecc.decrypt(timing_enc, private_key).decode("utf-8", errors="replace")
        trips.append({
            "id": trip_id, "pickup": pickup, "dropoff": dropoff,
            "timing": timing, "status": status, "created_at": created_at,
        })

    return render_template("dashboard.html", trips=trips)


@trips_bp.route("/request", methods=["GET", "POST"])
@require_login
def request_ride():
    if request.method == "GET":
        return render_template("request_ride.html")

    pickup = request.form["pickup"].strip()
    dropoff = request.form["dropoff"].strip()
    timing = request.form["timing"].strip()

    public_key, _ = _get_ecc_keys(g.user_id)

    # Real ECC/ECIES encryption - a fresh ephemeral key is used each time
    pickup_enc = ecc.encrypt(pickup.encode(), public_key)
    dropoff_enc = ecc.encrypt(dropoff.encode(), public_key)
    timing_enc = ecc.encrypt(timing.encode(), public_key)

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO trips (rider_id, pickup_encrypted, dropoff_encrypted, timing_encrypted)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    g.user_id, psycopg2.extras.Json(pickup_enc),
                    psycopg2.extras.Json(dropoff_enc), psycopg2.extras.Json(timing_enc),
                ),
            )
        conn.commit()

    return redirect(url_for("trips.dashboard"))
