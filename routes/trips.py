"""
routes/trips.py

Ride requests, driver acceptance, and ride lifecycle management.

Encrypted trip fields are protected with Teammate C's
hand-built HMAC-SHA256 implementation.
"""

import json

from flask import (
    Blueprint,
    request,
    render_template,
    redirect,
    url_for,
    g,
)

import psycopg2.extras

import db

from crypto import ecc, rsa as rsa_crypto
from crypto import mac

from routes.sessions import require_login


trips_bp = Blueprint(
    "trips",
    __name__,
    url_prefix="/trips"
)


# ============================================================
# MAC Configuration
# ============================================================

def _get_mac_key():
    """
    Retrieve the server-side HMAC integrity key.

    The key comes from RIDESAFE_MAC_KEY through config.py.
    It is never stored in the database.
    """

    from config import Config

    key = Config.MAC_KEY

    if not key:
        raise RuntimeError(
            "RIDESAFE_MAC_KEY is not configured"
        )

    return key


# ============================================================
# Canonical Payload Serialization
# ============================================================

def _canonical_payload(payload: dict) -> bytes:
    """
    Convert an encrypted ECC payload into deterministic bytes.

    The MAC field itself is excluded because the MAC is calculated
    over the remaining protected fields.

    sort_keys=True ensures the same dictionary always produces
    the same byte representation.
    """

    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")

    data = {
        key: value
        for key, value in payload.items()
        if key != "mac"
    }

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


# ============================================================
# Attach MAC
# ============================================================

def _attach_mac(payload: dict) -> dict:
    """
    Add an HMAC-SHA256 tag to an encrypted ECC payload.
    """

    protected_data = _canonical_payload(payload)

    tag = mac.compute_mac(
        protected_data,
        _get_mac_key()
    )

    protected_payload = dict(payload)
    protected_payload["mac"] = tag

    return protected_payload


# ============================================================
# Verify MAC
# ============================================================

def _verify_payload_mac(payload: dict) -> bool:
    """
    Verify the integrity of an encrypted ECC payload.

    Returns False if:
        - payload is malformed
        - MAC is missing
        - ciphertext was modified
        - ephemeral public key was modified
        - encryption scheme was modified
        - MAC was modified
    """

    if not isinstance(payload, dict):
        return False

    supplied_tag = payload.get("mac")

    if not isinstance(supplied_tag, str):
        return False

    try:
        protected_data = _canonical_payload(payload)

        return mac.verify_mac(
            protected_data,
            supplied_tag,
            _get_mac_key()
        )

    except (
        TypeError,
        ValueError,
        KeyError,
        RuntimeError,
    ):
        return False


# ============================================================
# ECC Key Retrieval
# ============================================================

def _get_ecc_keys(user_id):
    """
    Retrieve user's ECC public and private key.
    """

    with db.get_conn() as conn:
        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    ecc_public_key,
                    ecc_private_key_encrypted
                FROM user_keys
                WHERE user_id = %s
                """,
                (user_id,),
            )

            row = cur.fetchone()

    if not row:
        return None, None

    public_key = row[0]

    private_key = None

    if row[1]:
        private_key = row[1].get("raw")

    return (
        public_key,
        private_key
    )


# ============================================================
# RSA Key Retrieval / Profile Decryption
# ============================================================

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


# ============================================================
# Dashboard
# ============================================================

@trips_bp.route(
    "/dashboard",
    methods=["GET"]
)
@require_login
def dashboard():

    public_key, private_key = _get_ecc_keys(
        g.user_id
    )

    trips = []

    sos_triggered_id = request.args.get("sos_alert")

    with db.get_conn() as conn:
        with conn.cursor() as cur:

            # ====================================================
            # DRIVER DASHBOARD
            # ====================================================

            if g.user_role == "driver":

                cur.execute(
                    """
                    SELECT
                        id,
                        rider_id,
                        driver_id,
                        pickup_encrypted,
                        dropoff_encrypted,
                        timing_encrypted,
                        status,
                        created_at
                    FROM trips
                    WHERE
                        status = 'requested'
                        OR driver_id = %s
                    ORDER BY created_at DESC
                    """,
                    (g.user_id,),
                )

                rows = cur.fetchall()

                for (
                    trip_id,
                    rider_id,
                    driver_id,
                    pickup_enc,
                    dropoff_enc,
                    timing_enc,
                    status,
                    created_at,
                ) in rows:

                    rider_details = None

                    if driver_id == g.user_id:

                        # Driver has been assigned to this ride.

                        _, rider_privkey = _get_ecc_keys(
                            rider_id
                        )

                        # ------------------------------------------------
                        # IMPORTANT:
                        # Verify HMAC BEFORE decryption.
                        # ------------------------------------------------

                        pickup_valid = _verify_payload_mac(
                            pickup_enc
                        )

                        dropoff_valid = _verify_payload_mac(
                            dropoff_enc
                        )

                        timing_valid = _verify_payload_mac(
                            timing_enc
                        )

                        # ------------------------------------------------
                        # Reject tampered data.
                        # ------------------------------------------------

                        if not (
                            pickup_valid
                            and dropoff_valid
                            and timing_valid
                        ):

                            pickup = "[TAMPERED DATA REJECTED]"
                            dropoff = "[TAMPERED DATA REJECTED]"
                            timing = "[TAMPERED DATA REJECTED]"

                        else:

                            try:

                                pickup = ecc.decrypt(
                                    pickup_enc,
                                    rider_privkey
                                ).decode(
                                    "utf-8",
                                    errors="replace"
                                )

                                dropoff = ecc.decrypt(
                                    dropoff_enc,
                                    rider_privkey
                                ).decode(
                                    "utf-8",
                                    errors="replace"
                                )

                                timing = ecc.decrypt(
                                    timing_enc,
                                    rider_privkey
                                ).decode(
                                    "utf-8",
                                    errors="replace"
                                )

                            except Exception:

                                pickup = "[Decryption Error]"
                                dropoff = "[Decryption Error]"
                                timing = "[Decryption Error]"

                        # Decrypt rider personal details for assigned driver
                        rider_details = _get_decrypted_user_profile(rider_id)

                    else:

                        # Requested rides that are not yet assigned
                        # should not reveal encrypted trip details.

                        pickup = "Encrypted Ride Request"
                        dropoff = "Destination Hidden"
                        timing = "ASAP"

                    trips.append(
                        {
                            "id": trip_id,
                            "rider_id": rider_id,
                            "driver_id": driver_id,
                            "pickup": pickup,
                            "dropoff": dropoff,
                            "timing": timing,
                            "status": status,
                            "created_at": created_at,
                            "rider_details": rider_details,
                        }
                    )

            # ====================================================
            # RIDER DASHBOARD
            # ====================================================

            else:

                cur.execute(
                    """
                    SELECT
                        id,
                        driver_id,
                        pickup_encrypted,
                        dropoff_encrypted,
                        timing_encrypted,
                        status,
                        created_at
                    FROM trips
                    WHERE rider_id = %s
                    ORDER BY created_at DESC
                    """,
                    (g.user_id,),
                )

                rows = cur.fetchall()

                for (
                    trip_id,
                    driver_id,
                    pickup_enc,
                    dropoff_enc,
                    timing_enc,
                    status,
                    created_at,
                ) in rows:

                    # ------------------------------------------------
                    # Verify HMAC BEFORE decryption.
                    # ------------------------------------------------

                    pickup_valid = _verify_payload_mac(
                        pickup_enc
                    )

                    dropoff_valid = _verify_payload_mac(
                        dropoff_enc
                    )

                    timing_valid = _verify_payload_mac(
                        timing_enc
                    )

                    # ------------------------------------------------
                    # Reject tampered data.
                    # ------------------------------------------------

                    if not (
                        pickup_valid
                        and dropoff_valid
                        and timing_valid
                    ):

                        pickup = "[TAMPERED DATA REJECTED]"
                        dropoff = "[TAMPERED DATA REJECTED]"
                        timing = "[TAMPERED DATA REJECTED]"

                    else:

                        try:

                            pickup = ecc.decrypt(
                                pickup_enc,
                                private_key
                            ).decode(
                                "utf-8",
                                errors="replace"
                            )

                            dropoff = ecc.decrypt(
                                dropoff_enc,
                                private_key
                            ).decode(
                                "utf-8",
                                errors="replace"
                            )

                            timing = ecc.decrypt(
                                timing_enc,
                                private_key
                            ).decode(
                                "utf-8",
                                errors="replace"
                            )

                        except Exception:

                            pickup = "[Decryption Error]"
                            dropoff = "[Decryption Error]"
                            timing = "[Decryption Error]"

                    driver_details = None
                    if driver_id:
                        driver_details = _get_decrypted_user_profile(driver_id)

                    trips.append(
                        {
                            "id": trip_id,
                            "driver_id": driver_id,
                            "pickup": pickup,
                            "dropoff": dropoff,
                            "timing": timing,
                            "status": status,
                            "created_at": created_at,
                            "driver_details": driver_details,
                        }
                    )

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

            active_trips = [t for t in trips if t["status"] in ("requested", "accepted", "arrived", "in_progress")]

    return render_template(
        "dashboard.html",
        trips=active_trips,
        blogs=blogs,
        user_role=g.user_role,
        sos_triggered_id=sos_triggered_id,
    )


# ============================================================
# Trip History Page
# ============================================================

@trips_bp.route(
    "/history",
    methods=["GET"]
)
@require_login
def history():
    """Display past completed or cancelled trips for the logged-in user."""
    public_key, private_key = _get_ecc_keys(g.user_id)
    trips = []

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            if g.user_role == "driver":
                cur.execute(
                    """
                    SELECT id, rider_id, driver_id, pickup_encrypted, dropoff_encrypted, timing_encrypted, status, created_at
                    FROM trips
                    WHERE driver_id = %s AND status IN ('completed', 'cancelled')
                    ORDER BY created_at DESC
                    """,
                    (g.user_id,),
                )
                rows = cur.fetchall()

                for trip_id, rider_id, driver_id, pickup_enc, dropoff_enc, timing_enc, status, created_at in rows:
                    rider_details = None
                    if driver_id == g.user_id:
                        _, rider_privkey = _get_ecc_keys(rider_id)
                        pickup_valid = _verify_payload_mac(pickup_enc)
                        dropoff_valid = _verify_payload_mac(dropoff_enc)
                        timing_valid = _verify_payload_mac(timing_enc)

                        if not (pickup_valid and dropoff_valid and timing_valid):
                            pickup = "[TAMPERED DATA REJECTED]"
                            dropoff = "[TAMPERED DATA REJECTED]"
                            timing = "[TAMPERED DATA REJECTED]"
                        else:
                            try:
                                pickup = ecc.decrypt(pickup_enc, rider_privkey).decode("utf-8", errors="replace")
                                dropoff = ecc.decrypt(dropoff_enc, rider_privkey).decode("utf-8", errors="replace")
                                timing = ecc.decrypt(timing_enc, rider_privkey).decode("utf-8", errors="replace")
                            except Exception:
                                pickup = "[Decryption Error]"
                                dropoff = "[Decryption Error]"
                                timing = "[Decryption Error]"

                        rider_details = _get_decrypted_user_profile(rider_id)
                        rider_details["pickup"] = pickup
                        rider_details["dropoff"] = dropoff
                    else:
                        pickup = "Location Protected"
                        dropoff = "Destination Hidden"
                        timing = "Immediate"

                    driver_details = None
                    if driver_id:
                        driver_details = _get_decrypted_user_profile(driver_id)

                    trips.append({
                        "id": trip_id,
                        "rider_id": rider_id,
                        "driver_id": driver_id,
                        "pickup": pickup,
                        "dropoff": dropoff,
                        "timing": timing,
                        "status": status,
                        "created_at": created_at,
                        "rider_details": rider_details,
                        "driver_details": driver_details,
                    })

            else:  # Rider
                cur.execute(
                    """
                    SELECT id, driver_id, pickup_encrypted, dropoff_encrypted, timing_encrypted, status, created_at
                    FROM trips
                    WHERE rider_id = %s AND status IN ('completed', 'cancelled')
                    ORDER BY created_at DESC
                    """,
                    (g.user_id,),
                )
                rows = cur.fetchall()

                for trip_id, driver_id, pickup_enc, dropoff_enc, timing_enc, status, created_at in rows:
                    pickup_valid = _verify_payload_mac(pickup_enc)
                    dropoff_valid = _verify_payload_mac(dropoff_enc)
                    timing_valid = _verify_payload_mac(timing_enc)

                    if not (pickup_valid and dropoff_valid and timing_valid):
                        pickup = "[TAMPERED DATA REJECTED]"
                        dropoff = "[TAMPERED DATA REJECTED]"
                        timing = "[TAMPERED DATA REJECTED]"
                    else:
                        try:
                            pickup = ecc.decrypt(pickup_enc, private_key).decode("utf-8", errors="replace")
                            dropoff = ecc.decrypt(dropoff_enc, private_key).decode("utf-8", errors="replace")
                            timing = ecc.decrypt(timing_enc, private_key).decode("utf-8", errors="replace")
                        except Exception:
                            pickup = "[Decryption Error]"
                            dropoff = "[Decryption Error]"
                            timing = "[Decryption Error]"

                    driver_details = None
                    if driver_id:
                        driver_details = _get_decrypted_user_profile(driver_id)

                    trips.append({
                        "id": trip_id,
                        "driver_id": driver_id,
                        "pickup": pickup,
                        "dropoff": dropoff,
                        "timing": timing,
                        "status": status,
                        "created_at": created_at,
                        "driver_details": driver_details,
                    })

    return render_template(
        "history.html",
        trips=trips,
        user_role=g.user_role,
    )


# ============================================================
# Request Ride
# ============================================================

@trips_bp.route(
    "/request",
    methods=["GET", "POST"]
)
@require_login
def request_ride():

    if g.user_role != "rider":
        return redirect(
            url_for("trips.dashboard")
        )

    saved_locations = [
        "Gulshan",
        "Banani",
        "Dhanmondi",
        "Mirpur",
        "Hazrat Shahjalal International Airport",
        "Kamalapur Railway Station",
        "Mohakhali Bus Terminal",
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
        "Old Dhaka - Star Mosque",
        "Motijheel C/A",
        "Kawran Bazar",
        "Gulshan Avenue",
        "Tejgaon Industrial Area",
        "Agargaon Passport Office / Admin Zone",
    ]

    if request.method == "GET":

        return render_template(
            "request_ride.html",
            saved_locations=saved_locations,
        )

    # ========================================================
    # Read form data
    # ========================================================

    pickup = request.form[
        "pickup"
    ].strip()

    dropoff = request.form[
        "dropoff"
    ].strip()

    timing = request.form.get(
        "timing",
        "Now"
    ).strip()

    # ========================================================
    # Get rider ECC public key
    # ========================================================

    public_key, _ = _get_ecc_keys(
        g.user_id
    )

    if not public_key:
        return "ECC public key not found", 500

    # ========================================================
    # ECC ENCRYPTION
    # ========================================================

    pickup_enc = ecc.encrypt(
        pickup.encode(),
        public_key
    )

    dropoff_enc = ecc.encrypt(
        dropoff.encode(),
        public_key
    )

    timing_enc = ecc.encrypt(
        timing.encode(),
        public_key
    )

    # ========================================================
    # HMAC INTEGRITY PROTECTION
    # ========================================================

    # MAC is calculated AFTER encryption.
    #
    # Therefore the HMAC protects:
    #   - encryption scheme
    #   - ciphertext
    #   - ephemeral public key
    #
    # This allows us to detect modification of the
    # complete encrypted payload.

    pickup_enc = _attach_mac(
        pickup_enc
    )

    dropoff_enc = _attach_mac(
        dropoff_enc
    )

    timing_enc = _attach_mac(
        timing_enc
    )

    # ========================================================
    # STORE ENCRYPTED + MAC-PROTECTED DATA
    # ========================================================

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                INSERT INTO trips (
                    rider_id,
                    pickup_encrypted,
                    dropoff_encrypted,
                    timing_encrypted,
                    status
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    'requested'
                )
                """,
                (
                    g.user_id,

                    psycopg2.extras.Json(
                        pickup_enc
                    ),

                    psycopg2.extras.Json(
                        dropoff_enc
                    ),

                    psycopg2.extras.Json(
                        timing_enc
                    ),
                ),
            )

        conn.commit()

    return redirect(
        url_for("trips.dashboard")
    )


# ============================================================
# Accept Ride
# ============================================================

@trips_bp.route(
    "/<uuid:trip_id>/accept",
    methods=["POST"]
)
@require_login
def accept_ride(trip_id):

    if g.user_role != "driver":
        return redirect(
            url_for("trips.dashboard")
        )

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                UPDATE trips
                SET
                    driver_id = %s,
                    status = 'accepted'
                WHERE
                    id = %s
                    AND status = 'requested'
                """,
                (
                    g.user_id,
                    str(trip_id)
                )
            )

        conn.commit()

    return redirect(
        url_for("trips.dashboard")
    )


# ============================================================
# Update Trip Status
# ============================================================

@trips_bp.route(
    "/<uuid:trip_id>/status",
    methods=["POST"]
)
@require_login
def update_status(trip_id):

    if g.user_role != "driver":
        return redirect(
            url_for("trips.dashboard")
        )

    new_status = request.form.get(
        "status"
    )

    allowed_transitions = {
        "accepted": "arrived",
        "arrived": "in_progress",
        "in_progress": "completed",
    }

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT status
                FROM trips
                WHERE
                    id = %s
                    AND driver_id = %s
                """,
                (
                    str(trip_id),
                    g.user_id,
                )
            )

            row = cur.fetchone()

            if (
                row
                and allowed_transitions.get(row[0])
                == new_status
            ):

                cur.execute(
                    """
                    UPDATE trips
                    SET status = %s
                    WHERE
                        id = %s
                        AND driver_id = %s
                    """,
                    (
                        new_status,
                        str(trip_id),
                        g.user_id,
                    )
                )

        conn.commit()

    return redirect(
        url_for("trips.dashboard")
    )


# ============================================================
# Trigger SOS
# ============================================================

@trips_bp.route("/<uuid:trip_id>/sos", methods=["POST"])
@require_login
def trigger_sos(trip_id):
    if g.user_role != "rider":
        return redirect(url_for("trips.dashboard"))

    db.ensure_emergencies_table()

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT rider_id, driver_id FROM trips WHERE id = %s",
                (str(trip_id),),
            )
            row = cur.fetchone()
            if row:
                rider_id, driver_id = row[0], row[1]
                driver_name = "Unassigned"
                driver_phone = "N/A"
                driver_vehicle = "N/A"

                if driver_id:
                    d_info = _get_decrypted_user_profile(str(driver_id))
                    driver_name = d_info.get("name") or "Driver"
                    driver_phone = d_info.get("phone") or "N/A"
                    driver_vehicle = d_info.get("vehicle_info") or "N/A"

                cur.execute(
                    """
                    INSERT INTO emergencies (trip_id, rider_id, driver_id, driver_name, driver_phone, driver_vehicle, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 'active')
                    """,
                    (str(trip_id), str(rider_id), str(driver_id) if driver_id else None, driver_name, driver_phone, driver_vehicle),
                )
        conn.commit()

    return redirect(url_for("trips.dashboard", sos_alert=str(trip_id)))


# ============================================================
# Edit Drop-Off Location (Rider Only)
# ============================================================

@trips_bp.route("/<uuid:trip_id>/edit-dropoff", methods=["POST"])
@require_login
def edit_dropoff(trip_id):
    if g.user_role != "rider":
        return redirect(url_for("trips.dashboard"))

    new_dropoff = request.form.get("dropoff", "").strip()
    if not new_dropoff:
        return redirect(url_for("trips.dashboard"))

    # Verify rider ownership and trip status
    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT rider_id, status FROM trips WHERE id = %s",
                (str(trip_id),),
            )
            row = cur.fetchone()
            if not row or str(row[0]) != str(g.user_id) or row[1] not in ('requested', 'accepted', 'arrived', 'in_progress'):
                return redirect(url_for("trips.dashboard"))

    public_key, _ = _get_ecc_keys(g.user_id)
    if not public_key:
        return "ECC public key not found", 500

    dropoff_enc = ecc.encrypt(new_dropoff.encode(), public_key)
    dropoff_enc = _attach_mac(dropoff_enc)

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE trips
                SET dropoff_encrypted = %s
                WHERE id = %s AND rider_id = %s
                """,
                (json.dumps(dropoff_enc), str(trip_id), str(g.user_id)),
            )
        conn.commit()

    return redirect(url_for("trips.dashboard"))
