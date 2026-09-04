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

from crypto import ecc
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

                    # ------------------------------------------------
                    # Requested ride
                    # ------------------------------------------------

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

                    trips.append(
                        {
                            "id": trip_id,
                            "pickup": pickup,
                            "dropoff": dropoff,
                            "timing": timing,
                            "status": status,
                            "created_at": created_at,
                        }
                    )

    return render_template(
        "dashboard.html",
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