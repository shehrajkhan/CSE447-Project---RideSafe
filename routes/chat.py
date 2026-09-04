"""
routes/chat.py

End-to-end encrypted trip messaging using ECC.

Every encrypted chat payload is protected by Teammate C's
hand-built HMAC-SHA256 integrity mechanism.
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


chat_bp = Blueprint(
    "chat",
    __name__,
    url_prefix="/chat"
)


# ============================================================
# MAC Configuration
# ============================================================

def _get_mac_key():
    """
    Get the server-side HMAC key from config.py.

    The key comes from the RIDESAFE_MAC_KEY environment variable.
    It must never be stored in the database.
    """

    from config import Config

    key = Config.MAC_KEY

    if not key:
        raise RuntimeError(
            "RIDESAFE_MAC_KEY is not configured"
        )

    return key


# ============================================================
# Canonical Payload
# ============================================================

def _canonical_payload(payload: dict) -> bytes:
    """
    Convert an encrypted ECC payload into deterministic bytes.

    The MAC field is excluded because the MAC is calculated over
    all the other protected fields.

    sort_keys=True guarantees deterministic serialization.
    """

    if not isinstance(payload, dict):
        raise TypeError(
            "payload must be a dictionary"
        )

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
    Calculate HMAC-SHA256 over the encrypted payload and attach
    the resulting MAC tag.
    """

    protected_data = _canonical_payload(
        payload
    )

    tag = mac.compute_mac(
        protected_data,
        _get_mac_key()
    )

    result = dict(payload)

    result["mac"] = tag

    return result


# ============================================================
# Verify MAC
# ============================================================

def _verify_payload_mac(payload: dict) -> bool:
    """
    Verify the HMAC-SHA256 integrity tag.

    Returns False if:
        - payload is not a dictionary
        - MAC is missing
        - MAC is malformed
        - ciphertext was modified
        - ephemeral public key was modified
        - encryption scheme was modified
        - MAC itself was modified
        - integrity key is unavailable
    """

    if not isinstance(payload, dict):
        return False

    supplied_tag = payload.get(
        "mac"
    )

    if not isinstance(
        supplied_tag,
        str
    ):
        return False

    try:

        protected_data = _canonical_payload(
            payload
        )

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
# ECC Keys
# ============================================================

def _get_ecc_keys(user_id):
    """
    Retrieve the user's ECC public and private key.

    The existing project stores the private key inside
    ecc_private_key_encrypted["raw"].
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
                (user_id,)
            )

            row = cur.fetchone()

    if not row:
        return None, None

    public_key = row[0]

    private_key = None

    if row[1]:
        private_key = row[1].get(
            "raw"
        )

    return (
        public_key,
        private_key
    )


# ============================================================
# Chat Room
# ============================================================

@chat_bp.route(
    "/<uuid:trip_id>",
    methods=["GET", "POST"]
)
@require_login
def room(trip_id):

    trip_id_str = str(
        trip_id
    )

    user_id = g.user_id

    # ========================================================
    # Fetch Trip
    # ========================================================

    with db.get_conn() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                SELECT
                    rider_id,
                    driver_id
                FROM trips
                WHERE id = %s
                """,
                (trip_id_str,)
            )

            trip = cur.fetchone()

            if not trip:

                return redirect(
                    url_for(
                        "trips.dashboard"
                    )
                )

            rider_id, driver_id = trip

            # =================================================
            # Authorization
            # =================================================

            # Only the rider or assigned driver can access
            # the chat room.

            if (
                user_id != rider_id
                and user_id != driver_id
            ):

                return redirect(
                    url_for(
                        "trips.dashboard"
                    )
                )

            # =================================================
            # POST: Send Message
            # =================================================

            if request.method == "POST":

                message_text = request.form.get(
                    "message",
                    ""
                ).strip()

                if message_text:

                    # ------------------------------------------------
                    # Get rider public key
                    # ------------------------------------------------

                    rider_pubkey, _ = _get_ecc_keys(
                        rider_id
                    )

                    if not rider_pubkey:

                        return (
                            "Rider ECC public key not found",
                            500
                        )

                    # ------------------------------------------------
                    # ECC Encryption
                    # ------------------------------------------------

                    encrypted_msg = ecc.encrypt(
                        message_text.encode("utf-8"),
                        rider_pubkey
                    )

                    # ------------------------------------------------
                    # HMAC Integrity Protection
                    # ------------------------------------------------

                    # IMPORTANT:
                    #
                    # HMAC is calculated AFTER ECC encryption.
                    #
                    # Therefore the MAC protects the complete
                    # encrypted payload:
                    #
                    #   scheme
                    #   ciphertext
                    #   ephemeral_pubkey
                    #
                    # The MAC itself is stored as "mac".

                    encrypted_msg = _attach_mac(
                        encrypted_msg
                    )

                    # ------------------------------------------------
                    # Store Encrypted + MAC-Protected Message
                    # ------------------------------------------------

                    cur.execute(
                        """
                        INSERT INTO chat_messages (
                            trip_id,
                            sender_id,
                            message_encrypted
                        )
                        VALUES (
                            %s,
                            %s,
                            %s
                        )
                        """,
                        (
                            trip_id_str,
                            user_id,
                            psycopg2.extras.Json(
                                encrypted_msg
                            ),
                        ),
                    )

                    conn.commit()

                return redirect(
                    url_for(
                        "chat.room",
                        trip_id=trip_id_str
                    )
                )

            # =================================================
            # GET: Retrieve Chat History
            # =================================================

            cur.execute(
                """
                SELECT
                    id,
                    sender_id,
                    message_encrypted,
                    sent_at
                FROM chat_messages
                WHERE trip_id = %s
                ORDER BY sent_at ASC
                """,
                (trip_id_str,)
            )

            message_rows = cur.fetchall()

    # ========================================================
    # Obtain Rider Private Key
    # ========================================================

    _, rider_privkey = _get_ecc_keys(
        rider_id
    )

    formatted_messages = []

    # ========================================================
    # Verify MAC THEN Decrypt
    # ========================================================

    for (
        msg_id,
        sender_id,
        msg_enc,
        sent_at,
    ) in message_rows:

        # ----------------------------------------------------
        # STEP 1: Verify integrity
        # ----------------------------------------------------

        # NEVER decrypt the message before checking its MAC.

        mac_valid = _verify_payload_mac(
            msg_enc
        )

        # ----------------------------------------------------
        # STEP 2: Reject tampered message
        # ----------------------------------------------------

        if not mac_valid:

            text = (
                "[TAMPERED MESSAGE REJECTED]"
            )

        else:

            # ------------------------------------------------
            # STEP 3: Decrypt only after successful MAC check
            # ------------------------------------------------

            try:

                if not rider_privkey:

                    text = (
                        "[Private Key Not Found]"
                    )

                else:

                    decrypted_bytes = ecc.decrypt(
                        msg_enc,
                        rider_privkey
                    )

                    text = decrypted_bytes.decode(
                        "utf-8",
                        errors="replace"
                    )

            except Exception:

                text = (
                    "[Decryption Failed]"
                )

        # ----------------------------------------------------
        # Add formatted message
        # ----------------------------------------------------

        formatted_messages.append(
            {
                "id": msg_id,
                "sender_id": sender_id,
                "text": text,
                "is_me": (
                    sender_id == user_id
                ),
                "sent_at": sent_at,
            }
        )

    # ========================================================
    # Render Chat
    # ========================================================

    return render_template(
        "chat.html",
        trip={
            "id": trip_id_str
        },
        messages=formatted_messages,
    )