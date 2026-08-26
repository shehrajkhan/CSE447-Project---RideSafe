"""
routes/chat.py - End-to-end encrypted trip messaging module using ECC.
"""

from flask import Blueprint, request, render_template, redirect, url_for, g
import psycopg2.extras

import db
from crypto import ecc
from routes.sessions import require_login

chat_bp = Blueprint("chat", __name__, url_prefix="/chat")


def _get_ecc_keys(user_id):
    """Retrieve user's ECC public key and private key from storage."""
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


@chat_bp.route("/<uuid:trip_id>", methods=["GET", "POST"])
@require_login
def room(trip_id):
    trip_id_str = str(trip_id)
    user_id = g.user_id

    with db.get_conn() as conn:
        with conn.cursor() as cur:
            # 1. Fetch trip participant info and authorization check
            cur.execute(
                "SELECT rider_id, driver_id FROM trips WHERE id = %s",
                (trip_id_str,),
            )
            trip = cur.fetchone()

            if not trip:
                return redirect(url_for("trips.dashboard"))

            rider_id, driver_id = trip[0], trip[1]

            # Authorize: Only the rider or assigned driver can view/send messages
            if user_id != rider_id and user_id != driver_id:
                return redirect(url_for("trips.dashboard"))

            # 2. Process POST request (sending an encrypted message)
            if request.method == "POST":
                message_text = request.form.get("message", "").strip()
                if message_text:
                    rider_pubkey, _ = _get_ecc_keys(rider_id)
                    encrypted_msg = ecc.encrypt(message_text.encode("utf-8"), rider_pubkey)

                    cur.execute(
                        """
                        INSERT INTO chat_messages (trip_id, sender_id, message_encrypted)
                        VALUES (%s, %s, %s)
                        """,
                        (
                            trip_id_str,
                            user_id,
                            psycopg2.extras.Json(encrypted_msg),
                        ),
                    )
                    conn.commit()

                return redirect(url_for("chat.room", trip_id=trip_id_str))

            # 3. Process GET request (loading and decrypting chat history)
            cur.execute(
                """
                SELECT id, sender_id, message_encrypted, sent_at
                FROM chat_messages
                WHERE trip_id = %s
                ORDER BY sent_at ASC
                """,
                (trip_id_str,),
            )
            message_rows = cur.fetchall()

    # Obtain rider's private key for decrypting messages in this trip session
    _, rider_privkey = _get_ecc_keys(rider_id)

    formatted_messages = []
    for msg_id, sender_id, msg_enc, sent_at in message_rows:
        try:
            decrypted_bytes = ecc.decrypt(msg_enc, rider_privkey)
            text = decrypted_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = "[Decryption Failed]"

        formatted_messages.append({
            "id": msg_id,
            "sender_id": sender_id,
            "text": text,
            "is_me": (sender_id == user_id),
            "sent_at": sent_at,
        })

    return render_template(
        "chat.html",
        trip={"id": trip_id_str},
        messages=formatted_messages,
    )