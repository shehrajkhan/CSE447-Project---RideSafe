from flask import Blueprint, render_template, request, redirect, url_for, g, flash
import psycopg2.extras
from crypto import ecc
from db import get_conn

# Import Teammate C's MAC module if available, otherwise use a pass-through stub
try:
    from crypto import mac
except ImportError:
    class StubMAC:
        @staticmethod
        def generate_mac(data: str) -> str:
            return "STUB_MAC_TAG"
        @staticmethod
        def verify_mac(data: str, tag: str) -> bool:
            return True
    mac = StubMAC()

chat_bp = Blueprint("chat", __name__, url_prefix="/chat")

def require_login(f):
    """Decorator stub for login requirement."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not getattr(g, "user_id", None):
            flash("Please log in to access chat.", "error")
            return redirect(url_for("sessions.login"))
        return f(*args, **kwargs)
    return decorated_function

def _get_user_keys(user_id):
    """Fetch stored ECC keys for a user."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT public_key, private_key FROM user_keys WHERE user_id = %s",
                (user_id,)
            )
            return cur.fetchone()

@chat_bp.route("/<int:trip_id>", methods=["GET", "POST"])
@require_login
def room(trip_id):
    # Verify user is part of this trip (either rider or driver)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                "SELECT id, rider_id, driver_id, status FROM trips WHERE id = %s",
                (trip_id,)
            )
            trip = cur.fetchone()

    if not trip or g.user_id not in (trip["rider_id"], trip["driver_id"]):
        flash("Unauthorized access to this chat.", "error")
        return redirect(url_for("trips.dashboard"))

    # Identify the recipient
    recipient_id = trip["driver_id"] if g.user_id == trip["rider_id"] else trip["rider_id"]

    if request.method == "POST":
        message_text = request.form.get("message", "").strip()
        if message_text:
            # 1. Fetch recipient's public key to encrypt the message
            recipient_keys = _get_user_keys(recipient_id)
            if not recipient_keys or not recipient_keys[0]:
                flash("Recipient public key not found.", "error")
                return redirect(url_for("chat.room", trip_id=trip_id))

            recipient_pubkey = recipient_keys[0]

            # 2. Encrypt message using ECIES
            enc_payload = ecc.encrypt(message_text.encode("utf-8"), recipient_pubkey)

            # 3. Apply MAC tag (Teammate C's primitive / stub)
            mac_tag = mac.generate_mac(enc_payload["ciphertext"])
            enc_payload["mac"] = mac_tag

            # 4. Save encrypted message to database
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO chat_messages (trip_id, sender_id, recipient_id, payload)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (trip_id, g.user_id, recipient_id, psycopg2.extras.Json(enc_payload))
                    )
                conn.commit()

        return redirect(url_for("chat.room", trip_id=trip_id))

    # GET Request: Retrieve and decrypt messages sent to current user
    user_keys = _get_user_keys(g.user_id)
    user_privkey = user_keys[1] if user_keys else None

    decrypted_messages = []
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                """
                SELECT id, sender_id, recipient_id, payload, created_at 
                FROM chat_messages 
                WHERE trip_id = %s 
                ORDER BY created_at ASC
                """,
                (trip_id,)
            )
            raw_messages = cur.fetchall()

    for msg in raw_messages:
        payload = msg["payload"]
        
        # Verify MAC tag integrity before attempting decryption
        if not mac.verify_mac(payload.get("ciphertext", ""), payload.get("mac", "")):
            decrypted_text = "[TAMPERED MESSAGE REJECTED]"
        else:
            try:
                # If current user is recipient, decrypt using their private key
                if msg["recipient_id"] == g.user_id and user_privkey:
                    decrypted_text = ecc.decrypt(payload, user_privkey).decode("utf-8")
                else:
                    # Message sent by current user (already known plaintext fallback or note)
                    decrypted_text = "(Encrypted message sent to recipient)"
            except Exception:
                decrypted_text = "[Decryption Failed]"

        decrypted_messages.append({
            "id": msg["id"],
            "sender_id": msg["sender_id"],
            "text": decrypted_text,
            "created_at": msg["created_at"],
            "is_me": msg["sender_id"] == g.user_id
        })

    return render_template("chat.html", trip=trip, messages=decrypted_messages)