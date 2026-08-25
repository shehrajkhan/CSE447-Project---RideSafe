"""
routes/chat.py - In-app chat between rider and driver during an active ride.

Uses: crypto/ecc.py to encrypt messages, crypto/mac.py (whoever owns sessions/RBAC's module)
to tag each message so tampered/injected messages are rejected on delivery.
"""

from flask import Blueprint, jsonify

chat_bp = Blueprint("chat", __name__, url_prefix="/chat")


@chat_bp.route("/<trip_id>/messages", methods=["GET"])
def get_messages(trip_id):
    """
    TODO:
      1. Require a valid session + confirm the user belongs to this trip (RBAC)
      2. Fetch encrypted messages for this trip from Supabase
      3. Decrypt with crypto.ecc.decrypt()
      4. Verify each message's MAC (crypto.mac.verify_mac()) before returning it
    """
    return jsonify({"status": "not_implemented", "route": "get_messages", "trip_id": trip_id}), 501


@chat_bp.route("/<trip_id>/send", methods=["POST"])
def send_message(trip_id):
    """
    TODO:
      1. Encrypt the message with crypto.ecc.encrypt() using the recipient's public key
      2. Compute a MAC over the ciphertext (crypto.mac.compute_mac())
      3. Store {ciphertext, ephemeral_pubkey, mac} in Supabase
    """
    return jsonify({"status": "not_implemented", "route": "send_message", "trip_id": trip_id}), 501
