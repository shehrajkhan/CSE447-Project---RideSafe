"""
routes/trips.py - Ride requests & trip logs (the "posts" of this project).

Uses: crypto/ecc.py to encrypt pickup/drop-off/timing data, crypto/mac.py
(whoever owns sessions/RBAC's module) to tag each record for tamper detection.
"""

from flask import Blueprint, jsonify

trips_bp = Blueprint("trips", __name__, url_prefix="/trips")


@trips_bp.route("/", methods=["GET"])
def list_trips():
    """
    TODO:
      1. Require a valid session (routes/sessions.py)
      2. Fetch the user's encrypted trip rows from Supabase
      3. Decrypt each with crypto.ecc.decrypt()
      4. Re-verify the MAC tag on each (crypto.mac.verify_mac()) before
         trusting/displaying the decrypted data - reject/flag mismatches
    """
    return jsonify({"status": "not_implemented", "route": "list_trips"}), 501


@trips_bp.route("/request", methods=["POST"])
def request_ride():
    """
    TODO:
      1. Collect pickup/drop-off/timing from the form
      2. Encrypt with crypto.ecc.encrypt() using the driver's/rider's public key
      3. Compute a MAC over the ciphertext (crypto.mac.compute_mac())
      4. Store {ciphertext, mac} in Supabase
    """
    return jsonify({"status": "not_implemented", "route": "request_ride"}), 501


@trips_bp.route("/<trip_id>/log", methods=["POST"])
def log_trip_event(trip_id):
    """TODO: append an encrypted+MAC-tagged event to an ongoing trip."""
    return jsonify({"status": "not_implemented", "route": "log_trip_event", "trip_id": trip_id}), 501
