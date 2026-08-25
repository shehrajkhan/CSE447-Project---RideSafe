"""
routes/keys.py - Key Management Module: generate, store, rotate keypairs.

Uses: crypto/rsa.py, crypto/ecc.py for keypair generation.
"""

from flask import Blueprint, jsonify

keys_bp = Blueprint("keys", __name__, url_prefix="/keys")


@keys_bp.route("/generate", methods=["POST"])
def generate_keys():
    """
    TODO:
      1. Call crypto.rsa.generate_keypair() and crypto.ecc.generate_keypair()
      2. Wrap each private key: encrypt it with a key derived from the
         user's password (e.g. via your salted-hash routine as a KDF)
      3. Store encrypted private keys + plaintext public keys in Supabase
         (public keys are, by definition, fine to store as-is)
    """
    return jsonify({"status": "not_implemented", "route": "generate_keys"}), 501


@keys_bp.route("/rotate", methods=["POST"])
def rotate_keys():
    """
    TODO:
      1. Generate a new keypair
      2. Decrypt all of the user's existing records with the OLD private key
      3. Re-encrypt them with the NEW public key
      4. Recompute MAC tags (crypto.mac.compute_mac()) over the new ciphertext
      5. Replace the old keypair in Supabase, securely discard the old private key
    """
    return jsonify({"status": "not_implemented", "route": "rotate_keys"}), 501
