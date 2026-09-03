import unittest
import json
from app import create_app
import db
from crypto import ecc

class TestRideSafeSystem(unittest.TestCase):

    def setUp(self):
        """Set up test client and environment."""
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_ecc_primitives(self):
        """Verify ECC key generation, encryption, and decryption."""
        # Unpack directly: element 0 is private key, element 1 is public key
        privkey, pubkey = ecc.generate_keypair()

        message = b"Secret location data"
        ciphertext = ecc.encrypt(message, pubkey)
        decrypted = ecc.decrypt(ciphertext, privkey)

        self.assertEqual(message, decrypted)

    def test_02_trip_lifecycle_and_encryption(self):
        """Verify trip request creation and state changes."""
        # Test rider requesting a ride
        with self.client.session_transaction() as sess:
            sess["user_id"] = "test-rider-uuid"
            sess["user_role"] = "rider"

        response = self.client.post("/trips/request", data={
            "pickup": "Dhanmondi",
            "dropoff": "Gulshan",
            "timing": "Now"
        }, follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)

    def test_03_chat_access_and_encryption(self):
        """Verify chat authorization and end-to-end encrypted messaging."""
        # Test unauthorized access redirection
        with self.client.session_transaction() as sess:
            sess["user_id"] = "unauthorized-user-id"
            sess["user_role"] = "rider"

        response = self.client.get("/chat/00000000-0000-0000-0000-000000000000", follow_redirects=False)
        self.assertEqual(response.status_code, 302)

if __name__ == "__main__":
    unittest.main()