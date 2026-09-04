import os
import unittest


os.environ.setdefault(
    "RIDESAFE_MAC_KEY",
    "test-ridesafe-integrity-key"
)


from crypto import ecc
from crypto.integrity import (
    attach_mac,
    verify_payload_mac,
)


class TestTamperDetection(unittest.TestCase):

    def setUp(self):

        self.private_key, self.public_key = (
            ecc.generate_keypair()
        )

        encrypted = ecc.encrypt(
            b"Gulshan to Dhanmondi",
            self.public_key
        )

        self.payload = attach_mac(
            encrypted
        )


    def test_original_payload_is_valid(self):

        self.assertTrue(
            verify_payload_mac(
                self.payload
            )
        )


    def test_modified_ciphertext_is_rejected(self):

        tampered = dict(
            self.payload
        )

        ciphertext = tampered[
            "ciphertext"
        ]

        tampered[
            "ciphertext"
        ] = (
            ("0" if ciphertext[0] != "0" else "1")
            + ciphertext[1:]
        )

        self.assertFalse(
            verify_payload_mac(
                tampered
            )
        )


    def test_modified_ephemeral_key_is_rejected(self):

        tampered = dict(
            self.payload
        )

        ephemeral_key = tampered[
            "ephemeral_pubkey"
        ]

        tampered[
            "ephemeral_pubkey"
        ] = (
            ("0" if ephemeral_key[0] != "0" else "1")
            + ephemeral_key[1:]
        )

        self.assertFalse(
            verify_payload_mac(
                tampered
            )
        )


    def test_modified_mac_is_rejected(self):

        tampered = dict(
            self.payload
        )

        tag = tampered["mac"]

        tampered["mac"] = (
            ("0" if tag[0] != "0" else "1")
            + tag[1:]
        )

        self.assertFalse(
            verify_payload_mac(
                tampered
            )
        )


    def test_missing_mac_is_rejected(self):

        tampered = dict(
            self.payload
        )

        del tampered["mac"]

        self.assertFalse(
            verify_payload_mac(
                tampered
            )
        )


    def test_modified_scheme_is_rejected(self):

        tampered = dict(
            self.payload
        )

        tampered["scheme"] = "tampered"

        self.assertFalse(
            verify_payload_mac(
                tampered
            )
        )


if __name__ == "__main__":
    unittest.main()