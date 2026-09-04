import unittest
import hashlib
import hmac

from crypto.mac import compute_mac, verify_mac


class TestHMAC(unittest.TestCase):

    def test_matches_standard_hmac_sha256(self):
        """
        Our manually implemented HMAC should produce
        the same result as the standard reference.
        """

        cases = [
            (b"", "key"),

            (
                b"hello RideSafe",
                "secret-key"
            ),

            (
                b"pickup:Dhanmondi|dropoff:Gulshan",
                "ride-key"
            ),

            # Long key test
            (
                b"a" * 200,
                "k" * 100
            ),
        ]

        for data, key in cases:

            expected = hmac.new(
                key.encode("utf-8"),
                data,
                hashlib.sha256
            ).hexdigest()

            self.assertEqual(
                compute_mac(data, key),
                expected
            )


    def test_string_data_is_supported(self):

        expected = hmac.new(
            b"key",
            b"hello",
            hashlib.sha256
        ).hexdigest()

        self.assertEqual(
            compute_mac("hello", "key"),
            expected
        )


    def test_verification_accepts_valid_tag(self):

        data = b"sensitive ride data"

        key = "ride-safe-secret"

        tag = compute_mac(
            data,
            key
        )

        self.assertTrue(
            verify_mac(
                data,
                tag,
                key
            )
        )


    def test_modified_data_is_rejected(self):

        key = "ride-safe-secret"

        tag = compute_mac(
            b"pickup=Dhanmondi",
            key
        )

        self.assertFalse(
            verify_mac(
                b"pickup=Gulshan",
                tag,
                key
            )
        )


    def test_modified_tag_is_rejected(self):

        key = "ride-safe-secret"

        data = b"trip-status=accepted"

        tag = compute_mac(
            data,
            key
        )

        # Modify the first character of the tag.
        tampered_tag = (
            "0"
            if tag[0] != "0"
            else "1"
        ) + tag[1:]

        self.assertFalse(
            verify_mac(
                data,
                tampered_tag,
                key
            )
        )


    def test_wrong_key_is_rejected(self):

        data = b"private location data"

        tag = compute_mac(
            data,
            "correct-key"
        )

        self.assertFalse(
            verify_mac(
                data,
                tag,
                "wrong-key"
            )
        )


    def test_malformed_tags_fail_closed(self):

        self.assertFalse(
            verify_mac(
                b"data",
                "not-hex",
                "key"
            )
        )

        self.assertFalse(
            verify_mac(
                b"data",
                "00",
                "key"
            )
        )

        self.assertFalse(
            verify_mac(
                b"data",
                "",
                "key"
            )
        )


if __name__ == "__main__":
    unittest.main()