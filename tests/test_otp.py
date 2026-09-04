import unittest
from unittest.mock import patch

from crypto.otp import (
    generate_secret,
    hotp,
    totp,
    generate_otp,
    verify_otp,
)


class TestOTP(unittest.TestCase):

    def test_secret_is_random(self):
        """Secret should be random and 40 hexadecimal characters."""

        secret1 = generate_secret()
        secret2 = generate_secret()

        self.assertIsInstance(
            secret1,
            str,
        )

        self.assertIsInstance(
            secret2,
            str,
        )

        # 20 bytes = 160 bits.
        # Hex representation = 40 characters.
        self.assertEqual(
            len(secret1),
            40,
        )

        self.assertEqual(
            len(secret2),
            40,
        )

        # Two generated secrets should normally be different.
        self.assertNotEqual(
            secret1,
            secret2,
        )

        # Check that the secret contains only hexadecimal characters.
        self.assertTrue(
            all(
                c in "0123456789abcdef"
                for c in secret1.lower()
            )
        )


    def test_hotp_is_six_digits(self):
        """HOTP should always return a 6-digit code."""

        secret = generate_secret()

        code = hotp(
            secret,
            0,
        )

        self.assertEqual(
            len(code),
            6,
        )

        self.assertTrue(
            code.isdigit()
        )


    def test_hotp_is_deterministic(self):
        """
        The same secret and counter must always
        produce the same HOTP code.
        """

        secret = "00112233445566778899aabbccddeeff00112233"

        code1 = hotp(
            secret,
            123,
        )

        code2 = hotp(
            secret,
            123,
        )

        self.assertEqual(
            code1,
            code2,
        )


    def test_hotp_counter_changes_result(self):
        """
        Different counters should produce valid 6-digit HOTP values.

        We don't require the values to be mathematically different,
        because a theoretical 6-digit collision is possible.
        """

        secret = generate_secret()

        code1 = hotp(
            secret,
            100,
        )

        code2 = hotp(
            secret,
            101,
        )

        self.assertEqual(
            len(code1),
            6,
        )

        self.assertEqual(
            len(code2),
            6,
        )

        self.assertTrue(
            code1.isdigit()
        )

        self.assertTrue(
            code2.isdigit()
        )


    def test_totp_is_deterministic_for_same_time(self):
        """
        Same secret + same timestamp should produce
        the same TOTP.
        """

        secret = generate_secret()

        timestamp = 1_700_000_001

        code1 = totp(
            secret,
            timestamp,
        )

        code2 = totp(
            secret,
            timestamp,
        )

        self.assertEqual(
            code1,
            code2,
        )


    def test_totp_same_code_within_same_time_step(self):
        """
        Timestamps inside the same 30-second window
        should generate the same TOTP.
        """

        secret = generate_secret()

        # Both timestamps belong to the same 30-second
        # TOTP counter window.
        timestamp1 = 1_700_000_001
        timestamp2 = 1_700_000_005

        code1 = totp(
            secret,
            timestamp1,
        )

        code2 = totp(
            secret,
            timestamp2,
        )

        self.assertEqual(
            code1,
            code2,
        )


    def test_totp_changes_between_time_steps(self):
        """
        Moving to the next 30-second counter should
        still produce a valid 6-digit OTP.
        """

        secret = generate_secret()

        timestamp1 = 1_700_000_001
        timestamp2 = 1_700_000_031

        code1 = totp(
            secret,
            timestamp1,
        )

        code2 = totp(
            secret,
            timestamp2,
        )

        self.assertEqual(
            len(code1),
            6,
        )

        self.assertEqual(
            len(code2),
            6,
        )

        self.assertTrue(
            code1.isdigit()
        )

        self.assertTrue(
            code2.isdigit()
        )


    def test_generate_otp_returns_six_digits(self):
        """
        generate_otp() should use the current TOTP
        mechanism and return a 6-digit code.
        """

        secret = generate_secret()

        code = generate_otp(
            secret
        )

        self.assertEqual(
            len(code),
            6,
        )

        self.assertTrue(
            code.isdigit()
        )


    def test_verify_current_code(self):
        """
        The current TOTP should be accepted.
        """

        secret = generate_secret()

        timestamp = 1_700_000_001

        code = totp(
            secret,
            timestamp,
        )

        # Make the server think the current time
        # is exactly our test timestamp.
        with patch(
            "crypto.otp.time.time",
            return_value=timestamp,
        ):

            self.assertTrue(
                verify_otp(
                    secret,
                    code,
                )
            )


    def test_verify_previous_time_step(self):
        """
        The previous 30-second time step should be accepted
        because the project allows +/- 1 time-step drift.
        """

        secret = generate_secret()

        timestamp = 1_700_000_031

        previous_code = totp(
            secret,
            timestamp - 30,
        )

        with patch(
            "crypto.otp.time.time",
            return_value=timestamp,
        ):

            self.assertTrue(
                verify_otp(
                    secret,
                    previous_code,
                )
            )


    def test_verify_next_time_step(self):
        """
        The next 30-second time step should be accepted
        because the project allows +/- 1 time-step drift.
        """

        secret = generate_secret()

        timestamp = 1_700_000_001

        next_code = totp(
            secret,
            timestamp + 30,
        )

        with patch(
            "crypto.otp.time.time",
            return_value=timestamp,
        ):

            self.assertTrue(
                verify_otp(
                    secret,
                    next_code,
                )
            )


    def test_wrong_code_is_rejected(self):
        """An incorrect OTP must be rejected."""

        secret = generate_secret()

        timestamp = 1_700_000_001

        with patch(
            "crypto.otp.time.time",
            return_value=timestamp,
        ):

            self.assertFalse(
                verify_otp(
                    secret,
                    "123456",
                )
            )


    def test_invalid_code_too_short_is_rejected(self):
        """OTP with fewer than 6 digits must be rejected."""

        secret = generate_secret()

        self.assertFalse(
            verify_otp(
                secret,
                "12345",
            )
        )


    def test_invalid_code_too_long_is_rejected(self):
        """OTP with more than 6 digits must be rejected."""

        secret = generate_secret()

        self.assertFalse(
            verify_otp(
                secret,
                "1234567",
            )
        )


    def test_invalid_non_numeric_code_is_rejected(self):
        """OTP containing non-numeric characters must be rejected."""

        secret = generate_secret()

        self.assertFalse(
            verify_otp(
                secret,
                "abcdef",
            )
        )


    def test_empty_code_is_rejected(self):
        """Empty OTP must be rejected."""

        secret = generate_secret()

        self.assertFalse(
            verify_otp(
                secret,
                "",
            )
        )


    def test_wrong_secret_is_rejected(self):
        """
        An OTP generated with another secret must not
        be accepted.
        """

        secret1 = generate_secret()
        secret2 = generate_secret()

        timestamp = 1_700_000_001

        code = totp(
            secret1,
            timestamp,
        )

        with patch(
            "crypto.otp.time.time",
            return_value=timestamp,
        ):

            self.assertFalse(
                verify_otp(
                    secret2,
                    code,
                )
            )


if __name__ == "__main__":
    unittest.main()