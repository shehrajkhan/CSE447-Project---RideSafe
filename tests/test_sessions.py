import unittest
from unittest.mock import patch, MagicMock

from routes.sessions import (
    validate_session,
    revoke_session,
    revoke_user_sessions,
    require_role,
)


class TestSessionValidation(unittest.TestCase):

    @patch("routes.sessions.db.get_conn")
    def test_invalid_token_returns_none(
        self,
        mock_get_conn,
    ):
        """
        An unknown session token must be rejected.
        """

        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        mock_get_conn.return_value.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = None

        result = validate_session(
            "invalid-token"
        )

        self.assertIsNone(
            result
        )


    @patch("routes.sessions.db.get_conn")
    def test_valid_session_returns_user_and_role(
        self,
        mock_get_conn,
    ):
        """
        A valid active session returns user ID and role.
        """

        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        mock_get_conn.return_value.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = (
            "user-123",
            "rider",
            "active",
        )

        result = validate_session(
            "valid-token"
        )

        self.assertEqual(
            result,
            ("user-123", "rider")
        )


    @patch("routes.sessions.db.get_conn")
    def test_suspended_user_is_rejected(
        self,
        mock_get_conn,
    ):
        """
        A suspended user's existing session must no longer work.
        """

        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        mock_get_conn.return_value.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        mock_cursor.fetchone.return_value = (
            "user-123",
            "rider",
            "suspended",
        )

        result = validate_session(
            "valid-token"
        )

        self.assertIsNone(
            result
        )


    @patch("routes.sessions.db.get_conn")
    def test_revoke_session(
        self,
        mock_get_conn,
    ):
        """
        revoke_session() must mark the session revoked.
        """

        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        mock_get_conn.return_value.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        revoke_session(
            "session-token"
        )

        mock_cursor.execute.assert_called_once()

        sql = mock_cursor.execute.call_args[0][0]

        self.assertIn(
            "UPDATE sessions",
            sql
        )

        self.assertIn(
            "revoked",
            sql
        )

        mock_conn.commit.assert_called_once()


    @patch("routes.sessions.db.get_conn")
    def test_revoke_all_user_sessions(
        self,
        mock_get_conn,
    ):
        """
        revoke_user_sessions() should revoke all active
        sessions belonging to the user.
        """

        mock_conn = MagicMock()
        mock_cursor = MagicMock()

        mock_get_conn.return_value.__enter__.return_value = mock_conn
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor

        revoke_user_sessions(
            "user-123"
        )

        mock_cursor.execute.assert_called_once()

        sql = mock_cursor.execute.call_args[0][0]

        self.assertIn(
            "UPDATE sessions",
            sql
        )

        self.assertIn(
            "user_id",
            sql
        )

        self.assertIn(
            "revoked",
            sql
        )

        mock_conn.commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()