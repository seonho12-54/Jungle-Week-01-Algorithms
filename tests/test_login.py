import unittest
from contextlib import ExitStack
from unittest.mock import patch

import app.app as app_module


class LoginTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()

        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        self.db = self.patches.enter_context(patch.object(app_module, "db"))
        self.bcrypt = self.patches.enter_context(patch.object(app_module, "bcrypt"))
        self.create_access_token = self.patches.enter_context(
            patch.object(app_module, "create_access_token", return_value="access-token")
        )
        self.create_refresh_token = self.patches.enter_context(
            patch.object(app_module, "create_refresh_token", return_value="refresh-token")
        )
        self.refresh_token_hash = self.patches.enter_context(
            patch.object(app_module, "refresh_token_hash")
        )
        self.set_access_cookies = self.patches.enter_context(
            patch.object(app_module, "set_access_cookies")
        )
        self.set_refresh_cookies = self.patches.enter_context(
            patch.object(app_module, "set_refresh_cookies")
        )

    def assert_authentication_was_not_started(self):
        self.create_access_token.assert_not_called()
        self.create_refresh_token.assert_not_called()
        self.refresh_token_hash.assert_not_called()
        self.set_access_cookies.assert_not_called()
        self.set_refresh_cookies.assert_not_called()

    def test_rejects_malformed_json_before_querying_for_a_user(self):
        response = self.client.post(
            "/login", data='{"id":', content_type="application/json"
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {"result": "fail", "message": "JSON 형식이 잘못되었습니다."},
        )
        self.db.users.find_one.assert_not_called()
        self.bcrypt.check_password_hash.assert_not_called()
        self.assert_authentication_was_not_started()

    def test_rejects_missing_credentials_before_querying_for_a_user(self):
        cases = (
            ({"pwd": "secret"}, "id가 비어 있습니다."),
            ({"id": "alice"}, "비밀번호가 비어 있습니다."),
        )

        for payload, message in cases:
            with self.subTest(payload=payload):
                response = self.client.post("/login", json=payload)

                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json(), {"result": "fail", "message": message}
                )

        self.db.users.find_one.assert_not_called()
        self.bcrypt.check_password_hash.assert_not_called()
        self.assert_authentication_was_not_started()

    def test_unknown_user_returns_generic_error_without_checking_a_password(self):
        self.db.users.find_one.return_value = None

        response = self.client.post(
            "/login", json={"id": "unknown", "pwd": "secret"}
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json(),
            {"result": "fail", "message": "아이디 또는 비밀번호가 틀렸습니다."},
        )
        self.db.users.find_one.assert_called_once_with({"id": "unknown"})
        self.bcrypt.check_password_hash.assert_not_called()
        self.assert_authentication_was_not_started()

    def test_wrong_password_returns_same_error_as_an_unknown_user(self):
        self.db.users.find_one.return_value = {
            "id": "alice",
            "pwd": b"password-hash",
            "role": "USER",
        }
        self.bcrypt.check_password_hash.return_value = False

        response = self.client.post(
            "/login", json={"id": "alice", "pwd": "incorrect"}
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json(),
            {"result": "fail", "message": "아이디 또는 비밀번호가 틀렸습니다."},
        )
        self.db.users.find_one.assert_called_once_with({"id": "alice"})
        self.bcrypt.check_password_hash.assert_called_once_with(
            b"password-hash", "incorrect"
        )
        self.assert_authentication_was_not_started()

    def test_success_returns_role_and_completes_token_and_cookie_workflow(self):
        self.db.users.find_one.return_value = {
            "id": "alice",
            "pwd": b"password-hash",
            "role": "ADMIN",
        }
        self.bcrypt.check_password_hash.return_value = True

        response = self.client.post(
            "/login", json={"id": "alice", "pwd": "correct"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"result": "success", "role": "ADMIN"})
        self.db.users.find_one.assert_called_once_with({"id": "alice"})
        self.bcrypt.check_password_hash.assert_called_once_with(
            b"password-hash", "correct"
        )
        self.create_access_token.assert_called_once_with(identity="alice")
        self.create_refresh_token.assert_called_once_with(identity="alice")
        self.refresh_token_hash.assert_called_once_with(
            "alice", "refresh-token", "new"
        )
        self.set_access_cookies.assert_called_once()
        self.set_refresh_cookies.assert_called_once()

        access_response, access_token = self.set_access_cookies.call_args.args
        refresh_response, refresh_token = self.set_refresh_cookies.call_args.args
        self.assertIs(access_response, refresh_response)
        self.assertEqual(access_token, "access-token")
        self.assertEqual(refresh_token, "refresh-token")


if __name__ == "__main__":
    unittest.main()
