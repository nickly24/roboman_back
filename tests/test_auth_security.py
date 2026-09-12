"""Authentication boundaries for external branch accounts; no database access."""
import hashlib
import unittest
from unittest.mock import patch

from flask import Flask
from werkzeug.exceptions import BadRequest, Forbidden, Unauthorized
import shared


class AuthenticationSecurityTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.branch = shared.CurrentUser(id=3, role='BRANCH', owner_id=None,
                                         teacher_id=None, login='branch', branch_id=10)

    def test_new_password_is_hashed_and_verified(self):
        encoded = shared.hash_password('Garden-Password-2026')
        self.assertNotIn('Garden-Password-2026', encoded)
        self.assertTrue(shared.password_matches(encoded, 'Garden-Password-2026'))
        self.assertFalse(shared.password_matches(encoded, 'wrong-password'))

    def test_legacy_password_requires_exact_match(self):
        self.assertTrue(shared.password_matches('legacy-example', 'legacy-example'))
        self.assertFalse(shared.password_matches('legacy-example', 'any-other-value'))
        self.assertFalse(shared.password_matches('legacy-example', ''))

    def test_invalid_hash_does_not_become_plaintext_password(self):
        self.assertFalse(shared.password_matches('scrypt:invalid', 'scrypt:invalid'))

    def test_short_or_missing_new_password_rejected(self):
        for value in ('short', '', None, 12345678, 'x' * 257):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(BadRequest):
                    shared.hash_password(value)

    def test_user_id_is_never_accepted_as_bearer(self):
        for token in ('1', '42', '9' * 64, 'abc', 'x' * 129):
            with self.subTest(length=len(token)):
                with self.app.test_request_context(headers={'Authorization': 'Bearer ' + token}):
                    with patch.object(shared, 'db_cursor') as database:
                        with self.assertRaises(Unauthorized):
                            shared.get_current_user()
                        database.assert_not_called()

    def test_missing_authentication_is_rejected(self):
        with self.app.test_request_context():
            with self.assertRaises(Unauthorized):
                shared.get_current_user()

    def test_branch_role_cannot_enter_legacy_endpoints(self):
        endpoints = ['lessons_update', 'slots_create', 'teachers_get', 'calendar.series_update',
                     'accounting.sheets_list', 'branch_invoices.invoice_get', '', 'branch_portal_fake.test']
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                self.app.add_url_rule('/' + endpoint, endpoint=endpoint or 'unknown', view_func=lambda: '')
                with self.app.test_request_context('/' + endpoint):
                    with self.assertRaises(Forbidden):
                        shared.enforce_branch_route(self.branch)

    def test_branch_can_access_only_portal_and_own_session(self):
        for endpoint in ('auth_me', 'auth_logout', 'branch_portal.overview'):
            self.app.add_url_rule('/' + endpoint, endpoint=endpoint, view_func=lambda: '')
            with self.app.test_request_context('/' + endpoint):
                shared.enforce_branch_route(self.branch)

    def test_session_stores_only_token_digest(self):
        with patch.object(shared, 'exec_one') as write:
            first = shared.create_session(object(), 3)
            args = write.call_args.args
            self.assertEqual(args[2][0], hashlib.sha256(first.encode()).hexdigest())
            self.assertNotEqual(args[2][0], first)
            self.assertEqual(args[2][1], 3)
            second = shared.create_session(object(), 3)
            self.assertNotEqual(first, second)
            self.assertGreaterEqual(len(first), 40)


if __name__ == '__main__':
    unittest.main()
