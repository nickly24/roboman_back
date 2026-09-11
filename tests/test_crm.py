import unittest
from unittest.mock import MagicMock, patch

import main


class CRMTests(unittest.TestCase):
    def setUp(self):
        self.client = main.app.test_client()

    def test_removed_routes_return_404_without_database_access(self):
        paths = [
            '/api/crm/chats', '/api/crm/chats/1',
            '/api/crm/chats/1/messages', '/api/crm/chats/1/read',
            '/api/crm/chats/1/comments', '/api/crm/chats/1/summarize',
            '/api/crm/chats/1/ai-chat', '/api/crm/branches/1/chats',
            '/api/crm/nchats/ai-chat', '/api/crm/transcribe-voice',
            '/api/crm/registration-requests',
            '/api/crm/registration-requests/1/approve',
            '/api/crm/registration-requests/1/reject',
            '/api/crm/notification-subscribers',
            '/api/crm/notification-subscribers/1',
        ]
        with patch('main.db_cursor', side_effect=AssertionError('Unexpected database access')):
            for path in paths:
                for method in ['GET', 'POST', 'PUT', 'DELETE']:
                    with self.subTest(path=path, method=method):
                        response = self.client.open(path, method=method)
                        self.assertEqual(response.status_code, 404)

    def test_crm_settings_preserve_search_key_and_ignore_retired_fields(self):
        user = main.CurrentUser(id=1, role='OWNER', owner_id=1, teacher_id=None, login='test')
        cursor = MagicMock()
        with (
            patch('main.get_current_user', return_value=user),
            patch('main.db_cursor') as database,
            patch('main.fetch_one', return_value={'crm_access': 1, 'value_text': 'test-search-key'}),
        ):
            database.return_value.__enter__.return_value = (MagicMock(), cursor)
            response = self.client.get('/api/crm/settings')
            self.assertEqual(response.get_json()['data'], {'aitunnel_configured': True})

            response = self.client.put('/api/crm/settings', json={'telegram_bot_token': 'retired'})
            self.assertEqual(response.status_code, 200)
            cursor.execute.assert_not_called()

            response = self.client.put('/api/crm/settings', json={'aitunnel_api_key': 'new-search-key'})
            self.assertEqual(response.status_code, 200)
            cursor.execute.assert_called_once()
            self.assertEqual(cursor.execute.call_args.args[1][0:2], ('aitunnel_api_key', 'new-search-key'))


if __name__ == '__main__':
    unittest.main()
