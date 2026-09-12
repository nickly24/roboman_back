"""Lesson API regression tests: the database is mocked, never production."""
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

import main
from lesson_time import parse_lesson_time


class LessonTimeTests(unittest.TestCase):
    def test_parser_keeps_literal_time_and_rejects_zones_and_invalid_dates(self):
        for value in ['2026-09-12T16:00', '2026-09-01T00:30:00', '2026-03-08T02:30']:
            with self.subTest(value=value):
                result = parse_lesson_time(value)
                self.assertIsNone(result.tzinfo)
                self.assertEqual(result.isoformat(timespec='minutes'), value[:16])
        for value in [None, '', '2026-09-12', '2026-02-30T16:00', '2026-09-12T24:00',
                      '2026-09-12T13:00:00Z', '2026-09-12T16:00:00+03:00']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_lesson_time(value)

    def test_create_and_repeated_update_preserve_time_for_both_roles(self):
        for role in ['OWNER', 'TEACHER']:
            for entered in ['2026-09-12T16:00', '2026-09-01T00:30', '2026-09-30T23:45', '2026-03-08T02:30']:
                with self.subTest(role=role, entered=entered):
                    self.check_round_trip(role, entered)

    def check_round_trip(self, role, entered):
        user = main.CurrentUser(id=1, role=role, owner_id=1, teacher_id=2, login='test')
        row = {'id': 7, 'teacher_id': 2, 'branch_id': 1, 'paid_children': 1, 'trial_children': 0}
        cursor = MagicMock()

        def read(_cursor, sql, params):
            if 'FROM lessons' in sql or 'FROM v_lessons_calc' in sql:
                return dict(row)
            if 'price_per_child' in sql:
                return {'price_per_child': 100}
            return {'is_salary_free': 0}

        def insert(_cursor, sql, params):
            row['starts_at'] = datetime.fromisoformat(params[2])
            return row['id']

        def update(sql, params):
            self.assertIn('UPDATE lessons SET starts_at=%s', sql)
            row['starts_at'] = datetime.fromisoformat(params[0])

        cursor.execute.side_effect = update
        with (
            patch('main.get_current_user', return_value=user),
            patch('main.db_cursor') as database,
            patch('main.fetch_one', side_effect=read),
            patch('main.exec_one', side_effect=insert) as insert_call,
            patch('blueprints.curriculum.validate_lesson_curriculum', return_value={
                'instruction_id': None, 'run_id': None, 'lesson_id': None, 'mode': None,
            }),
        ):
            database.return_value.__enter__.return_value = (MagicMock(), cursor)
            client = main.app.test_client()
            body = {'branch_id': 1, 'teacher_id': 2, 'starts_at': entered,
                    'paid_children': 1, 'trial_children': 0, 'is_creative': True}
            response = client.post('/api/lessons', json=body)
            self.assertEqual(response.status_code, 200, response.get_json())
            self.assertEqual(insert_call.call_args.args[2][2], entered.replace('T', ' ') + ':00')
            expected = entered + ':00'
            self.assertEqual(response.get_json()['data']['starts_at'], expected)
            for _ in range(2):
                response = client.put('/api/lessons/7', json={'starts_at': response.get_json()['data']['starts_at']})
                self.assertEqual(response.status_code, 200, response.get_json())
                self.assertEqual(response.get_json()['data']['starts_at'], expected)

            # A stale frontend with toISOString() must fail instead of silently
            # saving the UTC-shifted hour. No write is made on either endpoint.
            cursor.execute.reset_mock()
            insert_call.reset_mock()
            body['starts_at'] = '2026-09-12T13:00:00Z'
            self.assertEqual(client.post('/api/lessons', json=body).status_code, 400)
            self.assertEqual(client.put('/api/lessons/7', json={'starts_at': body['starts_at']}).status_code, 400)
            cursor.execute.assert_not_called()
            insert_call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
