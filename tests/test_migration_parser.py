import unittest
from pathlib import Path
from scripts.apply_migrations import _statements


class MigrationParserTests(unittest.TestCase):
    def test_delimiters_preserve_trigger_body(self):
        sql = "DELIMITER $$\nCREATE TRIGGER t BEFORE INSERT ON x FOR EACH ROW\nBEGIN\nSET @a='hello; $$';\nSET @b=2;\nEND$$\nDELIMITER ;\nSELECT 1;"
        statements = _statements(sql)
        self.assertEqual(len(statements), 2)
        self.assertIn("SET @a='hello; $$';", statements[0])
        self.assertTrue(statements[0].endswith('END'))
        self.assertEqual(statements[1], 'SELECT 1')

    def test_comments_and_quoted_identifiers(self):
        statements = _statements("-- it's a comment;\nSELECT `a;b`, 'it''s;here'; /* ; */ SELECT 2;")
        self.assertEqual(len(statements), 2)
        self.assertIn("'it''s;here'", statements[0])

    def test_incomplete_quote_rejected(self):
        with self.assertRaises(ValueError):
            _statements("SELECT 'unterminated")

    def test_branch_trigger_migration_has_four_complete_statements(self):
        path = Path(__file__).resolve().parents[1] / 'migrations/20260912_002_branch_user_triggers.sql'
        statements = _statements(path.read_text())
        self.assertEqual(len(statements), 4)
        self.assertTrue(statements[1].endswith('END'))
        self.assertTrue(statements[3].endswith('END'))


if __name__ == '__main__':
    unittest.main()
