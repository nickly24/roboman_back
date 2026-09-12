"""Apply SQL migrations in filename order and record them in schema_migrations."""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

import mysql.connector  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "migrations"


def _statements(sql: str) -> list[str]:
    """Split SQL including DELIMITER trigger bodies, quoted text and comments."""
    statements: list[str] = []
    current: list[str] = []
    delimiter = ';'
    quote = None
    comment = None
    index = 0
    while index < len(sql):
        char = sql[index]
        following = sql[index:index + 2]
        if comment:
            current.append(char)
            if comment == 'line' and char == '\n':
                comment = None
            elif comment == 'block' and following == '*/':
                current.append('/')
                index += 1
                comment = None
            index += 1
            continue
        if quote:
            current.append(char)
            if char == '\\' and index + 1 < len(sql):
                current.append(sql[index + 1])
                index += 1
            elif char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    current.append(quote)
                    index += 1
                else:
                    quote = None
            index += 1
            continue
        if index == 0 or sql[index - 1] == '\n':
            directive = re.match(r'[ \t]*DELIMITER[ \t]+(\S+)[ \t]*(?:\r?\n|$)', sql[index:], re.IGNORECASE)
            if directive:
                delimiter = directive.group(1)
                index += directive.end()
                continue
        if char in ("'", '"', '`'):
            quote = char
        elif char == '#' or (following == '--' and (index + 2 == len(sql) or sql[index + 2].isspace())):
            comment = 'line'
        elif following == '/*':
            comment = 'block'
        if not quote and not comment and sql.startswith(delimiter, index):
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
            index += len(delimiter)
        else:
            current.append(char)
            index += 1
    if quote or comment == 'block':
        raise ValueError('Unterminated SQL quote or block comment')
    trailing = "".join(current).strip()
    if trailing:
        statements.append(trailing)
    return statements


def main() -> None:
    connection = mysql.connector.connect(
        host=os.environ.get("DB_HOST", "147.45.138.77"),
        port=int(os.environ.get("DB_PORT", "3306")),
        user=os.environ.get("DB_USER", "itmasters"),
        password=os.environ.get("DB_PASSWORD", "itmasters"),
        database=os.environ.get("DB_NAME", "roboman"),
        autocommit=False,
    )
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
          version VARCHAR(255) NOT NULL,
          checksum CHAR(64) NOT NULL,
          applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (version)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """
    )
    connection.commit()

    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        sql = path.read_text(encoding="utf-8")
        checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        cursor.execute("SELECT checksum FROM schema_migrations WHERE version=%s", (path.name,))
        row = cursor.fetchone()
        if row:
            if row[0] != checksum:
                raise RuntimeError(f"Applied migration changed: {path.name}")
            print(f"skip {path.name}")
            continue
        print(f"apply {path.name}")
        try:
            for statement in _statements(sql):
                cursor.execute(statement)
            cursor.execute(
                "INSERT INTO schema_migrations(version, checksum) VALUES (%s,%s)",
                (path.name, checksum),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        print(f"done {path.name}")

    cursor.close()
    connection.close()


if __name__ == "__main__":
    main()
