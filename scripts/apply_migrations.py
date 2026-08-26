"""Apply SQL migrations in filename order and record them in schema_migrations."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import mysql.connector  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS_DIR = ROOT / "migrations"


def _statements(sql: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    escaped = False
    for char in sql:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and (in_single or in_double):
            current.append(char)
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if char == ";" and not in_single and not in_double:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement)
            current = []
        else:
            current.append(char)
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
