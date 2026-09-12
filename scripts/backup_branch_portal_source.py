"""Read-only, private snapshot of source data before the branch portal migration."""
import gzip
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import mysql.connector

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from shared import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME


def main():
    destination = Path(__file__).resolve().parents[2] / '.local-backups'
    destination.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    path = destination / f'branch-portal-source-{stamp}.json.gz'
    connection = mysql.connector.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD,
        database=DB_NAME, connection_timeout=10, autocommit=False,
    )
    cursor = connection.cursor(dictionary=True)
    tables = {}
    try:
        cursor.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
        for name in ('auf_users', 'branches', 'lessons', 'departments', 'department_owners', 'schema_migrations'):
            cursor.execute('SHOW CREATE TABLE ' + name)
            schema = cursor.fetchone()['Create Table']
            cursor.execute('SELECT * FROM ' + name)
            tables[name] = dict(schema=schema, rows=cursor.fetchall())
        cursor.execute('SHOW CREATE VIEW v_lessons_calc')
        view = cursor.fetchone()['Create View']
    finally:
        connection.rollback()
        cursor.close()
        connection.close()
    payload = json.dumps(dict(created_at=stamp, database=DB_NAME, tables=tables, lesson_view=view), ensure_ascii=False, default=str).encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb') as stream:
            stream.write(payload)
    manifest = dict(path=str(path), sha256=hashlib.sha256(payload).hexdigest(), counts={name: len(table['rows']) for name, table in tables.items()})
    path.with_suffix('.manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == '__main__':
    main()
