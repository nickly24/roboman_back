"""Read-only JSON/schema snapshot before importing legacy schedules."""
import gzip
import hashlib
import json
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
    path = destination / f'calendar-source-{stamp}.json.gz'
    conn = mysql.connector.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, connection_timeout=10, autocommit=False)
    cur = conn.cursor(dictionary=True)
    cur.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
    tables = {}
    for name in ('schedules', 'branches', 'branch_teachers', 'teachers', 'departments', 'department_owners'):
        cur.execute('SHOW CREATE TABLE '+name)
        schema = cur.fetchone()['Create Table']
        cur.execute('SELECT * FROM '+name)
        tables[name] = dict(schema=schema, rows=cur.fetchall())
    conn.rollback()
    cur.close()
    conn.close()
    payload = json.dumps(dict(created_at=stamp, database=DB_NAME, tables=tables), ensure_ascii=False, default=str).encode()
    with gzip.open(path,'wb') as stream:
        stream.write(payload)
    path.chmod(0o600)
    manifest = dict(path=str(path), sha256=hashlib.sha256(payload).hexdigest(), counts={name:len(table['rows']) for name,table in tables.items()})
    path.with_suffix('.manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
    print(json.dumps(manifest,ensure_ascii=False))


if __name__ == '__main__':
    main()
