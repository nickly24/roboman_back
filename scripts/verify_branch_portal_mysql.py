"""Exercise real MySQL constraints and API SQL inside one always-rolled-back transaction.

No DDL, no commits, no external messages. Run explicitly, never from test discovery.
"""
import argparse
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
import sys
import uuid
from unittest.mock import patch

import mysql.connector

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main
import shared
from blueprints import branch_portal


def run():
    conn = mysql.connector.connect(host=shared.DB_HOST, port=shared.DB_PORT, user=shared.DB_USER,
        password=shared.DB_PASSWORD, database=shared.DB_NAME, autocommit=False, connection_timeout=10)
    conn.start_transaction()
    sequence = 0

    @contextmanager
    def transaction_cursor(**kwargs):
        nonlocal sequence
        sequence += 1
        savepoint = f'portal_check_{sequence}'
        cursor = conn.cursor(dictionary=kwargs.get('dictionary', True), buffered=True)
        cursor.execute('SAVEPOINT ' + savepoint)
        try:
            yield conn, cursor
        except BaseException:
            cursor.execute('ROLLBACK TO SAVEPOINT ' + savepoint)
            raise
        finally:
            cursor.execute('RELEASE SAVEPOINT ' + savepoint)
            cursor.close()

    checks = []
    try:
        with transaction_cursor() as (_, cur):
            cur.execute('''SELECT u.id,own.department_id FROM auf_users u JOIN department_owners own ON own.owner_id=u.owner_id
                WHERE u.role='OWNER' AND u.is_active=1 ORDER BY u.id,own.department_id LIMIT 1''')
            owner = cur.fetchone()
            assert owner, 'An active owner with department is required'
            token = shared.create_session(cur, owner['id'])
            cur.execute("INSERT INTO branches(department_id,name,address,price_per_child) VALUES (%s,%s,%s,%s)",
                (owner['department_id'], '__rollback_portal_' + uuid.uuid4().hex, 'Synthetic verification, rolled back', Decimal('300.00')))
            branch_id = cur.lastrowid
            cur.execute("SELECT id FROM teachers WHERE status='working' ORDER BY id LIMIT 1")
            teacher_id = cur.fetchone()['id']
            cur.execute('INSERT INTO branch_teachers(branch_id,teacher_id) VALUES (%s,%s)', (branch_id, teacher_id))
            cur.execute('''INSERT INTO lessons(branch_id,teacher_id,starts_at,paid_children,trial_children,price_snapshot,is_creative,created_by_user_id)
                VALUES (%s,%s,'2026-09-10 10:00:00',7,2,300,1,%s)''', (branch_id, teacher_id, owner['id']))
            lesson_id = cur.lastrowid

        with patch.object(shared, 'db_cursor', transaction_cursor), patch.object(main, 'db_cursor', transaction_cursor), patch.object(branch_portal, 'db_cursor', transaction_cursor):
            client = main.app.test_client()

            def request(method, path, auth=token, data=None, status=200):
                response = client.open('/api' + path, method=method,
                    headers={'Authorization': 'Bearer ' + auth} if auth else {}, json=data)
                payload = response.get_json(silent=True)
                assert response.status_code == status, (method, path, response.status_code, payload)
                checks.append(f'{method} {path}: {status}')
                return payload.get('data') if payload else response.data.decode()

            request('GET', '/auth/me', auth=str(owner['id']), status=401)
            access = request('POST', '/accounting/branch-access', data={'branch_id': branch_id,
                'login': 'rollback_' + uuid.uuid4().hex, 'password': 'Rollback-only-2026'})
            request('POST', '/auth/login', auth=None, data={'login': access['login'], 'password': 'incorrect'}, status=401)
            login = request('POST', '/auth/login', auth=None, data={'login': access['login'], 'password': 'Rollback-only-2026'})
            assert 'password_hash' not in login['user']
            branch_token = login['token']
            request('GET', '/lessons', auth=branch_token, status=403)
            request('PUT', f'/lessons/{lesson_id}', auth=branch_token, data={'paid_children': 99}, status=403)
            overview = request('GET', '/portal/overview?month=2026-09', auth=branch_token)
            assert overview['branch']['id'] == branch_id
            assert overview['summary']['accrued_amount'] == 2100
            assert overview['summary']['total_children'] == 9
            assert overview['summary']['estimated_profit'] is None
            preview = request('GET', f'/accounting/invoices/report?month=2026-09&branch_id={branch_id}')
            assert preview['total_amount'] == 2100
            invoice_data = {'branch_id': branch_id, 'month': '2026-09', 'items': preview['items'],
                'seller_details': 'Synthetic test only', 'payment_details': 'Not a real invoice'}
            invoice = request('POST', '/accounting/invoices', data=invoice_data)
            invoice_id = invoice['id']
            request('POST', '/accounting/invoices', data=invoice_data, status=409)
            request('GET', f'/portal/invoices/{invoice_id}', auth=branch_token, status=404)
            invoice = request('POST', f'/accounting/invoices/{invoice_id}/issue', data={'revision': invoice['revision']})
            request('PUT', f'/accounting/invoices/{invoice_id}', data={'revision': invoice['revision'], 'title': 'changed'}, status=409)
            visible = request('GET', f'/portal/invoices/{invoice_id}', auth=branch_token)
            assert visible['total_amount'] == 2100
            with transaction_cursor() as (_, cur):
                cur.execute('UPDATE lessons SET paid_children=8 WHERE id=%s', (lesson_id,))
            visible = request('GET', f'/portal/invoices/{invoice_id}', auth=branch_token)
            assert visible['total_amount'] == 2100, 'Issued snapshot changed with lesson'
            document = request('GET', f'/portal/invoices/{invoice_id}/document', auth=branch_token)
            assert '2100.00' in document
            invoice = request('POST', f'/portal/invoices/{invoice_id}/report-payment', auth=branch_token,
                data={'revision': invoice['revision'], 'payment_date': '2026-09-11'})
            assert invoice['status'] == 'payment_reported'
            request('POST', f'/accounting/invoices/{invoice_id}/confirm-payment', auth=branch_token,
                data={'revision': invoice['revision']}, status=403)
            invoice = request('POST', f'/accounting/invoices/{invoice_id}/confirm-payment', data={'revision': invoice['revision']})
            assert invoice['status'] == 'paid'
            request('POST', f'/accounting/invoices/{invoice_id}/cancel', data={'revision': invoice['revision'], 'note': 'test'}, status=409)
            request('PUT', '/portal/pricing?month=2026-09', auth=branch_token, data={'retail_price_per_child': 600})
            overview = request('GET', '/portal/overview?month=2026-09', auth=branch_token)
            assert overview['summary']['estimated_revenue'] == 4800
            assert overview['summary']['estimated_profit'] == 2400
            other_month = request('GET', '/portal/pricing?month=2026-08', auth=branch_token)
            assert other_month['retail_price_per_child'] is None
            request('PUT', '/portal/pricing?month=2026-09', auth=branch_token, data={'retail_price_per_child': 0})
            zero = request('GET', '/portal/overview?month=2026-09', auth=branch_token)
            assert zero['summary']['estimated_profit'] == -2400
            request('PUT', f"/accounting/branch-access/{access['id']}", data={'is_active': False})
            request('GET', '/auth/me', auth=branch_token, status=401)
    finally:
        conn.rollback()
        conn.close()
        print('Transaction rolled back; no test rows or sessions committed.')
    print(f'Passed {len(checks)} HTTP checks against MySQL, including invoice snapshots and payment state.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rollback-only', action='store_true', required=True)
    parser.parse_args()
    run()
