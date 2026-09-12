"""Invoice lifecycle, monetary calculations, scopes and snapshots on an isolated SQLite DB."""
import os
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from decimal import Decimal
from unittest.mock import patch

from flask import request
import main
from shared import CurrentUser

sqlite3.register_adapter(date, lambda value:value.isoformat())
sqlite3.register_adapter(datetime, lambda value:value.isoformat(' '))
sqlite3.register_adapter(Decimal, lambda value:str(value))
sqlite3.register_converter('DATE',lambda value:date.fromisoformat(value.decode()))
sqlite3.register_converter('DATETIME',lambda value:datetime.fromisoformat(value.decode()))

SCHEMA = '''
CREATE TABLE departments(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE department_owners(department_id INTEGER,owner_id INTEGER);
CREATE TABLE branches(id INTEGER PRIMARY KEY,department_id INTEGER,name TEXT,address TEXT,price_per_child DECIMAL,is_active INTEGER);
CREATE TABLE teachers(id INTEGER PRIMARY KEY,full_name TEXT,color TEXT);
CREATE TABLE instructions(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE curriculum_lessons(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE lessons(id INTEGER PRIMARY KEY,branch_id INTEGER,teacher_id INTEGER,starts_at DATETIME,paid_children INTEGER,trial_children INTEGER,is_creative INTEGER,instruction_id INTEGER,curriculum_lesson_id INTEGER,price_snapshot DECIMAL);
CREATE TABLE auf_users(id INTEGER PRIMARY KEY AUTOINCREMENT,login TEXT UNIQUE,password_hash TEXT,role TEXT,branch_id INTEGER,owner_id INTEGER,teacher_id INTEGER,is_active INTEGER DEFAULT 1,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE auth_sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER,expires_at DATETIME);
CREATE TABLE branch_retail_prices(branch_id INTEGER,month TEXT,retail_price_per_child DECIMAL,updated_by_user_id INTEGER,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(branch_id,month));
CREATE TABLE branch_invoices(id INTEGER PRIMARY KEY AUTOINCREMENT,number TEXT UNIQUE,branch_id INTEGER,branch_name TEXT,month TEXT,title TEXT,status TEXT DEFAULT 'draft',total_amount DECIMAL,due_date DATE,note TEXT,seller_details TEXT,buyer_details TEXT,payment_details TEXT,revision INTEGER DEFAULT 1,created_by_user_id INTEGER,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,issued_at DATETIME,payment_reported_at DATETIME,payment_date DATE,payment_note TEXT,paid_at DATETIME,paid_by_user_id INTEGER,cancelled_at DATETIME);
CREATE UNIQUE INDEX uq_invoice_period ON branch_invoices(branch_id,month) WHERE status<>'cancelled';
CREATE TABLE branch_invoice_items(id INTEGER PRIMARY KEY AUTOINCREMENT,invoice_id INTEGER,sort_order INTEGER,lesson_id INTEGER,description TEXT,lesson_date DATETIME,teacher_name TEXT,quantity DECIMAL,unit_price DECIMAL,amount DECIMAL);
CREATE TABLE branch_invoice_events(id INTEGER PRIMARY KEY AUTOINCREMENT,invoice_id INTEGER,actor_user_id INTEGER,actor_name TEXT,action TEXT,note TEXT,created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE calendar_series(id INTEGER PRIMARY KEY,branch_id INTEGER);
CREATE TABLE calendar_versions(id INTEGER PRIMARY KEY,series_id INTEGER,effective_week DATE,weekday INTEGER,starts_at TEXT,duration_minutes INTEGER,teacher_id INTEGER,teacher_name TEXT,is_active INTEGER);
CREATE TABLE calendar_occurrences(id INTEGER PRIMARY KEY,series_id INTEGER,week_start DATE,version_id INTEGER,scheduled_starts_at DATETIME,starts_at DATETIME,duration_minutes INTEGER,planned_teacher_id INTEGER,planned_teacher_name TEXT,confirmed_teacher_id INTEGER,confirmed_teacher_name TEXT,is_override INTEGER,is_cancelled INTEGER,needs_replacement INTEGER,revision INTEGER,response_epoch INTEGER,note TEXT);
INSERT INTO departments VALUES(1,'Первый отдел'),(2,'Чужой отдел');
INSERT INTO department_owners VALUES(1,1),(2,2);
INSERT INTO branches VALUES(1,1,'Ромашка','Москва',300,1),(2,2,'Чужой сад','Казань',500,1),(3,1,'Свободный сад','Москва',400,1);
INSERT INTO teachers VALUES(1,'Анна','#123456');
INSERT INTO instructions VALUES(1,'Робот');
INSERT INTO lessons VALUES(1,1,1,'2026-09-07 10:00:00',10,2,0,1,NULL,300),(2,1,1,'2026-09-10 10:00:00',5,1,1,NULL,NULL,320),(3,2,1,'2026-09-10 10:00:00',8,0,0,1,NULL,500),(4,1,1,'2026-09-11 10:00:00',0,4,0,1,NULL,300);
INSERT INTO auf_users(id,login,password_hash,role,branch_id,is_active) VALUES(10,'garden','hidden','BRANCH',1,1),(20,'foreign','hidden','BRANCH',2,1);
INSERT INTO calendar_series VALUES(1,1),(2,2);
INSERT INTO calendar_versions VALUES(1,1,'2026-09-07',1,'10:00',60,1,'Анна',1),(2,2,'2026-09-07',1,'11:00',60,1,'Анна',1);
'''


class Cursor:
    def __init__(self,connection):
        self.cursor = connection.cursor()
    def execute(self,sql,params=()):
        self.cursor.execute(sql.replace('%s','?').replace(' FOR UPDATE',''),params)
    @property
    def lastrowid(self):
        return self.cursor.lastrowid
    def fetchone(self):
        row = self.cursor.fetchone()
        return dict(row) if row is not None else None
    def fetchall(self):
        return [dict(r) for r in self.cursor.fetchall()]


class BranchPortalTests(unittest.TestCase):
    def setUp(self):
        handle,self.path = tempfile.mkstemp(suffix='.sqlite')
        os.close(handle)
        with sqlite3.connect(self.path) as db:
            db.executescript(SCHEMA)
        self.client = main.app.test_client()
        self.patches = [patch('blueprints.branch_portal.db_cursor',self.database),patch('main.db_cursor',self.database),
            patch('main.get_current_user',self.user),patch('shared.get_current_user',self.user),
            patch('blueprints.branch_portal.now',return_value=datetime(2026,9,12,12))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        os.unlink(self.path)

    @contextmanager
    def database(self):
        db = sqlite3.connect(self.path,timeout=10,detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db,Cursor(db)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def user(self):
        who = request.headers.get('X-Test-User','owner')
        if who.startswith('owner'):
            return CurrentUser(1 if who=='owner' else 2,'OWNER',1 if who=='owner' else 2,None,who)
        if who=='teacher':
            return CurrentUser(3,'TEACHER',None,1,'teacher')
        return CurrentUser(10 if who=='branch' else 20,'BRANCH',None,None,who,1 if who=='branch' else 2)

    def call(self,method,path,data=None,user='owner',code=200):
        response = self.client.open('/api'+path,method=method,json=data,headers={'X-Test-User':user})
        self.assertEqual(response.status_code,code,response.get_data(as_text=True))
        return (response.get_json() or {}).get('data')

    def draft(self,branch=1,month='2026-09',**values):
        data = dict(branch_id=branch,month=month,title='Занятия',seller_details='Исполнитель',payment_details='Банк, счёт 123',
            items=[dict(lesson_id=1,description='Робот',lesson_date='2026-09-07T10:00:00',teacher_name='Анна',quantity=10,unit_price=300)])
        data.update(values)
        return self.call('POST','/accounting/invoices',data)

    def action(self,row,action,**values):
        return self.call('POST',f"/accounting/invoices/{row['id']}/{action}",dict(revision=row['revision'],**values))

    def test_lifecycle_snapshot_and_payment_confirmation(self):
        row = self.draft()
        self.assertEqual(row['total_amount'],3000)
        self.call('GET',f"/portal/invoices/{row['id']}",user='branch',code=404)
        self.assertEqual(self.call('GET','/portal/invoices',user='branch')['items'],[])
        row = self.action(row,'issue')
        with self.database() as (_,cur):
            cur.execute('UPDATE lessons SET paid_children=1 WHERE id=1')
        issued = self.call('GET',f"/portal/invoices/{row['id']}",user='branch')
        self.assertEqual((issued['total_amount'],issued['items'][0]['quantity']),(3000,10))
        self.call('PUT',f"/accounting/invoices/{row['id']}",dict(revision=row['revision'],title='Changed'),code=409)
        row = self.call('POST',f"/portal/invoices/{row['id']}/report-payment",dict(revision=row['revision'],payment_date='2026-09-11',note='Перевели'),user='branch')
        self.assertEqual(row['status'],'payment_reported')
        overview = self.call('GET','/portal/overview?month=2026-09',user='branch')
        self.assertEqual((overview['summary']['paid_amount'],overview['summary']['outstanding_amount']),(0,3000))
        self.call('POST',f"/portal/invoices/{row['id']}/report-payment",dict(revision=row['revision']),user='branch',code=409)
        row = self.action(row,'confirm-payment')
        self.assertEqual(row['status'],'paid')
        self.assertEqual([e['action'] for e in row['events']],['created','issued','payment_reported','paid'])
        self.call('POST',f"/accounting/invoices/{row['id']}/cancel",dict(revision=row['revision'],note='Нет'),code=409)

    def test_scopes_and_generic_legacy_routes_are_closed(self):
        row = self.draft()
        row = self.action(row,'issue')
        for suffix in ('','/document'):
            self.call('GET',f"/portal/invoices/{row['id']}{suffix}",user='branch2',code=404)
            self.call('GET',f"/accounting/invoices/{row['id']}{suffix}",user='owner2',code=404)
        self.call('POST',f"/portal/invoices/{row['id']}/report-payment",dict(revision=2),user='branch2',code=404)
        for route in ('/users','/teachers/1','/instructions','/lessons','/calendar/week?start=2026-09-14','/accounting/invoices','/accounting/branch-access'):
            self.call('GET',route,user='branch',code=403)
        self.call('GET','/accounting/invoices',user='teacher',code=403)
        self.call('GET','/portal/overview?branch_id=2&month=2026-09',user='branch')
        for verb,path,data in [('GET','/users/20',None),('PUT','/users/20',{'password':'new-secret'}),('PUT','/users/20/activate',{}),('DELETE','/users/20',None)]:
            self.call(verb,path,data,code=403)

    def test_preview_pricing_profit_and_read_only_upcoming(self):
        preview = self.call('GET','/accounting/invoices/report?branch_id=1&month=2026-09')
        self.assertEqual((len(preview['items']),preview['total_amount']),(2,4600))
        self.call('GET','/accounting/invoices/report?branch_id=2&month=2026-09',code=404)
        data = self.call('GET','/portal/overview?month=2026-09',user='branch')
        self.assertEqual((data['summary']['lessons_count'],data['summary']['total_children'],data['summary']['accrued_amount']),(3,22,4600))
        self.assertIsNone(data['summary']['estimated_profit'])
        self.assertEqual(len(data['upcoming']),3)
        self.call('PUT','/portal/pricing?month=2026-09',{'retail_price_per_child':500},user='branch')
        data = self.call('GET','/portal/overview?month=2026-09',user='branch')
        self.assertEqual((data['summary']['estimated_revenue'],data['summary']['estimated_profit']),(7500,2900))
        self.assertEqual({l['id']:l['estimated_profit'] for l in data['lessons']},{1:2000,2:900,4:0})
        self.assertIsNone(self.call('GET','/portal/pricing?month=2026-10',user='branch')['retail_price_per_child'])
        self.call('PUT','/portal/pricing?month=2026-09',{'retail_price_per_child':None},user='branch')
        self.assertIsNone(self.call('GET','/portal/pricing?month=2026-09',user='branch')['retail_price_per_child'])
        with self.database() as (_,cur):
            cur.execute('SELECT COUNT(*) n FROM calendar_occurrences')
            self.assertEqual(cur.fetchone()['n'],0)

    def test_duplicate_month_cancel_and_stale_revision(self):
        row = self.draft()
        self.call('POST','/accounting/invoices',dict(branch_id=1,month='2026-09',items=[]),code=409)
        self.call('PUT',f"/accounting/invoices/{row['id']}",dict(revision=99,title='Stale'),code=409)
        row = self.action(row,'cancel',note='Ошибка в сумме')
        self.assertEqual(row['status'],'cancelled')
        self.assertEqual(self.call('GET','/portal/invoices',user='branch')['items'],[])
        self.assertEqual(self.draft()['status'],'draft')

    def test_rejection_requires_reason_and_can_report_again(self):
        row = self.action(self.draft(),'issue')
        row = self.call('POST',f"/portal/invoices/{row['id']}/report-payment",dict(revision=2),user='branch')
        self.call('POST',f"/accounting/invoices/{row['id']}/reject-payment",dict(revision=row['revision']),code=400)
        row = self.action(row,'reject-payment',note='Платёж не поступил')
        self.assertEqual(row['status'],'issued')
        row = self.call('POST',f"/portal/invoices/{row['id']}/report-payment",dict(revision=row['revision']),user='branch')
        self.assertEqual(row['status'],'payment_reported')

    def test_input_validation_money_and_cross_branch_lesson(self):
        for value in (-1,'NaN','Infinity',True):
            self.call('PUT','/portal/pricing?month=2026-09',dict(retail_price_per_child=value),user='branch',code=400)
        self.call('GET','/portal/overview?month=2026-13',user='branch',code=400)
        self.call('POST','/accounting/invoices',dict(branch_id=1,month='2026-09',items=[dict(lesson_id=3,description='Чужое',quantity=1,unit_price=100)]),code=400)
        row = self.draft(items=[dict(description='Дробная сумма',quantity=3,unit_price=0.1)])
        self.assertEqual(row['total_amount'],0.3)
        row = self.call('PUT',f"/accounting/invoices/{row['id']}",dict(revision=1,payment_details=''))
        self.call('POST',f"/accounting/invoices/{row['id']}/issue",dict(revision=row['revision']),code=400)

    def test_access_accounts_scoped_and_session_revoked_on_reset(self):
        listed = self.call('GET','/accounting/branch-access')['items']
        self.assertEqual([u['id'] for u in listed],[10])
        self.call('PUT','/accounting/branch-access/20',dict(is_active=False),code=404)
        self.call('POST','/accounting/branch-access',dict(branch_id=2,login='new',password='strong-pass'),code=404)
        self.call('POST','/accounting/branch-access',dict(branch_id=1,login='new',password='strong-pass'),code=409)
        row = self.call('POST','/accounting/branch-access',dict(branch_id=3,login='new',password='strong-pass'))
        self.assertNotIn('password_hash',row)
        with self.database() as (_,cur):
            cur.execute('SELECT password_hash FROM auf_users WHERE id=%s',(row['id'],))
            self.assertTrue(cur.fetchone()['password_hash'].startswith('scrypt:'))
            cur.execute("INSERT INTO auth_sessions VALUES('session',%s,'2026-10-01')",(row['id'],))
        self.call('PUT',f"/accounting/branch-access/{row['id']}",dict(password='updated-pass'))
        with self.database() as (_,cur):
            cur.execute('SELECT COUNT(*) n FROM auth_sessions')
            self.assertEqual(cur.fetchone()['n'],0)
        self.call('PUT',f"/accounting/branch-access/{row['id']}",dict(branch_id=1),code=400)

    def test_concurrent_confirm_only_one_transition(self):
        row = self.action(self.draft(),'issue')
        def confirm(_):
            with main.app.test_client() as client:
                return client.post(f"/api/accounting/invoices/{row['id']}/confirm-payment",json=dict(revision=row['revision'])).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(confirm,range(2))),[200,409])
        with self.database() as (_,cur):
            cur.execute("SELECT COUNT(*) n FROM branch_invoice_events WHERE action='paid'")
            self.assertEqual(cur.fetchone()['n'],1)

    def test_print_escapes_untrusted_text(self):
        row = self.draft(title='<script>alert(1)</script>')
        row = self.action(row,'issue')
        response = self.client.get(f"/api/portal/invoices/{row['id']}/document",headers={'X-Test-User':'branch'})
        self.assertEqual(response.status_code,200)
        text = response.get_data(as_text=True)
        self.assertNotIn('<script>',text)
        self.assertIn('&lt;script&gt;',text)
        self.assertIn('Банк, счёт 123',text)


if __name__=='__main__':
    unittest.main()
