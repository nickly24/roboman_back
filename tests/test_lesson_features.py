"""Help and curriculum workflows against an isolated transactional database.

MySQL view/trigger parity is separately verified by scripts/verify_lesson_help_mysql.py.
"""
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
from unittest.mock import patch

from flask import request
import main
from shared import CurrentUser

SCHEMA = '''
CREATE TABLE departments(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE department_owners(department_id INTEGER,owner_id INTEGER);
CREATE TABLE branches(id INTEGER PRIMARY KEY,department_id INTEGER,name TEXT,price_per_child NUMERIC,teacher_base_rate INTEGER);
CREATE TABLE teachers(id INTEGER PRIMARY KEY,full_name TEXT,color TEXT,status TEXT,is_salary_free INTEGER);
CREATE TABLE branch_teachers(branch_id INTEGER,teacher_id INTEGER);
CREATE TABLE settings(`key` TEXT PRIMARY KEY,value_int INTEGER,value_decimal NUMERIC,value_bool INTEGER,value_text TEXT,description TEXT);
CREATE TABLE instructions(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE curriculum_plans(id INTEGER PRIMARY KEY,name TEXT,description TEXT);
CREATE TABLE curriculum_modules(id INTEGER PRIMARY KEY,plan_id INTEGER,name TEXT,sort_order INTEGER);
CREATE TABLE lesson_formats(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE curriculum_lessons(id INTEGER PRIMARY KEY,module_id INTEGER,name TEXT,internal_description TEXT,external_description TEXT,format_id INTEGER,instruction_id INTEGER,sort_order INTEGER,created_at TEXT,updated_at TEXT);
CREATE TABLE curriculum_lesson_images(id INTEGER PRIMARY KEY,lesson_id INTEGER,filename TEXT,mime TEXT,sort_order INTEGER);
CREATE TABLE curriculum_lesson_comments(id INTEGER PRIMARY KEY,lesson_id INTEGER);
CREATE TABLE instruction_comments(id INTEGER PRIMARY KEY,instruction_id INTEGER);
CREATE TABLE branch_curriculum_runs(id INTEGER PRIMARY KEY,branch_id INTEGER,plan_id INTEGER,is_active INTEGER);
CREATE TABLE lessons(id INTEGER PRIMARY KEY AUTOINCREMENT,branch_id INTEGER,teacher_id INTEGER,starts_at TEXT,
 paid_children INTEGER DEFAULT 0,trial_children INTEGER DEFAULT 0,is_creative INTEGER DEFAULT 0,instruction_id INTEGER,
 curriculum_run_id INTEGER,curriculum_lesson_id INTEGER,curriculum_mode TEXT,skipped_curriculum_lesson_id INTEGER,
 lesson_type TEXT DEFAULT 'LESSON',help_rate_snapshot NUMERIC,is_salary_free INTEGER DEFAULT 0,is_fixed_salary_2000 INTEGER DEFAULT 0,
 price_snapshot NUMERIC,created_by_user_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE VIEW v_lessons_calc AS SELECT l.*,paid_children+trial_children AS total_children,
 paid_children*price_snapshot AS revenue,
 CASE WHEN l.is_salary_free=1 THEN 0 WHEN l.lesson_type='HELP' THEN help_rate_snapshot
 WHEN l.is_fixed_salary_2000=1 THEN 2000
 ELSE b.teacher_base_rate + MAX(0,paid_children+trial_children-(SELECT value_int FROM settings WHERE `key`='teacher_threshold_children')) *
 (SELECT value_int FROM settings WHERE `key`='teacher_bonus_per_child') END AS teacher_salary
 FROM lessons l JOIN branches b ON b.id=l.branch_id;
INSERT INTO departments VALUES(1,'Наш отдел'),(2,'Чужой отдел');
INSERT INTO department_owners VALUES(1,1),(2,2);
INSERT INTO branches VALUES(1,1,'Ромашка',300,1200),(2,2,'Чужой сад',400,1200);
INSERT INTO teachers VALUES(1,'Анна','#123456','working',0),(2,'Борис','#234567','working',0),(3,'Без оплаты','#345678','working',1);
INSERT INTO branch_teachers VALUES(1,1),(1,2),(1,3),(2,2);
INSERT INTO settings(`key`,value_int) VALUES('teacher_base_rate',1200),('teacher_threshold_children',8),('teacher_bonus_per_child',100),('teacher_help_rate',500);
INSERT INTO instructions VALUES(1,'Робот'),(2,'Карусель');
INSERT INTO curriculum_plans VALUES(1,'План','Описание');
INSERT INTO lesson_formats VALUES(1,'Конструирование');
INSERT INTO curriculum_modules VALUES(1,1,'Модуль 1',1),(2,1,'Модуль 2',2);
INSERT INTO curriculum_lessons(id,module_id,name,format_id,instruction_id,sort_order) VALUES
 (1,1,'Первый',1,1,1),(2,2,'Второй',1,2,1),(3,2,'Третий',1,NULL,2),(4,2,'Четвёртый',1,1,3);
'''


class Cursor:
    def __init__(self, db):
        self.cursor = db.cursor()

    def execute(self, sql, params=()):
        sql = sql.replace('%s', '?').replace(' FOR UPDATE', '')
        sql = sql.replace('ON DUPLICATE KEY UPDATE', 'ON CONFLICT(`key`) DO UPDATE SET')
        for field in ['value_int', 'value_decimal', 'value_bool', 'value_text', 'description']:
            sql = sql.replace(f'VALUES({field})', f'excluded.{field}')
        self.cursor.execute(sql, params)

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    def fetchone(self):
        row = self.cursor.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(row) for row in self.cursor.fetchall()]


class LessonFeatureTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix='.sqlite')
        os.close(handle)
        with sqlite3.connect(self.path) as db:
            db.executescript(SCHEMA)
        self.client = main.app.test_client()
        self.patches = [patch('main.db_cursor', self.database), patch('blueprints.curriculum.db_cursor', self.database),
                        patch('main.get_current_user', self.user), patch('shared.get_current_user', self.user)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        os.unlink(self.path)

    @contextmanager
    def database(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.create_function('DATE_FORMAT', 2, lambda value, pattern: datetime.fromisoformat(value).strftime(pattern.replace('%%', '%')))
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db, Cursor(db)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def user(self):
        who = request.headers.get('X-Test-User', 'owner')
        if who.startswith('owner'):
            return CurrentUser(1, 'OWNER', 2 if who == 'owner2' else 1, None, who)
        if who == 'branch':
            return CurrentUser(4, 'BRANCH', None, None, who, 1)
        return CurrentUser(2, 'TEACHER', None, 2 if who == 'teacher2' else 1, who)

    def call(self, method, path, body=None, user='owner', code=200):
        response = self.client.open('/api' + path, method=method, json=body, headers={'X-Test-User': user})
        self.assertEqual(response.status_code, code, response.get_data(as_text=True))
        return (response.get_json() or {}).get('data')

    def help(self, **values):
        data = dict(lesson_type='HELP', branch_id=1, teacher_id=1, starts_at='2026-09-10T00:00')
        data.update(values)
        return data

    def lesson(self, **values):
        data = dict(branch_id=1, teacher_id=1, starts_at='2026-09-11T10:30', paid_children=10, trial_children=2, is_creative=True)
        data.update(values)
        return data

    def plan(self):
        with self.database() as (_, cur):
            cur.execute('INSERT INTO branch_curriculum_runs VALUES(1,1,1,1)')

    def progress(self):
        return self.call('GET', '/branches/1/curriculum')

    def test_help_is_independent_of_curriculum_and_has_snapshot(self):
        self.plan()
        row = self.call('POST', '/lessons', self.help())
        self.assertEqual(row['lesson_type'], 'HELP')
        self.assertEqual(row['teacher_salary'], 500)
        self.assertEqual(row['help_rate_snapshot'], 500)
        self.assertEqual(row['revenue'], 0)
        self.assertEqual(row['total_children'], 0)
        for key in ['instruction_id', 'curriculum_run_id', 'curriculum_mode', 'curriculum_lesson_id', 'skipped_curriculum_lesson_id']:
            self.assertIsNone(row[key])
        self.assertEqual(self.progress()['current_lesson']['id'], 1)
        self.call('PUT', '/settings/teacher_help_rate', {'value_int': 750})
        self.assertEqual(self.call('GET', f"/lessons/{row['id']}")['teacher_salary'], 500)
        self.assertEqual(self.call('POST', '/lessons', self.help())['teacher_salary'], 750)
        self.assertEqual(self.call('PUT', f"/lessons/{row['id']}", {'starts_at': '2026-09-16T00:00'})['help_rate_snapshot'], 500)
        self.call('POST', f"/lessons/{row['id']}/reprice", {}, code=409)

    def test_help_cannot_accept_children_topic_or_client_snapshot(self):
        for fields in [{'paid_children': 2}, {'trial_children': 1}, {'instruction_id': 1}, {'is_creative': True},
                       {'curriculum_mode': 'PLAN'}, {'is_fixed_salary_2000': True}, {'help_rate_snapshot': 1},
                       {'skipped_curriculum_lesson_id': 1}, {'price_snapshot': 50}, {'lesson_type': 'unknown'}]:
            with self.subTest(fields=fields):
                self.call('POST', '/lessons', self.help(**fields), code=400)
        self.assertEqual(self.call('GET', '/lessons')['items'], [])

    def test_help_edits_preserve_type_and_amount_and_allow_teacher_date(self):
        row = self.call('POST', '/lessons', self.help())
        path = f"/lessons/{row['id']}"
        self.call('PUT', path, {'starts_at': '2026-09-12T00:00'}, user='teacher')
        for fields in [{'paid_children': 1}, {'instruction_id': 1}, {'price_snapshot': 300}, {'help_rate_snapshot': 10}, {'curriculum_mode': 'PLAN'}]:
            self.call('PUT', path, fields, code=400)
        self.call('PUT', path, {'lesson_type': 'LESSON'}, code=409)
        self.assertEqual(self.call('GET', path)['help_rate_snapshot'], 500)

    def test_salary_free_help_keeps_rate_but_no_salary(self):
        row = self.call('POST', '/lessons', self.help(teacher_id=3))
        self.assertEqual(row['help_rate_snapshot'], 500)
        self.assertEqual(row['teacher_salary'], 0)
        self.assertEqual(self.call('PUT', f"/lessons/{row['id']}/salary-paid", {})['teacher_salary'], 500)

    def test_settings_require_admin_and_nonnegative_integer_rate(self):
        for value in [-1, 0.5, 'NaN', 'Infinity', '', None, True, 100000000]:
            with self.subTest(value=value):
                self.call('PUT', '/settings/teacher_help_rate', {'value_int': value}, code=400)
        self.call('PUT', '/settings/teacher_help_rate', {'value_int': 100}, user='teacher', code=403)
        self.call('PUT', '/settings/teacher_help_rate', {'value_int': 0})
        self.assertEqual(self.call('POST', '/lessons', self.help())['teacher_salary'], 0)

    def test_salary_settings_roundtrip_and_legacy_update_keep_help_rate(self):
        data = dict(teacher_base_rate=1200, teacher_threshold_children=8, teacher_bonus_per_child=100, teacher_help_rate=650)
        items = self.call('PUT', '/settings/salary', data)['items']
        self.assertEqual({r['key']: r['value_int'] for r in items}['teacher_help_rate'], 650)
        del data['teacher_help_rate']
        self.call('PUT', '/settings/salary', data)
        self.assertEqual(self.call('GET', '/settings/teacher_help_rate')['value_int'], 650)
        self.call('PUT', '/settings/salary', {**data, 'teacher_help_rate': -3}, code=400)

    def test_missing_help_rate_requires_configuration(self):
        with self.database() as (_, cur):
            cur.execute("UPDATE settings SET value_int=NULL WHERE `key`='teacher_help_rate'")
        self.call('POST', '/lessons', self.help(), code=409)
        self.assertEqual(self.call('GET', '/lessons')['items'], [])

    def test_help_permissions_and_owner_scopes(self):
        row = self.call('POST', '/lessons', self.help(teacher_id=2), user='teacher')
        self.assertEqual(row['teacher_id'], 1)
        path = f"/lessons/{row['id']}"
        self.call('GET', path, user='teacher2', code=404)
        self.call('GET', path, user='owner2', code=404)
        self.call('PUT', path, {'starts_at': '2026-09-12T00:00'}, user='teacher2', code=403)
        self.call('DELETE', path, user='teacher', code=403)
        self.call('POST', '/lessons', self.help(branch_id=2), user='teacher', code=403)
        self.call('POST', '/lessons', self.help(branch_id=2), code=403)
        self.call('POST', '/lessons', self.help(), user='branch', code=403)
        self.call('PUT', path, {'starts_at': '2026-09-12T00:00'}, user='owner2', code=404)

    def test_help_in_salary_and_dashboard_without_distorting_attendance(self):
        self.call('POST', '/lessons', self.lesson())  # 1200 + 4*100 = 1600
        self.call('POST', '/lessons', self.help())
        self.call('POST', '/lessons', self.help(starts_at='2026-09-20T00:00'))
        month = '?month=2026-09'
        owner = self.call('GET', '/salary/owner-by-department' + month)['by_department'][0]
        self.assertEqual(owner['department_total'], 2600)
        teacher = owner['teachers'][0]
        self.assertEqual((teacher['lessons_count'], teacher['help_count'], teacher['records_count']), (1, 2, 3))
        self.assertEqual((teacher['salary_1_15'], teacher['salary_16_end']), (2100, 500))
        self.assertEqual((teacher['lessons_1_15'], teacher['lessons_16_end'], teacher['help_1_15'], teacher['help_16_end']), (1, 0, 1, 1))
        self.assertEqual(self.call('GET', '/salary/teacher-by-department' + month, user='teacher')['total_salary'], 2600)
        owner_kpi = self.call('GET', '/dashboard/owner' + month)['kpi']
        self.assertEqual((owner_kpi['revenue_sum'], owner_kpi['avg_children_per_lesson']), (3000, 12))
        self.assertEqual((owner_kpi['lessons_count'], owner_kpi['help_count'], owner_kpi['help_salary_sum']), (1, 2, 1000))
        teacher_dash = self.call('GET', '/dashboard/teacher' + month, user='teacher')
        self.assertEqual(teacher_dash['kpi']['salary_sum'], 2600)
        self.assertEqual(teacher_dash['total']['total_help_count'], 2)
        self.assertEqual(self.call('GET', '/reports/teacher/1/summary' + month)['kpi']['salary_sum'], 2600)
        self.assertEqual(self.call('GET', '/reports/revenue-by-month' + month)['items'][0]['help_count'], 2)
        self.assertEqual(self.call('GET', '/reports/attendance-by-month' + month)['items'][0]['total_children_sum'], 12)

    def test_only_help_month_and_empty_month_have_zero_lesson_averages(self):
        self.call('POST', '/lessons', self.help())
        kpi = self.call('GET', '/dashboard/owner?month=2026-09')['kpi']
        self.assertEqual((kpi['lessons_count'], kpi['help_count'], kpi['avg_children_per_lesson']), (0, 1, 0))
        self.assertEqual(self.call('GET', '/salary/owner-by-department?month=2026-10')['by_department'], [])

    def test_csv_and_type_filter_distinguish_help(self):
        self.call('POST', '/lessons', self.help())
        self.call('POST', '/lessons', self.lesson())
        self.assertEqual(len(self.call('GET', '/lessons?lesson_type=HELP')['items']), 1)
        self.assertEqual(self.call('GET', '/lessons?is_creative=0')['items'], [])
        response = self.client.get('/api/lessons/export.csv')
        self.assertEqual(response.status_code, 200)
        import csv, io
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        row = next(r for r in rows if r['lesson_type'] == 'HELP')
        self.assertEqual(row['help_rate_snapshot'], '500')
        self.assertEqual(row['paid_children'], '')
        self.assertEqual(row['teacher_salary'], '500')
        filtered = self.client.get('/api/lessons/export.csv?lesson_type=HELP')
        filtered_rows = list(csv.DictReader(io.StringIO(filtered.get_data(as_text=True))))
        self.assertEqual([r['lesson_type'] for r in filtered_rows], ['HELP'])
        filtered = self.client.get('/api/lessons/export.csv?is_creative=1')
        self.assertEqual(len(list(csv.DictReader(io.StringIO(filtered.get_data(as_text=True))))), 1)

    def skip_body(self, **values):
        return self.lesson(curriculum_mode='SKIP_TO_NEXT', curriculum_lesson_id=2, curriculum_expected_lesson_id=1, **values)

    def test_skip_records_next_topic_closes_both_steps_and_delete_restores(self):
        self.plan()
        progress = self.progress()
        self.assertEqual((progress['current_lesson']['id'], progress['next_lesson']['id']), (1, 2))
        row = self.call('POST', '/lessons', self.skip_body())
        self.assertEqual((row['instruction_id'], row['curriculum_lesson_id'], row['skipped_curriculum_lesson_id']), (2, 2, 1))
        progress = self.progress()
        self.assertEqual((progress['closed_lessons'], progress['current_lesson']['id']), (2, 3))
        self.call('POST', '/lessons', self.skip_body(), code=409)
        self.call('DELETE', f"/lessons/{row['id']}")
        self.assertEqual(self.progress()['closed_lessons'], 0)
        self.assertEqual(self.progress()['current_lesson']['id'], 1)

    def test_skip_validates_next_last_completed_and_no_plan(self):
        self.call('POST', '/lessons', self.skip_body(), code=400)
        self.plan()
        self.call('POST', '/lessons', self.lesson(curriculum_mode='SKIP_TO_NEXT', curriculum_lesson_id=3), code=409)
        self.call('POST', '/lessons', self.lesson(curriculum_mode='SKIP_TO_NEXT'), code=400)
        self.call('POST', '/lessons', self.skip_body())
        self.call('POST', '/lessons', self.lesson(curriculum_mode='PLAN', curriculum_lesson_id=3))
        self.assertIsNone(self.progress()['next_lesson'])
        self.call('POST', '/lessons', self.lesson(curriculum_mode='SKIP_TO_NEXT', curriculum_lesson_id=4), code=400)
        self.call('POST', '/lessons', self.lesson(curriculum_mode='PLAN', curriculum_lesson_id=4))
        self.assertTrue(self.progress()['is_completed'])
        self.call('POST', '/lessons', self.lesson(curriculum_mode='SKIP_TO_NEXT', curriculum_lesson_id=4), code=400)

    def test_invalid_curriculum_ids_are_bad_requests(self):
        self.plan()
        for field in ['curriculum_lesson_id', 'curriculum_expected_lesson_id']:
            for invalid in ['abc', [], 0, -1]:
                with self.subTest(field=field, invalid=invalid):
                    body = self.skip_body()
                    body[field] = invalid
                    self.call('POST', '/lessons', body, code=400)

    def test_plan_replace_pause_and_repeat_remain_supported(self):
        self.plan()
        self.call('POST', '/lessons', self.lesson(curriculum_mode='OFF_PLAN_PAUSE'))
        self.assertEqual(self.progress()['closed_lessons'], 0)
        self.call('POST', '/lessons', self.lesson(curriculum_mode='OFF_PLAN_REPLACE'))
        self.assertEqual(self.progress()['current_lesson']['id'], 2)
        self.call('POST', '/lessons', self.lesson(curriculum_mode='REPEAT', curriculum_lesson_id=1))
        self.assertEqual(self.progress()['current_lesson']['id'], 2)
        self.call('POST', '/lessons', self.lesson(curriculum_mode='PLAN', curriculum_lesson_id=2))
        self.assertEqual(self.progress()['current_lesson']['id'], 3)

    def test_skipped_step_module_cannot_be_deleted_or_reordered(self):
        self.plan()
        self.call('POST', '/lessons', self.skip_body())
        self.call('DELETE', '/curriculum-modules/1', code=409)
        self.call('DELETE', '/curriculum-lessons/1', code=409)
        self.call('PUT', '/curriculum-plans/1/modules/reorder', {'module_ids': [2, 1]}, code=409)

    def test_concurrent_skip_submissions_only_record_one_jump(self):
        self.plan()
        def submit(_):
            with main.app.test_client() as client:
                return client.post('/api/lessons', json=self.skip_body()).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(submit, [1, 2]))
        self.assertEqual(sorted(statuses), [200, 409])
        self.assertEqual(self.progress()['closed_lessons'], 2)
        self.assertEqual(len(self.call('GET', '/lessons')['items']), 1)


if __name__ == '__main__':
    unittest.main()
