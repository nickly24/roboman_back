"""API integration tests on an isolated SQLite database, never production data.
The adapter changes placeholders/locking syntax only. BEGIN IMMEDIATE serializes
SQLite writers; production uses an InnoDB series row lock for the same boundary.
"""
import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import date, datetime
from unittest.mock import patch

from flask import Flask, request
from shared import CurrentUser
from blueprints import calendar as calendar

sqlite3.register_adapter(date, lambda value: value.isoformat())
sqlite3.register_adapter(datetime, lambda value: value.isoformat(' '))
sqlite3.register_converter('DATE', lambda value: date.fromisoformat(value.decode()))
sqlite3.register_converter('DATETIME', lambda value: datetime.fromisoformat(value.decode()))

SCHEMA = '''
CREATE TABLE departments(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE department_owners(department_id INTEGER,owner_id INTEGER);
CREATE TABLE branches(id INTEGER PRIMARY KEY,department_id INTEGER,name TEXT,address TEXT,is_active INTEGER);
CREATE TABLE teachers(id INTEGER PRIMARY KEY,full_name TEXT,color TEXT,status TEXT);
CREATE TABLE branch_teachers(branch_id INTEGER,teacher_id INTEGER);
CREATE TABLE calendar_series(id INTEGER PRIMARY KEY AUTOINCREMENT,branch_id INTEGER,legacy_schedule_id INTEGER UNIQUE,request_key TEXT UNIQUE,revision INTEGER DEFAULT 1);
CREATE TABLE calendar_versions(id INTEGER PRIMARY KEY AUTOINCREMENT,series_id INTEGER,effective_week DATE,weekday INTEGER,starts_at TEXT,duration_minutes INTEGER,teacher_id INTEGER,teacher_name TEXT,is_active INTEGER DEFAULT 1);
CREATE TABLE calendar_occurrences(id INTEGER PRIMARY KEY AUTOINCREMENT,series_id INTEGER,week_start DATE,version_id INTEGER,scheduled_starts_at DATETIME,starts_at DATETIME,duration_minutes INTEGER,planned_teacher_id INTEGER,planned_teacher_name TEXT,confirmed_teacher_id INTEGER,confirmed_teacher_name TEXT,is_override INTEGER DEFAULT 0,is_cancelled INTEGER DEFAULT 0,needs_replacement INTEGER DEFAULT 0,revision INTEGER DEFAULT 1,response_epoch INTEGER DEFAULT 1,note TEXT DEFAULT '',UNIQUE(series_id,week_start));
CREATE TABLE calendar_responses(id INTEGER PRIMARY KEY AUTOINCREMENT,occurrence_id INTEGER,teacher_id INTEGER,teacher_name TEXT,answer TEXT,reason TEXT,response_epoch INTEGER,created_at DATETIME,actor_user_id INTEGER,actor_name TEXT,actor_role TEXT DEFAULT 'TEACHER');
CREATE TABLE curriculum_plans(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE lesson_formats(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE curriculum_modules(id INTEGER PRIMARY KEY,plan_id INTEGER,name TEXT,sort_order INTEGER);
CREATE TABLE instructions(id INTEGER PRIMARY KEY,name TEXT);
CREATE TABLE curriculum_lessons(id INTEGER PRIMARY KEY,module_id INTEGER,name TEXT,sort_order INTEGER,format_id INTEGER,instruction_id INTEGER);
CREATE TABLE branch_curriculum_runs(id INTEGER PRIMARY KEY,branch_id INTEGER,plan_id INTEGER,is_active INTEGER);
CREATE TABLE lessons(id INTEGER PRIMARY KEY,branch_id INTEGER,starts_at DATETIME,teacher_id INTEGER,instruction_id INTEGER,is_creative INTEGER DEFAULT 0,curriculum_run_id INTEGER,curriculum_lesson_id INTEGER,curriculum_mode TEXT);
CREATE TABLE calendar_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,series_id INTEGER,occurrence_id INTEGER,actor_user_id INTEGER,actor_name TEXT,action TEXT,details_json TEXT,created_at DATETIME);
INSERT INTO departments VALUES(1,'Первый'),(2,'Чужой');
INSERT INTO department_owners VALUES(1,1),(2,2);
INSERT INTO branches VALUES(1,1,'Сад 1','Адрес',1),(2,2,'Чужой сад','Адрес 2',1),(3,1,'Сад 3','Адрес 3',1);
INSERT INTO teachers VALUES(1,'Анна','#123456','working'),(2,'Борис','#345678','working'),(3,'Виктор','#567890','working'),(4,'Уволен','#123456','fired'),(5,'Свободный','#123456','working');
INSERT INTO branch_teachers VALUES(1,1),(1,2),(1,4),(2,3),(3,1);
'''


class Cursor:
    def __init__(self, conn):
        self.cursor = conn.cursor()

    def execute(self, sql, params=()):
        self.cursor.execute(sql.replace('%s','?').replace(' FOR UPDATE',''), params)

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    def fetchone(self):
        row = self.cursor.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(row) for row in self.cursor.fetchall()]


class CalendarTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix='.sqlite')
        os.close(handle)
        with sqlite3.connect(self.path) as db:
            db.executescript(SCHEMA)
        app = Flask(__name__)
        app.register_blueprint(calendar.bp, url_prefix='/api/calendar')
        app.testing = True
        self.app = app
        self.client = app.test_client()
        self.patches = [patch('blueprints.calendar.db_cursor',self.database),patch('shared.get_current_user',self.user),patch('blueprints.calendar.now',return_value=datetime(2026,9,11,9))]
        for p in self.patches:
            p.start()
        self.series = self.create()

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
            yield db, Cursor(db)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def user(self):
        who = request.headers.get('X-Test-User','owner')
        return CurrentUser(10 if who=='owner' else int(who),'OWNER' if who=='owner' else 'TEACHER',1 if who=='owner' else None,None if who=='owner' else int(who),who)

    def call(self,method,path,data=None,user='owner',code=200):
        response = self.client.open('/api/calendar'+path,method=method,json=data,headers={'X-Test-User':user})
        self.assertEqual(response.status_code,code,response.get_data(as_text=True))
        return response.get_json().get('data')

    def create(self,start='2026-09-14T10:00',branch=1,key='test-request-key-0001',teacher=1):
        return self.call('POST','/series',dict(branch_id=branch,starts_at=start,duration_minutes=60,teacher_id=teacher,request_key=key))['series_id']

    def detail(self,week='2026-09-14',user='owner'):
        return self.call('GET',f'/occurrences/{self.series}/{week}',user=user)

    def respond(self,answer,user='1',week='2026-09-14',snapshot=None,code=200):
        row=snapshot or self.detail(week,user)
        return self.call('POST',f'/occurrences/{self.series}/{week}/response',dict(answer=answer,revision=row['revision'],version_id=row['version_id']),user,code)

    def move(self,start='2026-09-15T12:00',week='2026-09-14',action='move',snapshot=None,code=200):
        row=snapshot or self.detail(week)
        return self.call('PUT',f'/occurrences/{self.series}/{week}',dict(action=action,starts_at=start,duration_minutes=45,teacher_id=1,revision=row['revision'],version_id=row['version_id'],note='Перенос'),code=code)

    def admin_response(self,answer='confirmed',teacher=1,snapshot=None,code=200,**extra):
        row=snapshot or self.detail()
        return self.call('POST',f'/occurrences/{self.series}/2026-09-14/response',dict(answer=answer,teacher_id=teacher,revision=row['revision'],version_id=row['version_id'],**extra),code=code)

    def assign(self,teacher=2,snapshot=None,code=200):
        row=snapshot or self.detail()
        return self.call('PUT',f'/occurrences/{self.series}/2026-09-14',dict(action='assign',teacher_id=teacher,revision=row['revision'],version_id=row['version_id'],note='Назначил админ'),code=code)

    def change_rule(self,start='2026-09-22T11:00',week='2026-09-21',action='change',revision=1,code=200,teacher=1):
        return self.call('PUT',f'/series/{self.series}',dict(starts_at=start,effective_week=week,duration_minutes=45,teacher_id=teacher,revision=revision,action=action),code=code)


    def learning_seed(self):
        with self.database() as (_, cur):
            for query in ["INSERT INTO curriculum_plans VALUES(1,'Основной план')",
                          "INSERT INTO lesson_formats VALUES(1,'Сборка')",
                          "INSERT INTO curriculum_modules VALUES(1,1,'Механизмы',1)",
                          "INSERT INTO instructions VALUES(1,'PDF мотоцикла'),(2,'PDF художника'),(3,'PDF карусели')",
                          "INSERT INTO curriculum_lessons VALUES(1,1,'Мотоцикл',1,1,1),(2,1,'Художник',2,1,2),(3,1,'Карусель',3,1,3)",
                          "INSERT INTO branch_curriculum_runs VALUES(1,1,1,1)"]:
                cur.execute(query)

    def record(self, id=1, start='2026-09-07 10:00:00', step=1, mode='PLAN', teacher=2, branch=1, instruction=1, run=1):
        with self.database() as (_, cur):
            cur.execute('INSERT INTO lessons(id,branch_id,starts_at,teacher_id,instruction_id,curriculum_run_id,curriculum_lesson_id,curriculum_mode) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',
                        (id,branch,start,teacher,instruction,run,step,mode))

    def test_forecast_uses_completed_steps_and_intervening_unopened_weeks(self):
        self.learning_seed()
        self.record()
        near = self.detail()['learning']
        self.assertEqual((near['kind'],near['title'],near['instruction_id']),('forecast','Художник',2))
        far = self.detail('2026-09-21')['learning']
        self.assertEqual(far['title'],'Карусель')
        week = self.call('GET','/week?start=2026-09-21')['items'][0]
        self.assertEqual(week['learning'],far)
        self.assertEqual(self.detail('2026-09-28')['learning']['kind'],'complete')
        with self.database() as (_, cur):
            cur.execute('SELECT COUNT(*) n FROM lessons')
            self.assertEqual(cur.fetchone()['n'],1)
            cur.execute('SELECT COUNT(*) n FROM calendar_occurrences')
            self.assertEqual(cur.fetchone()['n'],0)

    def test_cancelled_slot_does_not_advance_forecast_and_moved_slot_uses_destination(self):
        self.learning_seed()
        self.move(action='cancel')
        self.assertEqual(self.detail()['learning']['kind'],'cancelled')
        self.assertEqual(self.detail('2026-09-21')['learning']['title'],'Мотоцикл')
        self.move(action='restore')
        self.move('2026-09-23T12:00')
        self.assertEqual(self.detail()['learning']['title'],'Художник')
        self.assertEqual(self.detail('2026-09-21')['learning']['title'],'Мотоцикл')
        origin = self.call('GET','/week?start=2026-09-14')['items'][0]
        self.assertTrue(origin['is_ghost'])
        self.assertEqual(origin['learning']['title'],'Художник')

    def test_forecast_is_shared_across_all_slots_even_when_only_one_replacement_is_visible(self):
        self.learning_seed()
        second = self.create('2026-09-15T10:00',key='second-learning-key')
        self.respond('declined')
        # An unbound teacher sees only the replacement, but hidden branch slots still advance the plan.
        self.assertEqual(self.detail('2026-09-21')['learning']['title'],'Карусель')
        open_slot = self.call('GET','/week?start=2026-09-14',user='5')['items'][0]
        self.assertEqual(open_slot['learning']['title'],'Мотоцикл')
        self.assertEqual(self.call('GET',f'/occurrences/{second}/2026-09-14')['learning']['title'],'Художник')

    def test_repeat_does_not_double_count_and_pause_does_not_close_a_step(self):
        self.learning_seed()
        self.record()
        self.record(id=2,start='2026-09-08 10:00:00',mode='REPEAT')
        self.record(id=3,start='2026-09-09 10:00:00',step=None,mode='OFF_PLAN_PAUSE')
        self.assertEqual(self.detail()['learning']['title'],'Художник')
        self.record(id=4,start='2026-09-10 10:00:00',step=2,mode='OFF_PLAN_REPLACE',instruction=3)
        self.assertEqual(self.detail()['learning']['title'],'Карусель')

    def test_other_runs_and_future_journal_rows_do_not_close_current_progress(self):
        self.learning_seed()
        self.record(run=99)
        self.record(id=2,start='2026-09-18 10:00:00',step=2)
        self.assertEqual(self.detail()['learning']['title'],'Мотоцикл')

    def test_past_fact_uses_actual_teacher_and_instruction_without_duplicating_calendar_card(self):
        self.learning_seed()
        self.record(start='2026-09-14 10:00:00',teacher=2,step=1,instruction=3,mode='OFF_PLAN_REPLACE')
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,15,18)):
            item = self.call('GET','/week?start=2026-09-14')['items'][0]
            self.assertEqual(item['status'],'recorded')
            self.assertEqual(item['learning']['teacher_name'],'Борис')
            self.assertEqual(item['learning']['title'],'PDF карусели')
            self.assertEqual(item['learning']['curriculum_lesson_name'],'Мотоцикл')
            self.assertEqual(len(self.call('GET','/week?start=2026-09-14')['items']),1)
            self.assertEqual(self.detail()['learning'],item['learning'])

    def test_journal_before_calendar_exists_is_visible_without_a_recurring_rule(self):
        self.learning_seed()
        self.record()
        row = self.call('GET','/week?start=2026-09-07')['items'][0]
        self.assertTrue(row['is_journal_only'])
        self.assertEqual(row['learning']['teacher_name'],'Борис')
        self.assertEqual(self.call('GET','/recorded-lessons/1')['learning'],row['learning'])
        self.call('GET','/recorded-lessons/1',user='3',code=404)
        self.assertEqual(self.call('GET','/week?start=2026-09-07',user='3')['items'],[])

    def test_order_match_uses_calendar_time_instead_of_reported_time(self):
        self.learning_seed()
        self.record(start='2026-09-14 10:15:00')
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,15,18)):
            self.assertEqual(self.detail()['learning']['match'],'order')
            self.assertEqual(self.detail()['learning']['starts_at'],'2026-09-14T10:00:00')

    def test_excess_fact_keeps_its_reported_time_without_duplicating_the_matched_fact(self):
        self.learning_seed()
        self.record(start='2026-09-14 10:15:00')
        self.record(id=2,start='2026-09-14 11:15:00',step=2)
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,15,18)):
            rows = self.call('GET','/week?start=2026-09-14')['items']
            self.assertEqual(len(rows),2)
            self.assertEqual(self.detail()['learning']['lesson_id'],1)
            extra = [row for row in rows if row.get('is_journal_only')]
            self.assertEqual(len(extra),1)
            self.assertEqual(extra[0]['learning']['lesson_id'],2)
            self.assertEqual(extra[0]['starts_at'],'2026-09-14T11:15:00')
            self.assertEqual(self.call('GET','/recorded-lessons/2')['starts_at'],extra[0]['starts_at'])

    def test_facts_fill_slots_in_addition_order_regardless_of_reported_time_and_teacher(self):
        self.learning_seed()
        early = self.create(start='2026-09-14T09:00',key='early-slot-order-test',teacher=1)
        self.record(start='2026-09-14 23:30:00',teacher=2)
        self.record(id=2,start='2026-09-14 07:00:00',step=2,teacher=1)
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,15,18)):
            rows = self.call('GET','/week?start=2026-09-14')['items']
            self.assertEqual(len(rows),2)
            self.assertEqual([(row['series_id'],row['learning']['lesson_id']) for row in rows],[(early,1),(self.series,2)])
            self.assertEqual(rows[0]['learning']['starts_at'],'2026-09-14T09:00:00')
            self.assertEqual(rows[0]['learning']['teacher_id'],2)
            self.assertEqual(self.detail()['learning'],rows[1]['learning'])

    def test_past_without_report_is_not_presented_as_a_forecast(self):
        self.learning_seed()
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,15,18)):
            self.assertEqual(self.detail()['learning']['kind'],'unrecorded')

    def test_cancelled_history_does_not_require_a_report_but_still_shows_an_existing_fact(self):
        self.learning_seed()
        self.move(action='cancel')
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,15,18)):
            self.assertEqual(self.detail()['learning']['kind'],'cancelled')
            self.record(start='2026-09-14 10:00:00')
            actual = self.detail()
            self.assertEqual(actual['learning']['kind'],'actual')
            self.assertEqual(actual['status'],'recorded')
            self.assertEqual(actual['planning_status'],'cancelled')
            self.assertTrue(actual['is_cancelled'])

    def test_read_is_virtual_and_create_retry_is_idempotent(self):
        self.assertEqual(self.create(),self.series)
        self.detail()
        self.call('GET','/week?start=2026-09-14')
        with self.database() as (_,cur):
            cur.execute('SELECT COUNT(*) n FROM calendar_occurrences')
            self.assertEqual(cur.fetchone()['n'],0)
            cur.execute('SELECT COUNT(*) n FROM calendar_series')
            self.assertEqual(cur.fetchone()['n'],1)

    def test_weekly_confirmation_and_retry(self):
        before=self.detail()
        result=self.respond('confirmed',snapshot=before)
        self.assertEqual(result['confirmed_teacher_name'],'Анна')
        self.assertEqual(self.respond('confirmed',snapshot=before)['revision'],result['revision'])
        self.assertEqual(self.detail('2026-09-21')['status'],'pending')
        self.assertEqual(len(self.detail()['response_history']),1)

    def test_replacement_and_non_responsible_decline(self):
        self.respond('confirmed')
        self.assertEqual(self.respond('declined',user='2')['status'],'confirmed')
        self.assertEqual(self.respond('declined')['status'],'replacement')
        taken=self.respond('confirmed',user='2')
        self.assertEqual(taken['confirmed_teacher_name'],'Борис')
        self.assertTrue(taken['is_replacement'])
        self.assertEqual(self.respond('declined')['confirmed_teacher_id'],2)

    def test_concurrent_claims_have_one_winner(self):
        snapshot=self.detail()
        def claim(user):
            with self.app.test_client() as client:
                return client.post(f'/api/calendar/occurrences/{self.series}/2026-09-14/response',json=dict(answer='confirmed',revision=snapshot['revision'],version_id=snapshot['version_id']),headers={'X-Test-User':user}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes=list(pool.map(claim,['1','2']))
        self.assertEqual(sorted(codes),[200,409])
        self.assertEqual(len(self.detail()['response_history']),1)

    def test_move_resets_answer_preserves_history_and_next_week(self):
        self.respond('confirmed')
        moved=self.move()
        self.assertEqual(moved['status'],'pending')
        self.assertEqual(moved['starts_at'],'2026-09-15T12:00:00')
        self.assertEqual(len(moved['response_history']),1)
        self.assertEqual(moved['responses'],[])
        self.assertEqual(self.detail('2026-09-21')['starts_at'],'2026-09-21T10:00:00')
        self.respond('confirmed')
        self.assertEqual(len(self.detail()['response_history']),2)

    def test_cross_week_move_visible_at_destination_and_origin(self):
        self.move('2026-09-23T12:00')
        origin=self.call('GET','/week?start=2026-09-14')['items']
        target=self.call('GET','/week?start=2026-09-21')['items']
        self.assertTrue(origin[0]['is_ghost'])
        self.assertEqual(len(target),2)
        self.assertTrue(all(not item['is_ghost'] for item in target))
        self.assertEqual({item['week_start'] for item in target},{'2026-09-14','2026-09-21'})

    def test_rule_versions_preserve_earlier_weeks_and_exceptions(self):
        self.respond('confirmed')
        self.respond('confirmed',week='2026-09-21')
        self.move('2026-09-30T15:00',week='2026-09-28')
        self.change_rule()
        self.assertEqual(self.detail()['starts_at'],'2026-09-14T10:00:00')
        self.assertEqual(self.detail()['status'],'confirmed')
        self.assertEqual(self.detail('2026-09-21')['starts_at'],'2026-09-22T11:00:00')
        self.assertEqual(self.detail('2026-09-21')['status'],'pending')
        self.assertEqual(self.detail('2026-09-28')['starts_at'],'2026-09-30T15:00:00')
        self.assertEqual(self.detail('2026-10-05')['starts_at'],'2026-10-06T11:00:00')

    def test_new_change_supersedes_planned_future_rule(self):
        self.change_rule(start='2026-10-06T14:00',week='2026-10-05')
        self.change_rule(start='2026-09-23T12:00',week='2026-09-21',revision=2)
        self.assertEqual(self.detail('2026-10-05')['starts_at'],'2026-10-07T12:00:00')

    def test_stop_cancels_future_including_exceptions_and_keeps_past_plan(self):
        self.move('2026-09-24T12:00',week='2026-09-21')
        self.change_rule(action='stop')
        self.assertEqual(self.detail()['status'],'pending')
        self.assertEqual(self.detail('2026-09-21')['status'],'cancelled')
        self.assertEqual(self.call('GET','/week?start=2026-09-28')['items'],[])
        self.move(week='2026-09-21',action='restore',code=400)

    def test_stale_edit_and_stale_response_after_move_are_rejected(self):
        old=self.detail()
        self.move()
        self.move(snapshot=old,code=409)
        self.respond('confirmed',snapshot=old,code=409)
        self.change_rule()
        self.change_rule(revision=1,code=409)

    def test_cancel_restore_requires_new_confirmation(self):
        self.respond('confirmed')
        self.move(action='cancel')
        self.respond('confirmed',code=409)
        self.assertEqual(self.move(action='restore')['status'],'pending')

    def test_access_uses_garden_bindings_not_default_teacher(self):
        items=self.call('GET','/week?start=2026-09-14',user='2')['items']
        self.assertEqual(len(items),1)
        self.assertEqual(items[0]['planned_teacher_id'],1)
        self.call('GET',f'/occurrences/{self.series}/2026-09-14',user='3',code=404)
        self.call('PUT',f'/series/{self.series}',{},user='1',code=403)
        self.call('POST','/series',dict(branch_id=2,starts_at='2026-09-14T10:00',request_key='foreign-garden-0001'),code=404)
        self.respond('confirmed',user='4',code=400)
        context=self.call('GET','/context',user='1')
        self.assertEqual({b['id'] for b in context['branches']},{1,3})

    def test_invalid_dates_times_duration_and_past_changes(self):
        self.call('GET','/week?start=2026-09-15',code=400)
        self.change_rule(week='2026-09-07',start='2026-09-08T12:00',code=400)
        self.move(start='2026-09-10T12:00',code=400)
        row=self.detail()
        self.call('PUT',f'/occurrences/{self.series}/2026-09-14',dict(action='move',starts_at='2026-09-15T23:45',duration_minutes=60,revision=row['revision'],version_id=row['version_id']),code=400)
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,14,11)):
            self.respond('confirmed',code=400)
            self.move(code=400)
            self.change_rule(week='2026-09-14',start='2026-09-15T12:00',code=400)

    def test_past_card_offers_current_future_rule_not_historical_time(self):
        self.change_rule()
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,18,19)):
            detail=self.detail()
            self.assertEqual(detail['rule']['starts_at'],'10:00')
            self.assertEqual(detail['edit_week'],'2026-09-21')
            self.assertEqual(detail['edit_rule']['starts_at'],'11:00')

    def test_future_origin_already_held_early_is_preserved_when_rule_changes_or_stops(self):
        self.move('2026-09-11T10:00')
        self.respond('confirmed')
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,11,11)):
            self.change_rule(week='2026-09-14',start='2026-09-15T12:00')
            self.assertEqual(self.detail()['status'],'confirmed')
            self.assertEqual(self.detail()['starts_at'],'2026-09-11T10:00:00')
            self.change_rule(week='2026-09-14',action='stop',revision=2)
            self.assertEqual(self.detail()['status'],'confirmed')
            self.assertEqual(self.call('GET','/week?start=2026-09-21')['items'],[])

    def test_failed_action_rolls_back_materialization(self):
        with patch('blueprints.calendar.audit',side_effect=RuntimeError('test failure')):
            with self.assertRaises(RuntimeError):
                self.respond('confirmed')
        self.assertEqual(self.detail()['status'],'pending')
        with self.database() as (_,cur):
            cur.execute('SELECT COUNT(*) n FROM calendar_occurrences')
            self.assertEqual(cur.fetchone()['n'],0)

    def test_admin_confirms_on_behalf_of_teacher_with_author_and_retry(self):
        before=self.detail()
        result=self.admin_response(snapshot=before,note='Договорились')
        response=result['confirmed_response']
        self.assertEqual((response['teacher_id'],response['actor_role'],response['actor_user_id'],response['actor_name']),(1,'OWNER',10,'owner'))
        self.assertEqual(self.admin_response(snapshot=before,note='Договорились')['revision'],result['revision'])
        self.assertEqual(len(self.detail()['response_history']),1)
        self.assertEqual(self.detail(user='1')['my_response']['actor_role'],'OWNER')
        self.assertEqual(self.detail()['history'][0]['details']['teacher_id'],1)
        self.assertEqual(self.detail('2026-09-21')['status'],'pending')
        self.assertTrue(result['can_manage_teachers'])
        self.assertFalse(self.detail(user='1')['can_manage_teachers'])

    def test_teacher_can_change_admin_answer_and_source_is_preserved(self):
        self.admin_response()
        declined=self.respond('declined')
        self.assertEqual(declined['status'],'replacement')
        self.assertEqual(declined['my_response']['actor_role'],'TEACHER')
        confirmed=self.respond('confirmed')
        self.assertEqual(confirmed['confirmed_response']['actor_role'],'TEACHER')
        self.assertEqual([r['actor_role'] for r in confirmed['response_history']],['OWNER','TEACHER','TEACHER'])
        # An explicit admin answer after a teacher's answer records the new actor.
        self.assertEqual(len(self.admin_response()['response_history']),4)

    def test_admin_decline_and_replacement_do_not_erase_another_teacher(self):
        self.assertEqual(self.admin_response('declined',note='Болеет')['status'],'replacement')
        taken=self.admin_response(teacher=2)
        self.assertEqual(taken['confirmed_teacher_id'],2)
        self.assertTrue(taken['is_replacement'])
        self.assertEqual(self.admin_response('declined',teacher=1,note='Ещё не выздоровела')['confirmed_teacher_id'],2)
        self.assertEqual(self.admin_response('declined',teacher=2)['status'],'replacement')

    def test_admin_can_replace_confirmed_teacher_only_with_explicit_current_target(self):
        old=self.detail()
        self.respond('confirmed')
        self.admin_response(teacher=2,code=409)
        self.admin_response(teacher=2,replace_confirmed_teacher_id=4,code=409)
        self.admin_response(teacher=2,replace_confirmed_teacher_id=1,snapshot=old,code=409)
        before=self.detail()
        result=self.admin_response(teacher=2,replace_confirmed_teacher_id=1,snapshot=before)
        self.assertEqual(result['confirmed_teacher_id'],2)
        self.assertEqual(result['response_epoch'],before['response_epoch']+1)
        self.assertEqual([r['teacher_id'] for r in result['responses']],[2])
        self.assertEqual([r['answer'] for r in result['response_history']],['confirmed','confirmed'])
        self.assertEqual(result['history'][0]['details']['replaced_teacher_name'],'Анна')
        self.assertEqual(self.admin_response(teacher=2,replace_confirmed_teacher_id=1,snapshot=before)['revision'],result['revision'])
        self.respond('confirmed',user='1',code=409)

    def test_assign_only_this_date_preserves_time_note_rule_and_response_history(self):
        self.move()
        self.respond('confirmed')
        before=self.detail()
        result=self.assign()
        self.assertEqual(result['planned_teacher_id'],2)
        self.assertEqual(result['starts_at'],before['starts_at'])
        self.assertEqual(result['duration_minutes'],before['duration_minutes'])
        self.assertEqual(result['note'],'Перенос')
        self.assertEqual(result['status'],'pending')
        self.assertEqual(result['responses'],[])
        self.assertEqual(len(result['response_history']),1)
        self.assertEqual(result['history'][0]['details']['note'],'Назначил админ')
        self.assertEqual(result['history'][0]['details']['before']['planned_teacher_id'],1)
        self.assertEqual(result['rule']['teacher_id'],1)
        self.assertEqual(self.detail('2026-09-21')['planned_teacher_id'],1)
        self.assertEqual(self.assign()['revision'],result['revision'])
        self.assign(teacher=1,snapshot=before,code=409)
        self.assertIsNone(self.assign(teacher=None)['planned_teacher_id'])

    def test_admin_cannot_confirm_fired_or_unspecified_teacher_or_edit_other_owners(self):
        for tid in (None,4,999):
            self.admin_response(teacher=tid,code=400)
        self.admin_response('declined',teacher=999,code=400)
        self.assign(teacher=999,code=400)
        self.assign(teacher=4,code=400)
        row=self.detail()
        self.call('POST',f'/occurrences/{self.series}/2026-09-14/response',dict(answer='confirmed',teacher_id=2,revision=row['revision'],version_id=row['version_id']),user='1',code=403)
        self.call('PUT',f'/occurrences/{self.series}/2026-09-14',dict(action='assign',teacher_id=2,revision=row['revision'],version_id=row['version_id']),user='1',code=403)
        with self.database() as (_,cur):
            cur.execute('UPDATE branches SET department_id=2 WHERE id=1')
        self.admin_response(snapshot=row,code=404)
        self.assign(snapshot=row,code=404)

    def test_admin_can_free_confirmed_teacher_who_was_unlinked_or_fired(self):
        self.admin_response()
        with self.database() as (_,cur):
            cur.execute('DELETE FROM branch_teachers WHERE branch_id=1 AND teacher_id=1')
            cur.execute("UPDATE teachers SET status='fired' WHERE id=1")
        self.admin_response(teacher=1,code=400)
        declined=self.admin_response('declined',teacher=1)
        self.assertEqual(declined['status'],'replacement')
        self.assertEqual(declined['responses'][0]['teacher_name'],'Анна')
        self.assertEqual(self.admin_response(teacher=2)['confirmed_teacher_id'],2)

    def test_admin_actions_are_disabled_for_cancelled_or_started_dates(self):
        self.move(action='cancel')
        self.assertFalse(self.detail()['can_manage_teachers'])
        self.admin_response(code=409)
        self.admin_response('declined',code=409)
        self.assign(code=409)
        self.move(action='restore')
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,14,11)):
            self.assertFalse(self.detail()['can_manage_teachers'])
            self.admin_response(code=400)
            self.admin_response('declined',code=400)
            self.assign(code=400)

    def test_admin_and_teacher_concurrent_confirmation_have_one_winner(self):
        snapshot=self.detail()
        def claim(user):
            body=dict(answer='confirmed',revision=snapshot['revision'],version_id=snapshot['version_id'])
            if user=='owner':
                body['teacher_id']=2
            with self.app.test_client() as client:
                return client.post(f'/api/calendar/occurrences/{self.series}/2026-09-14/response',json=body,headers={'X-Test-User':user}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes=list(pool.map(claim,['owner','1']))
        self.assertEqual(sorted(codes),[200,409])
        self.assertEqual(len(self.detail()['response_history']),1)

    def test_failed_admin_replacement_rolls_back_teacher_and_history_together(self):
        before=self.respond('confirmed')
        with patch('blueprints.calendar.audit',side_effect=RuntimeError('test failure')):
            with self.assertRaises(RuntimeError):
                self.admin_response(teacher=2,replace_confirmed_teacher_id=1)
        after=self.detail()
        for key in ('confirmed_teacher_id','response_epoch','revision','response_history'):
            self.assertEqual(after[key],before[key])

    def test_open_replacements_visible_to_all_working_teachers_including_unbound(self):
        for user in ('3','5'):
            self.assertEqual(self.call('GET','/week?start=2026-09-14',user=user)['items'],[])
            self.call('GET',f'/occurrences/{self.series}/2026-09-14',user=user,code=404)
        self.respond('declined')
        for user in ('3','5'):
            items=self.call('GET','/week?start=2026-09-14',user=user)['items']
            self.assertEqual(len(items),1)
            self.assertTrue(items[0]['is_external_replacement'])
            self.assertFalse(items[0]['is_personal'])
            self.assertTrue(items[0]['can_confirm'])
            self.assertFalse(items[0]['can_respond'])
            self.assertEqual(self.detail(user=user)['status'],'replacement')
            self.respond('declined',user=user,code=403)
        # Employment status is still required, even if a teacher knows the date URL.
        with self.database() as (_,cur):
            cur.execute('DELETE FROM branch_teachers WHERE teacher_id=4')
        self.assertEqual(self.call('GET','/week?start=2026-09-14',user='4')['items'],[])
        self.call('GET',f'/occurrences/{self.series}/2026-09-14',user='4',code=404)

    def test_external_claim_retains_only_that_date_after_claim_and_later_replacement(self):
        self.respond('declined')
        before=self.detail(user='5')
        taken=self.respond('confirmed',user='3')
        self.assertEqual(taken['confirmed_teacher_id'],3)
        self.assertTrue(taken['is_personal'])
        self.assertFalse(taken['is_external_replacement'])
        self.assertEqual(len(self.call('GET','/week?start=2026-09-14',user='3')['items']),1)
        self.assertEqual(self.call('GET','/week?start=2026-09-21',user='3')['items'],[])
        self.call('GET',f'/occurrences/{self.series}/2026-09-21',user='3',code=404)
        self.assertEqual(self.call('GET','/week?start=2026-09-14',user='5')['items'],[])
        self.call('GET',f'/occurrences/{self.series}/2026-09-14',user='5',code=404)
        self.respond('confirmed',user='5',snapshot=before,code=409)
        self.assertEqual(self.respond('declined',user='3')['status'],'replacement')
        self.respond('confirmed',user='5')
        # A participant can still read their own answer/history after someone takes over.
        self.assertEqual(self.detail(user='3')['confirmed_teacher_id'],5)
        with self.database() as (_,cur):
            cur.execute('SELECT * FROM branch_teachers WHERE branch_id=1 AND teacher_id IN (3,5)')
            self.assertEqual(cur.fetchall(),[])

    def test_global_admin_assignment_and_confirmation_grant_date_access(self):
        self.assign(teacher=3)
        assigned=self.detail(user='3')
        self.assertTrue(assigned['can_confirm'])
        self.assertEqual(assigned['status'],'pending')
        self.assertEqual(self.call('GET','/week?start=2026-09-21',user='3')['items'],[])
        self.respond('confirmed',user='3')
        self.admin_response(teacher=5,replace_confirmed_teacher_id=3)
        self.assertEqual(self.detail(user='5')['my_response']['actor_role'],'OWNER')
        self.assertEqual(self.respond('declined',user='5')['status'],'replacement')
        staff=self.call('GET','/context')['teachers']
        self.assertEqual(next(t for t in staff if t['id']==5)['branch_ids'],[])
        self.assertEqual(len({t['id'] for t in staff}),len(staff))

    def test_global_regular_assignment_visible_only_for_effective_weeks(self):
        self.change_rule(teacher=3)
        self.assertEqual(self.call('GET','/week?start=2026-09-14',user='3')['items'],[])
        future=self.detail(week='2026-09-21',user='3')
        self.assertEqual(future['planned_teacher_id'],3)
        self.assertTrue(future['can_confirm'])
        self.respond('confirmed',week='2026-09-21',user='3')
        self.assertEqual(self.detail(week='2026-09-28',user='3')['status'],'pending')
        new_series=self.create(branch=3,teacher=5,key='unbound-teacher-series-001')
        items=self.call('GET','/week?start=2026-09-14',user='5')['items']
        self.assertEqual([r['series_id'] for r in items],[new_series])
        with self.database() as (_,cur):
            cur.execute('SELECT * FROM branch_teachers WHERE teacher_id=5')
            self.assertEqual(cur.fetchall(),[])

    def test_public_replacements_disappear_when_cancelled_started_or_replanned(self):
        self.respond('declined')
        self.move(action='cancel')
        self.assertEqual(self.call('GET','/week?start=2026-09-14',user='3')['items'],[])
        self.call('GET',f'/occurrences/{self.series}/2026-09-14',user='3',code=404)
        self.move(action='restore')
        self.respond('declined')
        with patch('blueprints.calendar.now',return_value=datetime(2026,9,14,11)):
            self.assertEqual(self.call('GET','/week?start=2026-09-14',user='3')['items'],[])
            self.call('GET',f'/occurrences/{self.series}/2026-09-14',user='3',code=404)
        self.move()
        self.assertEqual(self.call('GET','/week?start=2026-09-14',user='3')['items'],[])

    def test_non_responsible_decline_does_not_publish_an_occupied_date(self):
        self.respond('confirmed')
        self.respond('declined',user='2')
        self.assertEqual(self.call('GET','/week?start=2026-09-14',user='3')['items'],[])

    def test_concurrent_global_claims_have_one_winner(self):
        self.respond('declined')
        snapshot=self.detail()
        def claim(user):
            with self.app.test_client() as client:
                return client.post(f'/api/calendar/occurrences/{self.series}/2026-09-14/response',json=dict(answer='confirmed',revision=snapshot['revision'],version_id=snapshot['version_id']),headers={'X-Test-User':user}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes=list(pool.map(claim,['3','5']))
        self.assertEqual(sorted(codes),[200,409])
        self.assertEqual(len(self.detail()['response_history']),2)

    def test_external_replacement_moved_between_weeks_keeps_its_identity(self):
        self.move('2026-09-23T12:00')
        self.respond('declined')
        origin=self.call('GET','/week?start=2026-09-14',user='3')['items']
        target=self.call('GET','/week?start=2026-09-21',user='3')['items']
        self.assertEqual(len(origin),1)
        self.assertTrue(origin[0]['is_ghost'])
        self.assertEqual(len(target),1)
        self.assertFalse(target[0]['is_ghost'])
        self.assertEqual(target[0]['week_start'],'2026-09-14')
        self.respond('confirmed',user='3')
        self.assertEqual(len(self.call('GET','/week?start=2026-09-21',user='3')['items']),1)


if __name__ == '__main__':
    unittest.main()
