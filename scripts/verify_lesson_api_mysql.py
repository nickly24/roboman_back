"""Verify help and curriculum APIs against migrated local MySQL, then roll back.

Run explicitly: .venv/bin/python scripts/verify_lesson_api_mysql.py
Only loopback hosts and a database name containing _qa are accepted. No DDL,
commits, production credentials, existing users or external messages are used.
"""
import argparse
from contextlib import ExitStack, contextmanager
import csv
from io import StringIO
import os
from pathlib import Path
import re
import sys
import uuid
from unittest.mock import patch

import mysql.connector

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main
import shared
from blueprints import accounting, branch_portal, calendar, curriculum


def run(host='127.0.0.1', port=13317, database='roboman_lesson_qa_full', user='root', password=''):
    if host not in {'127.0.0.1', 'localhost', '::1'} or not re.fullmatch(r'[a-zA-Z0-9_]+_qa(?:_[a-zA-Z0-9_]+)?', database):
        raise ValueError('Verification requires a loopback host and an explicit _qa database')
    connection = mysql.connector.connect(host=host, port=port, database=database,
        user=user, password=password, autocommit=False, connection_timeout=10)
    connection.start_transaction()
    sequence = 0
    checks = []

    @contextmanager
    def transaction_cursor(**kwargs):
        nonlocal sequence
        sequence += 1
        savepoint = f'lesson_api_check_{sequence}'
        cursor = connection.cursor(dictionary=kwargs.get('dictionary', True), buffered=True)
        cursor.execute('SAVEPOINT ' + savepoint)
        try:
            yield connection, cursor
        except BaseException:
            cursor.execute('ROLLBACK TO SAVEPOINT ' + savepoint)
            raise
        finally:
            cursor.execute('RELEASE SAVEPOINT ' + savepoint)
            cursor.close()

    try:
        tag = 'lesson_qa_' + uuid.uuid4().hex[:12]
        with transaction_cursor() as (_, cur):
            cur.execute("SHOW COLUMNS FROM lessons LIKE 'help_rate_snapshot'")
            assert cur.fetchone(), 'Apply 20260922_001_lesson_help_and_skip.sql first'

            def insert(sql, values=()):
                cur.execute(sql, values)
                return cur.lastrowid

            owner = insert('INSERT INTO owners(full_name) VALUES(%s)', (tag,))
            other_owner = insert('INSERT INTO owners(full_name) VALUES(%s)', (tag + '_foreign',))
            teacher = insert("INSERT INTO teachers(full_name,color,status) VALUES(%s,'#123456','working')", (tag,))
            other_teacher = insert("INSERT INTO teachers(full_name,color,status) VALUES(%s,'#345678','working')", (tag + '_foreign',))
            dep = insert('INSERT INTO departments(name) VALUES(%s)', (tag,))
            foreign_dep = insert('INSERT INTO departments(name) VALUES(%s)', (tag + '_foreign',))
            cur.execute('INSERT INTO department_owners(department_id,owner_id) VALUES(%s,%s),(%s,%s)', (dep,owner,foreign_dep,other_owner))
            branch = insert('INSERT INTO branches(department_id,name,address,price_per_child,teacher_base_rate) VALUES(%s,%s,%s,300,1200)', (dep,tag,'Synthetic local fixture'))
            foreign_branch = insert('INSERT INTO branches(department_id,name,address,price_per_child,teacher_base_rate) VALUES(%s,%s,%s,300,1200)', (foreign_dep,tag,'Synthetic local fixture'))
            cur.execute('INSERT INTO branch_teachers(branch_id,teacher_id) VALUES(%s,%s),(%s,%s)', (branch,teacher,foreign_branch,other_teacher))
            identities = {
                'owner': ('OWNER', owner, None, None),
                'teacher': ('TEACHER', None, teacher, None),
                'foreign_owner': ('OWNER', other_owner, None, None),
                'foreign_teacher': ('TEACHER', None, other_teacher, None),
                'branch': ('BRANCH', None, None, branch),
            }
            tokens = {}
            for name, scope in identities.items():
                uid = insert('INSERT INTO auf_users(login,password_hash,role,owner_id,teacher_id,branch_id) VALUES(%s,%s,%s,%s,%s,%s)', (tag + '_' + name, 'unused-local-password', *scope))
                tokens[name] = shared.create_session(cur, uid)

        with ExitStack() as stack:
            for module in (main, shared, accounting, branch_portal, calendar, curriculum):
                stack.enter_context(patch.object(module, 'db_cursor', transaction_cursor))
            client = main.app.test_client()

            def request(method, path, data=None, actor='owner', status=200):
                response = client.open('/api' + path, method=method, json=data,
                    headers={'Authorization': 'Bearer ' + tokens[actor]})
                payload = response.get_json(silent=True)
                assert response.status_code == status, (method,path,response.status_code,payload or response.get_data(as_text=True))
                checks.append(f'{actor} {method} {path}: {status}')
                return payload.get('data') if payload else response.get_data(as_text=True)

            def setting(rate):
                return request('PUT','/settings/salary',dict(teacher_base_rate=1200,teacher_threshold_children=5,teacher_bonus_per_child=100,teacher_help_rate=rate))

            plan = request('POST','/curriculum-plans',dict(name=tag))
            first_module = request('POST',f"/curriculum-plans/{plan['id']}/modules",dict(name='First'))
            later_module = request('POST',f"/curriculum-plans/{plan['id']}/modules",dict(name='Later'))
            lesson_format = request('POST','/lesson-formats',dict(name=tag))
            steps = [request('POST',f"/curriculum-modules/{module['id']}/lessons",dict(name=f'Step {index}',format_id=lesson_format['id']))['id']
                for index,module in enumerate((first_module,later_module,later_module,later_module),1)]
            request('PUT',f'/branches/{branch}/curriculum',dict(enabled=True,plan_id=plan['id']))

            def progress():
                return request('GET',f'/branches/{branch}/curriculum')

            help_data = dict(branch_id=branch,teacher_id=teacher,lesson_type='HELP',starts_at='2026-09-10T00:00')
            with transaction_cursor() as (_, cur):
                cur.execute("UPDATE settings SET value_int=NULL WHERE `key`='teacher_help_rate'")
            request('POST','/lessons',help_data,status=409)
            setting(750)
            help_one = request('POST','/lessons',help_data)
            assert (help_one['lesson_type'],help_one['help_rate_snapshot'],help_one['teacher_salary'],help_one['revenue']) == ('HELP',750,750,0)
            assert help_one['total_children'] == 0 and help_one['curriculum_run_id'] is None and help_one['instruction_id'] is None
            assert progress()['current_lesson']['id'] == steps[0]
            setting(900)
            request('PUT',f"/lessons/{help_one['id']}",dict(starts_at='2026-09-11T00:00'),actor='teacher')
            historical = request('GET',f"/lessons/{help_one['id']}")
            assert (historical['help_rate_snapshot'],historical['teacher_salary']) == (750,750)
            help_two = request('POST','/lessons',{**help_data,'starts_at':'2026-09-20T00:00'},actor='teacher')
            assert help_two['help_rate_snapshot'] == 900 and help_two['teacher_salary'] == 900
            for invalid in ({'paid_children':1},{'trial_children':1},{'instruction_id':1},{'is_creative':True},
                            {'is_fixed_salary_2000':True},{'help_rate_snapshot':1},{'price_snapshot':10}):
                request('POST','/lessons',{**help_data,**invalid},status=400)
                request('PUT',f"/lessons/{help_one['id']}",invalid,status=400)
            request('PUT',f"/lessons/{help_one['id']}",{'lesson_type':'LESSON'},status=409)
            request('POST',f"/lessons/{help_one['id']}/reprice",status=409)
            request('POST','/lessons',{**help_data,'branch_id':foreign_branch},status=403)
            request('POST','/lessons',{**help_data,'branch_id':foreign_branch},actor='teacher',status=403)
            request('POST','/lessons',help_data,actor='branch',status=403)
            request('GET',f"/lessons/{help_one['id']}",actor='foreign_owner',status=404)
            request('GET',f"/lessons/{help_one['id']}",actor='foreign_teacher',status=404)
            request('PUT',f"/lessons/{help_one['id']}",{'starts_at':'2026-09-12T00:00'},actor='foreign_teacher',status=403)
            request('PUT','/settings/teacher_help_rate',{'value_int':20},actor='teacher',status=403)
            for rate in (-1,'NaN',True,0.25):
                request('PUT','/settings/teacher_help_rate',{'value_int':rate},status=400)

            for path in ('/dashboard/teacher','/reports/teacher/%s/summary' % teacher):
                kpi = request('GET',path+'?month=2026-09',actor='teacher')['kpi']
                assert (kpi['salary_sum'],kpi['help_count'],kpi['lessons_count']) == (1650,2,0)
            owner_kpi = request('GET','/dashboard/owner?month=2026-09')['kpi']
            assert (owner_kpi['help_salary_sum'],owner_kpi['help_count'],owner_kpi['lessons_count'],owner_kpi['avg_children_per_lesson']) == (1650,2,0,0)
            salary = request('GET','/salary/teacher-by-department?month=2026-09',actor='teacher')
            assert salary['total_salary'] == 1650
            for suffix in ('?month=2026-09','?from=2026-09-01&to=2026-10-01',''):
                salary = request('GET','/salary/owner-by-department'+suffix)['by_department'][0]
                assert salary['department_total'] == 1650
                assert salary['teachers'][0]['help_count'] == 2
                if suffix.startswith('?month'):
                    assert (salary['teachers'][0]['salary_1_15'],salary['teachers'][0]['salary_16_end']) == (750,900)
                    assert (salary['teachers'][0]['help_1_15'],salary['teachers'][0]['help_16_end']) == (1,1)
            sheet = request('POST','/accounting/sheets',dict(department_id=dep,year=2026,month=9))
            for period,amount in (('1_15',750),('16_end',900)):
                request('POST',f"/accounting/sheets/{sheet['id']}/salaries",dict(owner_id=owner,teacher_id=teacher,period_type=period,amount=amount))
            sheet_detail = request('GET',f"/accounting/sheets/{sheet['id']}")
            assert sheet_detail['summary']['expenses_salaries'] == 1650
            assert sheet_detail['summary']['profit'] == -1650
            assert sheet_detail['summary']['owner_balances'][0]['salary_paid'] == 1650
            report = request('GET',f'/reports/branch/{branch}/summary?month=2026-09')['kpi']
            assert (report['help_count'],report['total_children_sum'],report['revenue_sum']) == (2,0,0)
            assert request('GET','/reports/revenue-by-month?month=2026-09')['items'][0]['help_salary_sum'] == 1650
            assert request('GET','/reports/attendance-by-month?month=2026-09')['items'][0]['total_children_sum'] == 0
            listed = request('GET','/lessons?month=2026-09')['items']
            assert {r['id'] for r in listed} == {help_one['id'],help_two['id']}
            exported = list(csv.DictReader(StringIO(request('GET','/lessons/export.csv?month=2026-09'))))
            assert len(exported) == 2 and {row['lesson_type'] for row in exported} == {'HELP'}
            assert sum(float(row['teacher_salary']) for row in exported) == 1650
            portal = request('GET','/portal/overview?month=2026-09',actor='branch')
            assert (portal['summary']['help_count'],portal['summary']['lessons_count'],portal['summary']['accrued_amount']) == (2,0,0)
            assert all('help_rate_snapshot' not in lesson and 'teacher_salary' not in lesson for lesson in portal['lessons'])
            assert request('GET',f'/accounting/invoices/report?month=2026-09&branch_id={branch}')['items'] == []
            request('POST','/accounting/invoices',dict(branch_id=branch,month='2026-09',items=[dict(lesson_id=help_one['id'],description='Help',quantity=1,unit_price=750)]),status=400)
            request('PUT',f"/lessons/{help_one['id']}/salary-free")
            assert request('GET',f"/lessons/{help_one['id']}")['teacher_salary'] == 0
            request('PUT',f"/lessons/{help_one['id']}/salary-paid")

            lesson_data = dict(branch_id=branch,teacher_id=teacher,paid_children=5,trial_children=2,starts_at='2026-09-12T10:00')
            skip_data = {**lesson_data,'curriculum_mode':'SKIP_TO_NEXT','curriculum_lesson_id':steps[1],'curriculum_expected_lesson_id':steps[0]}
            skip = request('POST','/lessons',skip_data)
            assert (skip['curriculum_lesson_id'],skip['skipped_curriculum_lesson_id'],skip['teacher_salary']) == (steps[1],steps[0],1400)
            assert (progress()['current_lesson']['id'],progress()['closed_lessons']) == (steps[2],2)
            request('POST','/lessons',skip_data,status=409)
            request('PUT',f"/curriculum-lessons/{steps[0]}",dict(name='Cannot change'),status=409)
            request('DELETE',f"/curriculum-modules/{first_module['id']}",status=409)
            request('PUT',f"/curriculum-plans/{plan['id']}/modules/reorder",dict(module_ids=[later_module['id'],first_module['id']]),status=409)
            regular = request('POST','/lessons',{**lesson_data,'curriculum_mode':'PLAN','curriculum_lesson_id':steps[2]})
            assert progress()['current_lesson']['id'] == steps[3]
            repeat = request('POST','/lessons',{**lesson_data,'curriculum_mode':'REPEAT','curriculum_lesson_id':steps[1]})
            assert progress()['current_lesson']['id'] == steps[3]
            request('POST','/lessons',{**lesson_data,'curriculum_mode':'SKIP_TO_NEXT','curriculum_lesson_id':steps[3]},status=400)
            for recorded in (repeat,regular,skip):
                request('DELETE',f"/lessons/{recorded['id']}")
            assert (progress()['current_lesson']['id'],progress()['closed_lessons']) == (steps[0],0)
            assert request('GET',f"/lessons/{help_one['id']}")['teacher_salary'] == 750
        print(f'Passed {len(checks)} HTTP checks against {host}:{port}/{database}; all fixtures rolled back.')
    finally:
        connection.rollback()
        connection.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=13317)
    parser.add_argument('--database',default='roboman_lesson_qa_full')
    parser.add_argument('--user',default='root')
    arguments = parser.parse_args()
    run(arguments.host,arguments.port,arguments.database,arguments.user,os.environ.get('LESSON_QA_DB_PASSWORD',''))
