"""Versioned weekly planning. All writes lock the series before its occurrence.

Dates are Moscow wall time. GETs expand immutable rules without creating rows.
Recorded lessons remain independent; read-only curriculum enrichment lives in calendar_learning.
"""
from __future__ import annotations

import json
import re
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from flask import Blueprint, abort, g, request
from werkzeug.exceptions import HTTPException

from shared import db_cursor, exec_one, fetch_all, fetch_one, require_auth, require_role, _ok, _err

bp = Blueprint('calendar', __name__)


@bp.errorhandler(HTTPException)
def http_error(error):
    return _err(error.description, status=error.code)


def now():
    return datetime.now(ZoneInfo('Europe/Moscow')).replace(tzinfo=None, microsecond=0)


def parse_date(value, label='Дата'):
    try:
        result = date.fromisoformat(str(value))
        if not 2000 <= result.year <= 2100:
            raise ValueError()
        return result
    except (TypeError, ValueError):
        abort(400, description=f'{label}: укажите дату в формате ГГГГ-ММ-ДД')


def monday(value):
    return value - timedelta(days=value.weekday())


def week_date(value):
    result = parse_date(value, 'Неделя')
    if result.weekday() != 0:
        abort(400, description='Неделя должна начинаться с понедельника')
    return result


def integer(value, label, low=1, high=2**63 - 1):
    try:
        if isinstance(value, bool) or not re.fullmatch(r'\d+', str(value)):
            raise ValueError()
        number = int(value)
        if not low <= number <= high:
            raise ValueError()
        return number
    except (ValueError, TypeError):
        abort(400, description=f'{label}: допустимо целое число от {low} до {high}')


def teacher_id(value):
    return None if value in (None, '') else integer(value, 'Преподаватель')


def local_datetime(value):
    try:
        if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d)?', str(value)):
            raise ValueError()
        result = datetime.fromisoformat(value)
        parse_date(result.date())
        return result.replace(second=0)
    except (TypeError, ValueError):
        abort(400, description='Укажите дату и время занятия по Москве')


def time_value(value):
    if isinstance(value, timedelta):
        return (datetime.min + value).time()
    if isinstance(value, time):
        return value
    try:
        return time.fromisoformat(str(value))
    except ValueError:
        abort(400, description='Укажите корректное время')


def note_value(data):
    note = data.get('note', '')
    if not isinstance(note, str) or len(note) > 1000:
        abort(400, description='Комментарий должен быть не длиннее 1000 символов')
    return note.strip()


def scope(alias='b'):
    user = g.current_user
    if user.role == 'OWNER':
        return (f'EXISTS (SELECT 1 FROM department_owners own WHERE own.department_id={alias}.department_id AND own.owner_id=%s)', (user.owner_id,))
    return (f'EXISTS (SELECT 1 FROM branch_teachers bt WHERE bt.branch_id={alias}.id AND bt.teacher_id=%s)', (user.teacher_id,))


def branch_access(cur, branch_id):
    sql, args = scope()
    row = fetch_one(cur, f'SELECT b.* FROM branches b WHERE b.id=%s AND {sql}', (branch_id, *args))
    if not row:
        abort(404, description='Сад не найден или недоступен')
    return row


def eligible(cur, id):
    if id is None:
        return None
    row = fetch_one(cur, "SELECT id,full_name,color FROM teachers WHERE id=%s AND status='working'", (id,))
    if not row:
        abort(400, description='Выберите работающего преподавателя')
    return row


def series_row(cur, id, lock=False):
    row = fetch_one(cur, 'SELECT * FROM calendar_series WHERE id=%s' + (' FOR UPDATE' if lock else ''), (id,))
    if not row:
        abort(404, description='Регулярное занятие не найдено')
    # Teacher access belongs to a specific date, never to the whole series.
    if g.current_user.role == 'OWNER':
        branch_access(cur, row['branch_id'])
    return row


def teacher_viewer(cur):
    if g.current_user.role != 'TEACHER':
        return None
    tid = g.current_user.teacher_id
    return dict(id=tid,
                working=bool(fetch_one(cur, "SELECT 1 FROM teachers WHERE id=%s AND status='working'", (tid,))),
                branches={r['branch_id'] for r in fetch_all(cur, 'SELECT branch_id FROM branch_teachers WHERE teacher_id=%s', (tid,))})


def date_relation(row, branch_id, responses, viewer):
    """Assignments and previous answers retain access to this date only."""
    if viewer is None:
        return True, False
    personal = bool(viewer['id'] is not None and (branch_id in viewer['branches']
                or viewer['id'] in (row['planned_teacher_id'],row['confirmed_teacher_id'])
                or any(r['teacher_id'] == viewer['id'] for r in responses)))
    public = bool(row['needs_replacement'] and not row['confirmed_teacher_id'] and not row['is_cancelled'] and row['starts_at'] > now())
    return personal, public


def versions(cur, id):
    return fetch_all(cur, 'SELECT * FROM calendar_versions WHERE series_id=%s ORDER BY id', (id,))


def version_for(rows, week):
    # Creation order makes "this and following weeks" supersede previously planned changes.
    return next((row for row in reversed(rows) if row['effective_week'] <= week), None)


def planned_start(version, week):
    return datetime.combine(week + timedelta(days=version['weekday'] - 1), time_value(version['starts_at']))


def teacher_name(cur, id):
    row = fetch_one(cur, 'SELECT full_name FROM teachers WHERE id=%s', (id,)) if id else None
    return row['full_name'] if row else None


def virtual(cur, series, version, week, names=None):
    start = planned_start(version, week)
    return dict(id=None, series_id=series['id'], week_start=week, version_id=version['id'],
                scheduled_starts_at=start, starts_at=start, duration_minutes=version['duration_minutes'],
                planned_teacher_id=version['teacher_id'], planned_teacher_name=version['teacher_name'],
                confirmed_teacher_id=None, confirmed_teacher_name=None, is_override=0,
                is_cancelled=0, needs_replacement=0, revision=0, response_epoch=1, note='')


def occurrence(cur, series, week, materialize=False):
    row = fetch_one(cur, 'SELECT * FROM calendar_occurrences WHERE series_id=%s AND week_start=%s', (series['id'], week))
    if row:
        return row
    version = version_for(versions(cur, series['id']), week)
    if not version or not version['is_active']:
        abort(404, description='В эту неделю занятие не запланировано')
    row = virtual(cur, series, version, week)
    if materialize:
        fields = [key for key in row if key != 'id']
        row['id'] = exec_one(cur, f"INSERT INTO calendar_occurrences ({','.join(fields)}) VALUES ({','.join(['%s'] * len(fields))})", tuple(row[key] for key in fields))
    return row


def audit(cur, series_id, occurrence_id, action, details):
    user = g.current_user
    exec_one(cur, '''INSERT INTO calendar_audit
        (series_id,occurrence_id,actor_user_id,actor_name,action,details_json,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
        (series_id, occurrence_id, user.id, user.login, action, json.dumps(details, ensure_ascii=False, default=str), now()))


def expected(row, data):
    if integer(data.get('revision'), 'Редакция', 0) != row['revision'] or integer(data.get('version_id'), 'Версия') != row['version_id']:
        abort(409, description='Занятие уже изменилось. Данные обновлены — проверьте новое время и ответьте ещё раз.')


def future(row):
    if row['starts_at'] <= now():
        abort(400, description='Занятие уже началось. Прошедшие даты доступны только для просмотра.')


def save_occurrence(cur, row, **changes):
    changes['revision'] = row['revision'] + 1
    cur.execute(f"UPDATE calendar_occurrences SET {','.join(key+'=%s' for key in changes)} WHERE id=%s", (*changes.values(), row['id']))
    row.update(changes)


def reset_answers(row):
    return dict(confirmed_teacher_id=None, confirmed_teacher_name=None, needs_replacement=0,
                response_epoch=row['response_epoch'] + 1)


def decorate(cur, row, series, detail=False, cache=None):
    branch = series if cache is not None else fetch_one(cur, '''SELECT b.name,b.address,b.department_id,d.name department_name
        FROM branches b JOIN departments d ON d.id=b.department_id WHERE b.id=%s''', (series['branch_id'],))
    item = {**row, 'key': f"{series['id']}:{row['week_start']}", 'branch_id': series['branch_id'],
            'branch_name': branch['name'], 'address': branch['address'], 'department_id': branch['department_id'],
            'department_name': branch['department_name'], 'series_revision': series['revision'],
            'is_past': row['starts_at'] <= now()}
    item['status'] = 'cancelled' if row['is_cancelled'] else 'confirmed' if row['confirmed_teacher_id'] else 'replacement' if row['needs_replacement'] else 'pending'
    responses = cache['responses'].get(row['id'], []) if cache is not None else (fetch_all(cur, 'SELECT * FROM calendar_responses WHERE occurrence_id=%s ORDER BY id', (row['id'],)) if row['id'] else [])
    latest = {}
    for response in responses:
        if response['response_epoch'] == row['response_epoch']:
            latest[response['teacher_id']] = response
    item['responses'] = list(latest.values())
    item['my_response'] = latest.get(g.current_user.teacher_id)
    item['confirmed_response'] = latest.get(row['confirmed_teacher_id'])
    viewer = cache['viewer'] if cache is not None else teacher_viewer(cur)
    personal, public = date_relation(row, series['branch_id'], responses, viewer)
    item['is_personal'] = personal
    item['is_visible'] = personal or bool(viewer and viewer['working'] and public)
    item['is_external_replacement'] = bool(viewer and public and not personal)
    item['can_manage_teachers'] = g.current_user.role == 'OWNER' and not item['is_past'] and not row['is_cancelled']
    item['is_replacement'] = bool(row['confirmed_teacher_id'] and (row['planned_teacher_id'] and row['confirmed_teacher_id'] != row['planned_teacher_id'] or any(r['answer'] == 'declined' for r in latest.values())))
    available = bool(viewer and viewer['working'] and not item['is_past'] and not row['is_cancelled'])
    item['can_respond'] = available and personal
    item['can_confirm'] = available and (personal or public) and row['confirmed_teacher_id'] in (None, g.current_user.teacher_id)
    if detail:
        item['response_history'] = responses
        history = fetch_all(cur, '''SELECT * FROM calendar_audit WHERE series_id=%s
            AND (occurrence_id=%s OR occurrence_id IS NULL) ORDER BY id DESC''', (series['id'], row['id']))
        for entry in history:
            entry['details'] = json.loads(entry.pop('details_json'))
        item['history'] = history
        version = version_for(versions(cur, series['id']), row['week_start'])
        item['rule'] = {**version, 'starts_at': time_value(version['starts_at']).strftime('%H:%M')} if version else None
        edit_week = row['week_start']
        if edit_week < monday(now().date()) or item['is_past'] or (edit_week == monday(now().date()) and version and planned_start(version,edit_week) <= now()):
            edit_week = monday(now().date()) + timedelta(days=7)
        edit_version = version_for(versions(cur,series['id']),edit_week)
        item['edit_week'] = edit_week
        item['edit_rule'] = {**edit_version, 'starts_at': time_value(edit_version['starts_at']).strftime('%H:%M')} if edit_version else None
    return item


@bp.get('/context')
@require_auth
def context():
    sql, args = scope()
    with db_cursor() as (_, cur):
        branches = fetch_all(cur, f'''SELECT b.id,b.name,b.address,b.department_id,b.is_active,d.name department_name
            FROM branches b JOIN departments d ON d.id=b.department_id WHERE {sql} ORDER BY b.name''', args)
        staff = fetch_all(cur, 'SELECT id,full_name,color,status FROM teachers ORDER BY full_name')
        bindings = fetch_all(cur, 'SELECT branch_id,teacher_id FROM branch_teachers')
        for teacher in staff:
            teacher['branch_ids'] = [r['branch_id'] for r in bindings if r['teacher_id'] == teacher['id']]
        return _ok(dict(branches=branches, teachers=staff, timezone='Europe/Moscow', today=now().date()))


@bp.get('/week')
@require_auth
def get_week():
    week = week_date(request.args.get('start'))
    end = week + timedelta(days=7)
    sql, args = scope() if g.current_user.role == 'OWNER' else ('1=1', ())
    with db_cursor() as (_, cur):
        series_list = fetch_all(cur, f"""SELECT s.*,b.name,b.address,b.department_id,d.name department_name
            FROM calendar_series s JOIN branches b ON b.id=s.branch_id JOIN departments d ON d.id=b.department_id
            WHERE {sql} ORDER BY s.id""", args)
        all_versions = fetch_all(cur, f"""SELECT v.* FROM calendar_versions v JOIN calendar_series s ON s.id=v.series_id
            JOIN branches b ON b.id=s.branch_id WHERE {sql} ORDER BY v.id""", args)
        stored = fetch_all(cur, f"""SELECT o.* FROM calendar_occurrences o JOIN calendar_series s ON s.id=o.series_id
            JOIN branches b ON b.id=s.branch_id WHERE {sql} AND (o.week_start=%s OR (o.starts_at >= %s AND o.starts_at < %s))""",
            (*args,week,datetime.combine(week,time()),datetime.combine(end,time())))
        responses = fetch_all(cur, f"""SELECT r.* FROM calendar_responses r JOIN calendar_occurrences o ON o.id=r.occurrence_id
            JOIN calendar_series s ON s.id=o.series_id JOIN branches b ON b.id=s.branch_id WHERE {sql}
            AND (o.week_start=%s OR (o.starts_at >= %s AND o.starts_at < %s)) ORDER BY r.id""",
            (*args,week,datetime.combine(week,time()),datetime.combine(end,time())))
        cache = dict(responses={},viewer=teacher_viewer(cur))
        for response in responses:
            cache['responses'].setdefault(response['occurrence_id'],[]).append(response)
        items = []
        for series in series_list:
            version = version_for([v for v in all_versions if v['series_id'] == series['id']],week)
            rows = [r for r in stored if r['series_id'] == series['id']]
            if not any(r['week_start'] == week for r in rows) and version and version['is_active']:
                rows.append(virtual(cur,series,version,week))
            for row in rows:
                item = decorate(cur,row,series,cache=cache)
                if not item.pop('is_visible'):
                    continue
                item['is_ghost'] = not (week <= row['starts_at'].date() < end)
                item['display_date'] = (row['scheduled_starts_at'] if item['is_ghost'] else row['starts_at']).date()
                if item['is_ghost'] and not week <= item['display_date'] < end:
                    item['display_date'] = week
                items.append(item)
        from .calendar_learning import enrich
        items = enrich(cur, items, week)
        return _ok(dict(items=sorted(items, key=lambda r:(r['display_date'],r['starts_at'],r['branch_name'])), week_start=week, today=now().date(), timezone='Europe/Moscow'))


@bp.get('/occurrences/<int:series_id>/<week>')
@require_auth
def get_occurrence(series_id, week):
    week = week_date(week)
    with db_cursor() as (_, cur):
        series = series_row(cur, series_id)
        item = decorate(cur, occurrence(cur, series, week), series, detail=True)
        if not item.pop('is_visible'):
            abort(404, description='Занятие не найдено или больше не доступно для замены')
        from .calendar_learning import enrich
        return _ok(enrich(cur, [item])[0])


@bp.get('/recorded-lessons/<int:lesson_id>')
@require_auth
def get_recorded_lesson(lesson_id):
    from .calendar_learning import get_recorded
    with db_cursor() as (_, cur):
        return _ok(get_recorded(cur, lesson_id))


def rule_values(cur, branch_id, data):
    start = local_datetime(data.get('starts_at'))
    duration = integer(data.get('duration_minutes'), 'Длительность', 1, 600)
    tid = teacher_id(data.get('teacher_id'))
    eligible(cur, tid)
    if start + timedelta(minutes=duration) > datetime.combine(start.date()+timedelta(days=1),time()):
        abort(400, description='Занятие должно заканчиваться в тот же день')
    return start, duration, tid


def insert_version(cur, series_id, week, start, duration, tid, active=True):
    return exec_one(cur, '''INSERT INTO calendar_versions(series_id,effective_week,weekday,starts_at,duration_minutes,teacher_id,teacher_name,is_active)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s)''', (series_id, week, start.isoweekday(), start.strftime('%H:%M:%S'), duration, tid, teacher_name(cur,tid), int(active)))


@bp.post('/series')
@require_role('OWNER')
def create_series():
    data = request.get_json(silent=True) or {}
    branch_id = integer(data.get('branch_id'), 'Сад')
    key = data.get('request_key')
    if not isinstance(key, str) or not re.fullmatch(r'[a-zA-Z0-9-]{16,64}', key):
        abort(400, description='Не указан идентификатор запроса. Откройте форму заново.')
    with db_cursor() as (_, cur):
        branch_access(cur, branch_id)
        # Lock the parent for concurrent retries before looking up the unique request key.
        fetch_one(cur, 'SELECT id FROM branches WHERE id=%s FOR UPDATE', (branch_id,))
        existing = fetch_one(cur, 'SELECT * FROM calendar_series WHERE request_key=%s FOR UPDATE', (key,))
        if existing:
            branch_access(cur, existing['branch_id'])
            first = versions(cur,existing['id'])[0]
            return _ok(dict(series_id=existing['id'], week_start=first['effective_week'], repeated=True))
        start, duration, tid = rule_values(cur, branch_id, data)
        if start <= now():
            abort(400, description='Первая дата должна быть в будущем')
        id = exec_one(cur, 'INSERT INTO calendar_series(branch_id,request_key) VALUES(%s,%s)', (branch_id, key))
        insert_version(cur,id,monday(start.date()),start,duration,tid)
        audit(cur,id,None,'series_created',dict(starts_at=start,duration_minutes=duration,teacher_id=tid,effective_week=monday(start.date())))
        return _ok(dict(series_id=id, week_start=monday(start.date())))


@bp.put('/series/<int:series_id>')
@require_role('OWNER')
def change_series(series_id):
    data = request.get_json(silent=True) or {}
    week = week_date(data.get('effective_week'))
    stop = data.get('action') == 'stop'
    with db_cursor() as (_, cur):
        series = series_row(cur,series_id,lock=True)
        if integer(data.get('revision'), 'Редакция') != series['revision']:
            abort(409, description='Правило уже изменилось. Обновите календарь и откройте форму заново.')
        old_versions = versions(cur,series_id)
        old_version = version_for(old_versions,week)
        if not old_version:
            abort(400, description='Выберите неделю не раньше первого занятия')
        if week < monday(now().date()):
            abort(400, description='Нельзя менять прошлые недели')
        if week == monday(now().date()) and planned_start(old_version,week) <= now():
            abort(400, description='Занятие этой недели уже началось. Выберите следующую неделю.')
        if stop:
            start, duration, tid = planned_start(old_version,week), old_version['duration_minutes'],old_version['teacher_id']
        else:
            start, duration, tid = rule_values(cur,series['branch_id'],data)
            if monday(start.date()) != week or start <= now():
                abort(400, description='Новая дата должна быть в выбранной неделе и в будущем')
        stored = fetch_all(cur, 'SELECT * FROM calendar_occurrences WHERE series_id=%s AND week_start >= %s', (series_id,week))
        if any(row['starts_at'] <= now() and not row['is_override'] for row in stored):
            abort(400, description='Изменение затронет уже начавшуюся дату. Выберите более позднюю неделю.')
        vid = insert_version(cur,series_id,week,start,duration,tid,not stop)
        changed = 0
        for row in stored:
            # An exception moved from a future week into the past is already history.
            if row['starts_at'] <= now():
                continue
            if row['is_override'] and not stop:
                continue
            new_start = datetime.combine(row['week_start']+timedelta(days=start.weekday()),start.time())
            differs = stop or row['starts_at'] != new_start or row['duration_minutes'] != duration or row['planned_teacher_id'] != tid or row['is_cancelled']
            if differs:
                changes = reset_answers(row)
                changes.update(version_id=vid,is_cancelled=int(stop),note='Повторы завершены' if stop else '',
                               starts_at=row['starts_at'] if stop else new_start,
                               scheduled_starts_at=row['scheduled_starts_at'] if stop else new_start,
                               duration_minutes=row['duration_minutes'] if stop else duration,
                               planned_teacher_id=row['planned_teacher_id'] if stop else tid,
                               planned_teacher_name=row['planned_teacher_name'] if stop else teacher_name(cur,tid))
                save_occurrence(cur,row,**changes)
                audit(cur,series_id,row['id'],'series_date_cancelled' if stop else 'series_date_changed',dict(starts_at=row['starts_at'],effective_week=week))
                changed += 1
        cur.execute('UPDATE calendar_series SET revision=revision+1 WHERE id=%s', (series_id,))
        audit(cur,series_id,None,'series_stopped' if stop else 'series_changed',dict(effective_week=week,starts_at=start,duration_minutes=duration,teacher_id=tid,reset_dates=changed))
        return _ok(dict(series_id=series_id,reset_dates=changed,week_start=week))


@bp.post('/occurrences/<int:series_id>/<week>/response')
@require_role('OWNER','TEACHER')
def respond(series_id,week):
    week = week_date(week)
    data = request.get_json(silent=True) or {}
    answer = data.get('answer')
    if answer not in ('confirmed','declined'):
        abort(400, description='Выберите «Я приду» или «Не смогу»')
    reason = note_value(data)
    with db_cursor() as (_, cur):
        series = series_row(cur,series_id,lock=True)
        row = occurrence(cur,series,week)
        user = g.current_user
        is_owner = user.role == 'OWNER'
        if is_owner:
            target_id = integer(data.get('teacher_id'), 'Преподаватель')
        else:
            target_id = user.teacher_id
            if data.get('teacher_id') is not None and teacher_id(data['teacher_id']) != target_id:
                abort(403, description='Преподаватель может отвечать только за себя')
        if is_owner and answer == 'declined':
            teacher = fetch_one(cur, 'SELECT id,full_name,color FROM teachers WHERE id=%s', (target_id,))
            if not teacher and target_id in (row['planned_teacher_id'],row['confirmed_teacher_id']):
                name = row['confirmed_teacher_name'] if target_id == row['confirmed_teacher_id'] else row['planned_teacher_name']
                teacher = dict(id=target_id,full_name=name or 'Преподаватель')
            if not teacher:
                abort(400, description='Преподаватель не найден')
        else:
            teacher = eligible(cur,target_id)
        if not is_owner:
            responses = fetch_all(cur, 'SELECT * FROM calendar_responses WHERE occurrence_id=%s', (row['id'],)) if row['id'] else []
            viewer = teacher_viewer(cur)
            personal, public = date_relation(row,series['branch_id'],responses,viewer)
            if not personal and not (viewer['working'] and public):
                abort(409 if row['confirmed_teacher_id'] or row['is_cancelled'] else 404,
                      description='Занятие недоступно или замену уже взял другой преподаватель. Обновите календарь.')
            if answer == 'declined' and not personal:
                abort(403, description='Вы можете взять эту замену. Отказ доступен после назначения на занятие.')
        future(row)
        if row['is_cancelled']:
            abort(409, description='Занятие отменено')
        latest = fetch_one(cur, '''SELECT * FROM calendar_responses WHERE occurrence_id=%s AND teacher_id=%s
            AND response_epoch=%s ORDER BY id DESC LIMIT 1''', (row['id'],teacher['id'],row['response_epoch'])) if row['id'] else None
        # A retried answer is a no-op only for the same schedule epoch/version.
        same_version = str(data.get('version_id')) == str(row['version_id'])
        same_actor = latest and latest.get('actor_role', 'TEACHER') == user.role and (not is_owner or latest.get('actor_user_id') == user.id)
        if same_version and same_actor and latest['answer'] == answer and latest['reason'] == reason and (answer == 'declined' or row['confirmed_teacher_id'] == teacher['id']):
            return _ok(decorate(cur,row,series,True))
        expected(row,data)
        replacing = answer == 'confirmed' and row['confirmed_teacher_id'] not in (None,teacher['id'])
        replaced_id, replaced_name = None, None
        if replacing:
            if not is_owner:
                abort(409, description=f"Занятие уже подтвердил(а) {row['confirmed_teacher_name']}. Обновите календарь.")
            if teacher_id(data.get('replace_confirmed_teacher_id')) != row['confirmed_teacher_id']:
                abort(409, description='Занятие уже подтверждено другим преподавателем. Проверьте, кого заменяете, и подтвердите замену.')
            replaced_id, replaced_name = row['confirmed_teacher_id'],row['confirmed_teacher_name']
        row = occurrence(cur,series,week,materialize=True)
        # Replacement archives the old appointment; it is not a teacher's refusal.
        changes = reset_answers(row) if replacing else {}
        if answer == 'confirmed':
            changes.update(confirmed_teacher_id=teacher['id'],confirmed_teacher_name=teacher['full_name'],needs_replacement=0)
        elif row['confirmed_teacher_id'] == teacher['id']:
            changes.update(confirmed_teacher_id=None,confirmed_teacher_name=None,needs_replacement=1)
        elif row['confirmed_teacher_id'] is None and row['planned_teacher_id'] in (None,teacher['id']):
            changes['needs_replacement'] = 1
        save_occurrence(cur,row,**changes)
        response_id = exec_one(cur, '''INSERT INTO calendar_responses
            (occurrence_id,teacher_id,teacher_name,answer,reason,response_epoch,created_at,actor_user_id,actor_name,actor_role)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (row['id'],teacher['id'],teacher['full_name'],answer,reason,row['response_epoch'],now(),user.id,user.login if is_owner else teacher['full_name'],user.role))
        audit(cur,series_id,row['id'],answer,dict(teacher_id=teacher['id'],teacher_name=teacher['full_name'],note=reason,
            starts_at=row['starts_at'],response_epoch=row['response_epoch'],response_id=response_id,actor_role=user.role,
            replaced_teacher_id=replaced_id,replaced_teacher_name=replaced_name))
        return _ok(decorate(cur,row,series,True))


@bp.put('/occurrences/<int:series_id>/<week>')
@require_role('OWNER')
def change_occurrence(series_id,week):
    week = week_date(week)
    data = request.get_json(silent=True) or {}
    action = data.get('action')
    if action not in ('move','cancel','restore','assign'):
        abort(400, description='Неизвестное действие')
    note = note_value(data)
    with db_cursor() as (_, cur):
        series = series_row(cur,series_id,lock=True)
        row = occurrence(cur,series,week)
        expected(row,data)
        future(row)
        before = {key:row[key] for key in ('starts_at','duration_minutes','planned_teacher_id','planned_teacher_name','is_cancelled')}
        changes = dict(is_override=1,note=note)
        if action == 'assign':
            changes.pop('note')  # Assignment comments belong to audit, not the date's scheduling note.
            if row['is_cancelled']:
                abort(409, description='Занятие отменено. Сначала восстановите эту дату.')
            tid = teacher_id(data.get('teacher_id'))
            eligible(cur,tid)
            if tid == row['planned_teacher_id']:
                return _ok(decorate(cur,row,series,True))
            changes.update(reset_answers(row),planned_teacher_id=tid,planned_teacher_name=teacher_name(cur,tid))
        elif action == 'move':
            start,duration,tid = rule_values(cur,series['branch_id'],data)
            if start <= now():
                abort(400, description='Новое время должно быть в будущем')
            if row['is_cancelled']:
                abort(400, description='Сначала восстановите отменённую дату')
            changes.update(starts_at=start,duration_minutes=duration,planned_teacher_id=tid,planned_teacher_name=teacher_name(cur,tid))
            if start != row['starts_at'] or duration != row['duration_minutes'] or tid != row['planned_teacher_id']:
                changes.update(reset_answers(row))
        else:
            if action == 'restore':
                version = version_for(versions(cur,series_id),week)
                if not version or not version['is_active']:
                    abort(400, description='Повторы завершены. Сначала возобновите регулярное правило.')
            changes.update(reset_answers(row),is_cancelled=int(action == 'cancel'))
        row = occurrence(cur,series,week,materialize=True)
        save_occurrence(cur,row,**changes)
        audit(cur,series_id,row['id'],action,dict(before=before,after={key:row[key] for key in before},note=note))
        return _ok(decorate(cur,row,series,True))
