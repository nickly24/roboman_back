"""Read-only curriculum forecasts and recorded lessons for the calendar.

The journal remains the source of facts. A forecast never advances a curriculum
run or creates a lesson, occurrence, attendance response or financial record.

Within a branch/date, journal rows in insertion order fill calendar slots in
scheduled-time order. Matched cards use calendar time; unmatched journal rows
retain their originally entered time. Viewing the calendar never stores links.
"""
from collections import defaultdict
from datetime import datetime, time, timedelta

from flask import abort, g
from shared import fetch_all

CLOSING_MODES = {'PLAN', 'REPEAT', 'OFF_PLAN_REPLACE'}
FACT_SELECT = '''SELECT l.id,l.branch_id,l.starts_at,l.teacher_id,t.full_name teacher_name,
    l.instruction_id,i.name instruction_name,l.is_creative,
    l.curriculum_run_id,l.curriculum_lesson_id,l.curriculum_mode,
    cl.name curriculum_lesson_name,cl.format_id,lf.name format_name,
    cm.id module_id,cm.name module_name,cp.id plan_id,cp.name plan_name,
    b.name branch_name,b.address,b.department_id,d.name department_name
    FROM lessons l JOIN branches b ON b.id=l.branch_id
    JOIN departments d ON d.id=b.department_id
    LEFT JOIN teachers t ON t.id=l.teacher_id
    LEFT JOIN instructions i ON i.id=l.instruction_id
    LEFT JOIN curriculum_lessons cl ON cl.id=l.curriculum_lesson_id
    LEFT JOIN lesson_formats lf ON lf.id=cl.format_id
    LEFT JOIN curriculum_modules cm ON cm.id=cl.module_id
    LEFT JOIN curriculum_plans cp ON cp.id=cm.plan_id'''


def identity(event):
    return event['series_id'], event['week_start']


def fact_scope():
    from .calendar import scope
    sql, args = scope()
    if g.current_user.role == 'TEACHER':
        return f'({sql} OR l.teacher_id=%s)', (*args, g.current_user.teacher_id)
    return sql, args


def fact_learning(fact, match='order'):
    mode = fact['curriculum_mode']
    off_plan = mode in {'OFF_PLAN_REPLACE', 'OFF_PLAN_PAUSE'}
    title = (fact['instruction_name'] if off_plan else fact['curriculum_lesson_name']) or fact['instruction_name'] or ('Творческое занятие' if fact['is_creative'] else 'Занятие без инструкции')
    return dict(kind='actual', title=title, lesson_id=fact['id'], starts_at=fact['starts_at'],
                teacher_id=fact['teacher_id'], teacher_name=fact['teacher_name'],
                curriculum_lesson_id=fact['curriculum_lesson_id'], curriculum_mode=mode,
                curriculum_lesson_name=fact['curriculum_lesson_name'],
                plan_id=fact['plan_id'], plan_name=fact['plan_name'],
                module_id=fact['module_id'], module_name=fact['module_name'],
                instruction_id=fact['instruction_id'], instruction_name=fact['instruction_name'],
                format_name=fact['format_name'], match=match)


def match_facts(events, facts):
    """Pair each branch/day's first-added fact with its first calendar slot.

    IDs preserve insertion order independently of reported time and teacher.
    Each fact and slot is used at most once; excess facts stay in the journal.
    """
    by_day, facts_by_day = defaultdict(list), defaultdict(list)
    for event in events:
        by_day[event['branch_id'], event['starts_at'].date()].append(event)
    for fact in facts:
        facts_by_day[fact['branch_id'], fact['starts_at'].date()].append(fact)
    matches = {}
    for key, slots in by_day.items():
        ordered_slots = sorted(slots, key=lambda slot: (slot['starts_at'], slot['series_id'], slot['week_start']))
        ordered_records = sorted(facts_by_day[key], key=lambda record: record['id'])
        for slot, record in zip(ordered_slots, ordered_records):
            matches[identity(slot)] = {**fact_learning(record), 'starts_at': slot['starts_at']}
    return matches


def forecast(events, runs, steps, closed, at):
    """Expand one shared branch progression, regardless of the viewer/week filter."""
    remaining = {branch: [step for step in steps.get(run['plan_id'], []) if step['id'] not in closed.get(run['id'], set())] for branch, run in runs.items()}
    offsets = defaultdict(int)
    result = {}
    for event in sorted(events, key=lambda e: (e['starts_at'], e['series_id'], e['week_start'])):
        if event['starts_at'] <= at:
            continue
        key, branch = identity(event), event['branch_id']
        if event['is_cancelled']:
            result[key] = dict(kind='cancelled')
            continue
        run = runs.get(branch)
        if not run:
            result[key] = dict(kind='no_plan')
            continue
        rows, index = remaining[branch], offsets[branch]
        if index >= len(rows):
            result[key] = dict(kind='complete', plan_id=run['plan_id'], plan_name=run['plan_name'])
            continue
        step = rows[index]
        result[key] = dict(kind='forecast', title=step['name'], curriculum_lesson_id=step['id'],
                           plan_id=run['plan_id'], plan_name=run['plan_name'],
                           module_id=step['module_id'], module_name=step['module_name'],
                           instruction_id=step['instruction_id'], instruction_name=step['instruction_name'],
                           format_name=step['format_name'], position=index + 1, as_of=at)
        offsets[branch] += 1
    return result


def expand(cur, branch_ids, start, end):
    from .calendar import monday, version_for, virtual
    if not branch_ids:
        return []
    marks = ','.join(['%s'] * len(branch_ids))
    series = fetch_all(cur, f'SELECT * FROM calendar_series WHERE branch_id IN ({marks})', tuple(branch_ids))
    if not series:
        return []
    ids = tuple(s['id'] for s in series)
    marks = ','.join(['%s'] * len(ids))
    versions = defaultdict(list)
    for v in fetch_all(cur, f'SELECT * FROM calendar_versions WHERE series_id IN ({marks}) ORDER BY id', ids):
        versions[v['series_id']].append(v)
    stored = fetch_all(cur, f'''SELECT * FROM calendar_occurrences WHERE series_id IN ({marks})
        AND ((week_start >= %s AND week_start <= %s) OR (starts_at >= %s AND starts_at < %s))''',
        (*ids, monday(start.date()), monday((end - timedelta(microseconds=1)).date()), start, end))
    rows = {identity(row): row for row in stored}
    for s in series:
        week = monday(start.date())
        while datetime.combine(week, time()) < end:
            version = version_for(versions[s['id']], week)
            if (s['id'], week) not in rows and version and version['is_active']:
                rows[s['id'], week] = virtual(cur, s, version, week)
            week += timedelta(days=7)
    branches = {s['id']: s['branch_id'] for s in series}
    return [{**row, 'branch_id': branches[row['series_id']]} for row in rows.values() if start <= row['starts_at'] < end]


def recorded_event(fact):
    from .calendar import monday
    return dict(key=f"lesson:{fact['id']}", journal_lesson_id=fact['id'], is_journal_only=True,
                branch_id=fact['branch_id'], branch_name=fact['branch_name'], address=fact['address'],
                department_id=fact['department_id'], department_name=fact['department_name'],
                starts_at=fact['starts_at'], scheduled_starts_at=fact['starts_at'], display_date=fact['starts_at'].date(),
                week_start=monday(fact['starts_at'].date()), duration_minutes=None,
                planned_teacher_id=None, planned_teacher_name=None, confirmed_teacher_id=None,
                confirmed_teacher_name=None, is_past=True, is_ghost=False, is_override=False,
                is_cancelled=False, status='recorded', responses=[], history=[], learning=fact_learning(fact, 'journal'),
                can_confirm=False, can_respond=False, can_manage_teachers=False)


def enrich(cur, items, week=None):
    from .calendar import now
    at = now()
    tomorrow = datetime.combine(at.date() + timedelta(days=1), time())
    journal = []
    if week is not None and datetime.combine(week, time()) <= at:
        sql, args = fact_scope()
        journal = fetch_all(cur, f'''{FACT_SELECT} WHERE {sql} AND l.starts_at >= %s AND l.starts_at < %s
            AND l.starts_at < %s ORDER BY DATE(l.starts_at),l.id''', (*args, datetime.combine(week,time()), datetime.combine(week + timedelta(days=7),time()), tomorrow))
    if not items:
        return [recorded_event(f) for f in journal]
    branches = sorted({item['branch_id'] for item in items})
    # Include intervening weeks and actual destinations of moves, even outside the visible week.
    start = datetime.combine(min(at.date(), *(item['starts_at'].date() for item in items)), time())
    end = datetime.combine(max(at.date(), *(item['starts_at'].date() for item in items)) + timedelta(days=1), time())
    events = expand(cur, branches, start, end)
    marks = ','.join(['%s'] * len(branches))
    facts = fetch_all(cur, f'''{FACT_SELECT} WHERE l.branch_id IN ({marks}) AND l.starts_at >= %s
        AND l.starts_at < %s AND l.starts_at < %s ORDER BY DATE(l.starts_at),l.id''', (*branches, start, end, tomorrow))
    matches = match_facts([e for e in events if e['starts_at'].date() <= at.date()], facts)
    projections = {}
    if any(item['starts_at'] > at for item in items):
        run_rows = fetch_all(cur, f'''SELECT r.id,r.branch_id,r.plan_id,p.name plan_name
            FROM branch_curriculum_runs r JOIN curriculum_plans p ON p.id=r.plan_id
            WHERE r.is_active=1 AND r.branch_id IN ({marks}) ORDER BY r.id''', tuple(branches))
        runs = {r['branch_id']: r for r in run_rows}
        steps, closed = defaultdict(list), defaultdict(set)
        if runs:
            plan_ids = tuple(sorted({r['plan_id'] for r in runs.values()}))
            plan_marks = ','.join(['%s'] * len(plan_ids))
            for step in fetch_all(cur, f'''SELECT cl.id,cl.name,cl.module_id,cm.plan_id,cm.name module_name,
                cl.instruction_id,i.name instruction_name,lf.name format_name
                FROM curriculum_lessons cl JOIN curriculum_modules cm ON cm.id=cl.module_id
                JOIN lesson_formats lf ON lf.id=cl.format_id LEFT JOIN instructions i ON i.id=cl.instruction_id
                WHERE cm.plan_id IN ({plan_marks}) ORDER BY cm.sort_order,cm.id,cl.sort_order,cl.id''', plan_ids):
                steps[step['plan_id']].append(step)
            run_ids = tuple(r['id'] for r in runs.values())
            run_marks = ','.join(['%s'] * len(run_ids))
            for row in fetch_all(cur, f'''SELECT curriculum_run_id,curriculum_lesson_id,curriculum_mode FROM lessons
                WHERE curriculum_run_id IN ({run_marks}) AND curriculum_lesson_id IS NOT NULL AND starts_at < %s''', (*run_ids, tomorrow)):
                if row['curriculum_mode'] in CLOSING_MODES:
                    closed[row['curriculum_run_id']].add(row['curriculum_lesson_id'])
        projections = forecast([event for event in events if identity(event) not in matches], runs, steps, closed, at)
    visible_facts = set()
    for item in items:
        key = identity(item)
        if key in matches:
            item['learning'] = matches[key]
            visible_facts.add(matches[key]['lesson_id'])
            item['planning_status'] = item['status']
            item['status'] = 'recorded'
            item.update(is_past=True, can_confirm=False, can_respond=False, can_manage_teachers=False)
        elif item['is_cancelled']:
            item['learning'] = dict(kind='cancelled')
        elif item['is_past']:
            item['learning'] = dict(kind='unrecorded')
        else:
            item['learning'] = projections.get(key, dict(kind='no_plan'))
    # Preserve actual lessons predating the new calendar, and do not duplicate matched facts.
    items.extend(recorded_event(fact) for fact in journal if fact['id'] not in visible_facts)
    return items


def get_recorded(cur, lesson_id):
    from .calendar import now
    sql, args = fact_scope()
    tomorrow = datetime.combine(now().date() + timedelta(days=1), time())
    rows = fetch_all(cur, f'{FACT_SELECT} WHERE l.id=%s AND {sql} AND l.starts_at < %s', (lesson_id, *args, tomorrow))
    if not rows:
        abort(404, description='Проведённое занятие не найдено или недоступно')
    return recorded_event(rows[0])
