"""External branch cabinet and owner invoicing, with explicit scopes and immutable issue snapshots."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import date, datetime, time, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from html import escape
from zoneinfo import ZoneInfo

from flask import Blueprint, Response, abort, g, request
from mysql.connector import IntegrityError
from werkzeug.exceptions import HTTPException

from shared import db_cursor, exec_one, fetch_all, fetch_one, require_auth, require_role, hash_password, _ok, _err

portal_bp = Blueprint('branch_portal', __name__)
invoices_bp = Blueprint('branch_invoices', __name__)
STATUSES = {'draft', 'issued', 'payment_reported', 'paid', 'cancelled'}
CENT = Decimal('0.01')


@portal_bp.errorhandler(HTTPException)
@invoices_bp.errorhandler(HTTPException)
def http_error(error):
    return _err(error.description, status=error.code)


@portal_bp.errorhandler(IntegrityError)
@invoices_bp.errorhandler(IntegrityError)
def integrity_error(error):
    if error.errno == 1062:
        return _err('Такая запись уже существует. Обновите список.', status=409)
    return _err('Не удалось сохранить запись: проверьте связанные данные.', status=400)


def now():
    return datetime.now(ZoneInfo('Europe/Moscow')).replace(tzinfo=None, microsecond=0)


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, description='Ожидается JSON-объект')
    return data


def integer(value, label='Идентификатор'):
    if isinstance(value, bool) or not re.fullmatch(r'[1-9]\d{0,17}', str(value)):
        abort(400, description=f'{label}: укажите положительное целое число')
    return int(value)


def money(value, label='Сумма', maximum='99999999.99'):
    try:
        if isinstance(value, bool) or value is None:
            raise ValueError()
        number = Decimal(str(value))
        if not number.is_finite() or number < 0 or number > Decimal(maximum):
            raise ValueError()
        return number.quantize(CENT, rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError):
        abort(400, description=f'{label}: укажите неотрицательное число до {maximum}')


def text_value(value, label='Текст', limit=5000, required=False):
    if value is None:
        value = ''
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        abort(400, description=f'{label}: {"обязательное поле, " if required else ""}не более {limit} символов')
    return value.strip()


def month_value(value=None):
    result = str(value or now().strftime('%Y-%m'))
    if not re.fullmatch(r'20\d{2}-(0[1-9]|1[0-2])', result):
        abort(400, description='Месяц: укажите ГГГГ-ММ')
    return result


def month_range(month):
    start = date.fromisoformat(month + '-01')
    end = date(start.year + (start.month == 12), start.month % 12 + 1, 1)
    return datetime.combine(start, time()), datetime.combine(end, time())


def optional_date(value, label='Дата'):
    if value in (None, ''):
        return None
    try:
        if not re.fullmatch(r'20\d{2}-\d\d-\d\d', str(value)):
            raise ValueError()
        return date.fromisoformat(value)
    except (ValueError, TypeError):
        abort(400, description=f'{label}: укажите ГГГГ-ММ-ДД')


def owner_scope(alias='b'):
    user = g.current_user
    if user.role != 'OWNER' or not user.owner_id:
        abort(403, description='Требуется доступ администратора')
    return (f'EXISTS (SELECT 1 FROM department_owners own WHERE own.department_id={alias}.department_id AND own.owner_id=%s)', (user.owner_id,))


def branch_row(cur, branch_id=None, lock=False):
    user = g.current_user
    if user.role == 'BRANCH':
        branch_id = user.branch_id
        clause, params = 'b.is_active=1', ()
    else:
        branch_id = integer(branch_id, 'Сад')
        clause, params = owner_scope()
    row = fetch_one(cur, f'''SELECT b.id,b.name,b.address,b.department_id,b.price_per_child,b.is_active,
        d.name AS department_name FROM branches b JOIN departments d ON d.id=b.department_id
        WHERE b.id=%s AND {clause}''' + (' FOR UPDATE' if lock else ''), (branch_id, *params))
    if not row:
        abort(404, description='Сад не найден или недоступен')
    return row


def pricing(cur, branch_id, month):
    row = fetch_one(cur, 'SELECT retail_price_per_child,updated_at FROM branch_retail_prices WHERE branch_id=%s AND month=%s', (branch_id, month))
    return dict(month=month, retail_price_per_child=row['retail_price_per_child'] if row else None,
                updated_at=row['updated_at'] if row else None)


def recorded_lessons(cur, branch_id, month, retail=None):
    start, end = month_range(month)
    rows = fetch_all(cur, '''SELECT l.id,l.starts_at,l.teacher_id,t.full_name AS teacher_name,t.color AS teacher_color,
        l.instruction_id,i.name AS instruction_name,cl.name AS curriculum_lesson_name,l.is_creative,
        l.paid_children,l.trial_children,(l.paid_children+l.trial_children) AS total_children,l.price_snapshot,
        (l.paid_children*l.price_snapshot) AS amount
        FROM lessons l JOIN teachers t ON t.id=l.teacher_id
        LEFT JOIN instructions i ON i.id=l.instruction_id
        LEFT JOIN curriculum_lessons cl ON cl.id=l.curriculum_lesson_id
        WHERE l.branch_id=%s AND l.starts_at >= %s AND l.starts_at < %s
        ORDER BY l.starts_at DESC,l.id DESC''', (branch_id,start,end))
    for row in rows:
        row['amount'] = money(row['amount'], maximum='999999999999.99')
        row['estimated_revenue'] = (Decimal(row['paid_children']) * Decimal(str(retail))).quantize(CENT) if retail is not None else None
        row['estimated_profit'] = row['estimated_revenue'] - row['amount'] if retail is not None else None
    return rows


def upcoming_lessons(cur, branch_id, month):
    """Expand existing calendar versions without materializing occurrences or responses."""
    from .calendar import version_for, virtual
    start, end = month_range(month)
    lower = max(start, now())
    if lower >= end:
        return []
    series = fetch_all(cur, 'SELECT * FROM calendar_series WHERE branch_id=%s ORDER BY id', (branch_id,))
    versions = fetch_all(cur, '''SELECT v.* FROM calendar_versions v JOIN calendar_series s ON s.id=v.series_id
        WHERE s.branch_id=%s ORDER BY v.id''', (branch_id,))
    stored = fetch_all(cur, '''SELECT o.* FROM calendar_occurrences o JOIN calendar_series s ON s.id=o.series_id
        WHERE s.branch_id=%s AND (o.week_start >= %s AND o.week_start < %s OR o.starts_at >= %s AND o.starts_at < %s)''',
        (branch_id, start.date()-timedelta(days=start.weekday()), end.date(), start, end))
    rows = {(r['series_id'],r['week_start']): r for r in stored}
    week = start.date()-timedelta(days=start.weekday())
    while week < end.date():
        for rule in series:
            key = (rule['id'],week)
            version = version_for([v for v in versions if v['series_id']==rule['id']],week)
            if key not in rows and version and version['is_active']:
                rows[key] = virtual(cur,rule,version,week)
        week += timedelta(days=7)
    result = []
    for row in rows.values():
        if lower <= row['starts_at'] < end:
            status = 'cancelled' if row['is_cancelled'] else 'needs_replacement' if row['needs_replacement'] else 'confirmed' if row['confirmed_teacher_id'] else 'scheduled'
            result.append(dict(id=f"{row['series_id']}:{row['week_start']}", starts_at=row['starts_at'],
                duration_minutes=row['duration_minutes'],teacher_name=row['confirmed_teacher_name'] or row['planned_teacher_name'],status=status))
    return sorted(result,key=lambda r:r['starts_at'])


def invoice_row(cur, invoice_id, lock=False):
    user = g.current_user
    if user.role == 'BRANCH':
        clause, params = "i.branch_id=%s AND i.status<>'draft' AND i.issued_at IS NOT NULL", (user.branch_id,)
    else:
        clause, params = owner_scope()
    row = fetch_one(cur, f'''SELECT i.* FROM branch_invoices i JOIN branches b ON b.id=i.branch_id
        WHERE i.id=%s AND {clause}''' + (' FOR UPDATE' if lock else ''), (invoice_id,*params))
    if not row:
        abort(404, description='Счёт не найден или недоступен')
    return row


def invoice_detail(cur, invoice_id):
    row = invoice_row(cur,invoice_id)
    row['items'] = fetch_all(cur, 'SELECT * FROM branch_invoice_items WHERE invoice_id=%s ORDER BY sort_order,id', (invoice_id,))
    row['events'] = fetch_all(cur, 'SELECT action,actor_name,note,created_at FROM branch_invoice_events WHERE invoice_id=%s ORDER BY id', (invoice_id,))
    if g.current_user.role == 'BRANCH':
        row['events'] = [e for e in row['events'] if e['action'] not in ('created','updated')]
    row['delivery_channel'] = 'cabinet'
    return row


def invoice_list(cur, month=None, branch_id=None, status=None):
    user = g.current_user
    if user.role == 'BRANCH':
        clauses, params = ["i.branch_id=%s", "i.status<>'draft'", 'i.issued_at IS NOT NULL'], [user.branch_id]
    else:
        clause, args = owner_scope()
        clauses, params = [clause], list(args)
        if branch_id:
            branch_row(cur,branch_id)
            clauses.append('i.branch_id=%s')
            params.append(integer(branch_id))
    if month:
        clauses.append('i.month=%s')
        params.append(month_value(month))
    if status:
        if status not in STATUSES:
            abort(400,description='Неизвестный статус счёта')
        clauses.append('i.status=%s')
        params.append(status)
    return fetch_all(cur, f'''SELECT i.* FROM branch_invoices i JOIN branches b ON b.id=i.branch_id
        WHERE {' AND '.join(clauses)} ORDER BY i.month DESC,i.id DESC LIMIT 1000''', tuple(params))


def invoice_summary(items):
    return dict(total_amount=sum((Decimal(str(r['total_amount'])) for r in items if r['status']!='cancelled'),Decimal(0)),
        outstanding_amount=sum((Decimal(str(r['total_amount'])) for r in items if r['status'] in ('issued','payment_reported')),Decimal(0)),
        paid_amount=sum((Decimal(str(r['total_amount'])) for r in items if r['status']=='paid'),Decimal(0)),
        payment_reported_count=sum(r['status']=='payment_reported' for r in items),
        draft_count=sum(r['status']=='draft' for r in items))


def expected_revision(row, data):
    if integer(data.get('revision'), 'Версия счёта') != row['revision']:
        abort(409,description='Счёт изменён другим пользователем. Обновите его и повторите действие.')


def event(cur, invoice_id, action, note=''):
    user = g.current_user
    exec_one(cur, 'INSERT INTO branch_invoice_events(invoice_id,actor_user_id,actor_name,action,note) VALUES (%s,%s,%s,%s,%s)',
        (invoice_id,user.id,user.login,action,note))


def validated_items(cur, raw_items, branch_id, month):
    if not isinstance(raw_items,list) or not 1 <= len(raw_items) <= 500:
        abort(400,description='Добавьте от 1 до 500 строк счёта')
    result = []
    for item in raw_items:
        if not isinstance(item,dict):
            abort(400,description='Некорректная строка счёта')
        lesson_id = integer(item['lesson_id']) if item.get('lesson_id') else None
        if lesson_id:
            start,end = month_range(month)
            lesson = fetch_one(cur, 'SELECT id FROM lessons WHERE id=%s AND branch_id=%s AND starts_at >= %s AND starts_at < %s', (lesson_id,branch_id,start,end))
            if not lesson:
                abort(400,description='Занятие в строке не принадлежит выбранному саду и месяцу')
        quantity = money(item.get('quantity'), 'Количество', '999999.99')
        price = money(item.get('unit_price'), 'Стоимость')
        amount = money(quantity*price, maximum='999999999999.99')
        lesson_date = item.get('lesson_date')
        if lesson_date:
            try:
                lesson_date = datetime.fromisoformat(str(lesson_date))
                if lesson_date.tzinfo is not None or not 2000 <= lesson_date.year <= 2099:
                    raise ValueError()
            except (TypeError,ValueError):
                abort(400,description='Некорректная дата занятия в строке')
        result.append(dict(lesson_id=lesson_id,description=text_value(item.get('description'),'Описание строки',1000,True),
            lesson_date=lesson_date or None,teacher_name=text_value(item.get('teacher_name'),'Преподаватель',255),quantity=quantity,unit_price=price,amount=amount))
    total = money(sum((i['amount'] for i in result),Decimal(0)),maximum='999999999999.99')
    return result,total


def save_items(cur, invoice_id, items):
    cur.execute('DELETE FROM branch_invoice_items WHERE invoice_id=%s', (invoice_id,))
    for index,item in enumerate(items):
        exec_one(cur, '''INSERT INTO branch_invoice_items(invoice_id,sort_order,lesson_id,description,lesson_date,teacher_name,quantity,unit_price,amount)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''', (invoice_id,index,item['lesson_id'],item['description'],item['lesson_date'],item['teacher_name'],item['quantity'],item['unit_price'],item['amount']))


@portal_bp.get('/overview')
@require_auth
@require_role('BRANCH')
def overview():
    month = month_value(request.args.get('month'))
    with db_cursor() as (_,cur):
        branch = branch_row(cur)
        price = pricing(cur,branch['id'],month)
        lessons = recorded_lessons(cur,branch['id'],month,price['retail_price_per_child'])
        invoices = invoice_list(cur,month)
        upcoming = upcoming_lessons(cur,branch['id'],month)
    daily = defaultdict(lambda:dict(lessons_count=0,paid_children=0,trial_children=0,amount=Decimal(0)))
    for lesson in lessons:
        day = daily[str(lesson['starts_at'])[:10]]
        day['lessons_count'] += 1
        day['paid_children'] += lesson['paid_children']
        day['trial_children'] += lesson['trial_children']
        day['amount'] += lesson['amount']
    summary = dict(lessons_count=len(lessons),paid_children=sum(l['paid_children'] for l in lessons),
        trial_children=sum(l['trial_children'] for l in lessons),total_children=sum(l['total_children'] for l in lessons),
        accrued_amount=sum((l['amount'] for l in lessons),Decimal(0)),
        invoiced_amount=sum((Decimal(str(i['total_amount'])) for i in invoices if i['status']!='cancelled'),Decimal(0)),
        paid_amount=sum((Decimal(str(i['total_amount'])) for i in invoices if i['status']=='paid'),Decimal(0)),
        outstanding_amount=sum((Decimal(str(i['total_amount'])) for i in invoices if i['status'] in ('issued','payment_reported')),Decimal(0)),
        estimated_revenue=sum((l['estimated_revenue'] for l in lessons),Decimal(0)) if price['retail_price_per_child'] is not None else None,
        estimated_profit=sum((l['estimated_profit'] for l in lessons),Decimal(0)) if price['retail_price_per_child'] is not None else None)
    return _ok(dict(branch=branch,month=month,pricing=price,summary=summary,lessons=lessons,invoices=invoices,upcoming=upcoming,
        daily=[dict(date=day,**values) for day,values in sorted(daily.items())]))


@portal_bp.get('/lessons')
@require_auth
@require_role('BRANCH')
def portal_lessons():
    month = month_value(request.args.get('month'))
    with db_cursor() as (_,cur):
        branch = branch_row(cur)
        price = pricing(cur,branch['id'],month)
        return _ok(dict(items=recorded_lessons(cur,branch['id'],month,price['retail_price_per_child'])))


@portal_bp.get('/pricing')
@require_auth
@require_role('BRANCH')
def get_pricing():
    month = month_value(request.args.get('month'))
    with db_cursor() as (_,cur):
        branch = branch_row(cur)
        return _ok(pricing(cur,branch['id'],month))


@portal_bp.put('/pricing')
@require_auth
@require_role('BRANCH')
def update_pricing():
    data = body()
    month = month_value(request.args.get('month'))
    if 'retail_price_per_child' not in data:
        abort(400,description='Укажите розничную стоимость')
    retail = money(data['retail_price_per_child'],'Розничная стоимость') if data['retail_price_per_child'] is not None else None
    with db_cursor() as (_,cur):
        branch = branch_row(cur,lock=True)
        cur.execute('DELETE FROM branch_retail_prices WHERE branch_id=%s AND month=%s',(branch['id'],month))
        if retail is not None:
            exec_one(cur, 'INSERT INTO branch_retail_prices(branch_id,month,retail_price_per_child,updated_by_user_id) VALUES (%s,%s,%s,%s)',(branch['id'],month,retail,g.current_user.id))
        return _ok(pricing(cur,branch['id'],month))


@portal_bp.get('/invoices')
@require_auth
@require_role('BRANCH')
def portal_invoices():
    with db_cursor() as (_,cur):
        return _ok(dict(items=invoice_list(cur,request.args.get('month'))))


@portal_bp.get('/invoices/<int:invoice_id>')
@require_auth
@require_role('BRANCH')
def portal_invoice(invoice_id):
    with db_cursor() as (_,cur):
        return _ok(invoice_detail(cur,invoice_id))


@portal_bp.post('/invoices/<int:invoice_id>/report-payment')
@require_auth
@require_role('BRANCH')
def report_payment(invoice_id):
    data = body()
    note = text_value(data.get('note'),'Комментарий')
    payment_date = optional_date(data.get('payment_date'),'Дата оплаты') or now().date()
    if payment_date > now().date():
        abort(400,description='Дата оплаты не может быть в будущем')
    with db_cursor() as (_,cur):
        row = invoice_row(cur,invoice_id,lock=True)
        expected_revision(row,data)
        if row['status'] != 'issued':
            abort(409,description='Сообщить об оплате можно только для выставленного счёта')
        cur.execute("UPDATE branch_invoices SET status='payment_reported',payment_reported_at=%s,payment_date=%s,payment_note=%s,revision=revision+1 WHERE id=%s",(now(),payment_date,note,invoice_id))
        event(cur,invoice_id,'payment_reported',note)
        return _ok(invoice_detail(cur,invoice_id))


@invoices_bp.get('/invoices')
@require_auth
@require_role('OWNER')
def list_invoices():
    with db_cursor() as (_,cur):
        items = invoice_list(cur,request.args.get('month'),request.args.get('branch_id'),request.args.get('status'))
        return _ok(dict(items=items,summary=invoice_summary(items)))


@invoices_bp.get('/invoices/report')
@require_auth
@require_role('OWNER')
def report_preview():
    month = month_value(request.args.get('month'))
    with db_cursor() as (_,cur):
        branch = branch_row(cur,request.args.get('branch_id'))
        lessons = recorded_lessons(cur,branch['id'],month)
        defaults = fetch_one(cur, 'SELECT seller_details,payment_details,buyer_details FROM branch_invoices WHERE branch_id=%s ORDER BY id DESC LIMIT 1', (branch['id'],)) or {}
    items = [dict(lesson_id=l['id'],description=l['curriculum_lesson_name'] or l['instruction_name'] or ('Творческое занятие' if l['is_creative'] else 'Занятие по робототехнике'),
        lesson_date=l['starts_at'],teacher_name=l['teacher_name'],quantity=l['paid_children'],unit_price=l['price_snapshot'],amount=l['amount']) for l in reversed(lessons) if l['paid_children'] > 0]
    return _ok(dict(items=items,total_amount=sum((i['amount'] for i in items),Decimal(0)),month=month,branch=branch,**defaults))


@invoices_bp.post('/invoices')
@require_auth
@require_role('OWNER')
def create_invoice():
    data = body()
    month = month_value(data.get('month'))
    with db_cursor() as (_,cur):
        branch = branch_row(cur,data.get('branch_id'),lock=True)
        existing = fetch_one(cur,"SELECT id FROM branch_invoices WHERE branch_id=%s AND month=%s AND status<>'cancelled'",(branch['id'],month))
        if existing:
            abort(409,description='За этот месяц уже есть счёт. Откройте существующий или отмените его.')
        items,total = validated_items(cur,data.get('items'),branch['id'],month)
        invoice_id = exec_one(cur,'''INSERT INTO branch_invoices(branch_id,branch_name,month,title,total_amount,due_date,note,seller_details,buyer_details,payment_details,created_by_user_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (branch['id'],branch['name'],month,text_value(data.get('title') or f'Занятия за {month}','Название',255,True),total,
             optional_date(data.get('due_date'),'Срок оплаты'),text_value(data.get('note'),'Комментарий'),
             text_value(data.get('seller_details'),'Исполнитель'),text_value(data.get('buyer_details') or f"{branch['name']}\n{branch['address']}",'Плательщик'),
             text_value(data.get('payment_details'),'Реквизиты'),g.current_user.id))
        cur.execute('UPDATE branch_invoices SET number=%s WHERE id=%s',(f'СЧ-{month.replace("-","")}-{invoice_id:05d}',invoice_id))
        save_items(cur,invoice_id,items)
        event(cur,invoice_id,'created')
        return _ok(invoice_detail(cur,invoice_id))


@invoices_bp.get('/invoices/<int:invoice_id>')
@require_auth
@require_role('OWNER')
def get_invoice(invoice_id):
    with db_cursor() as (_,cur):
        return _ok(invoice_detail(cur,invoice_id))


@invoices_bp.put('/invoices/<int:invoice_id>')
@require_auth
@require_role('OWNER')
def update_invoice(invoice_id):
    data = body()
    with db_cursor() as (_,cur):
        row = invoice_row(cur,invoice_id,lock=True)
        expected_revision(row,data)
        if row['status'] != 'draft':
            abort(409,description='Изменять можно только черновик. Для исправления выставленного счёта отмените его и создайте новый.')
        fields,params = [],[]
        for field in ('title','note','seller_details','buyer_details','payment_details'):
            if field in data:
                fields.append(f'{field}=%s')
                params.append(text_value(data[field],field,255 if field=='title' else 5000,field=='title'))
        if 'due_date' in data:
            fields.append('due_date=%s')
            params.append(optional_date(data['due_date'],'Срок оплаты'))
        if 'items' in data:
            items,total = validated_items(cur,data['items'],row['branch_id'],row['month'])
            fields.append('total_amount=%s')
            params.append(total)
            save_items(cur,invoice_id,items)
        if not fields:
            abort(400,description='Нет изменений')
        cur.execute(f"UPDATE branch_invoices SET {','.join(fields)},revision=revision+1 WHERE id=%s",(*params,invoice_id))
        event(cur,invoice_id,'updated')
        return _ok(invoice_detail(cur,invoice_id))


@invoices_bp.post('/invoices/<int:invoice_id>/<action>')
@require_auth
@require_role('OWNER')
def transition_invoice(invoice_id,action):
    if action not in ('issue','confirm-payment','reject-payment','cancel'):
        abort(404)
    data = body()
    note = text_value(data.get('note'),'Комментарий')
    with db_cursor() as (_,cur):
        row = invoice_row(cur,invoice_id,lock=True)
        expected_revision(row,data)
        if action=='issue':
            if row['status']!='draft':
                abort(409,description='Выставить можно только черновик')
            if not (row.get('seller_details') or '').strip() or not (row.get('payment_details') or '').strip():
                abort(400,description='Заполните исполнителя и реквизиты для оплаты')
            if Decimal(str(row['total_amount'])) <= 0:
                abort(400,description='Сумма выставляемого счёта должна быть больше нуля')
            cur.execute("UPDATE branch_invoices SET status='issued',issued_at=%s,revision=revision+1 WHERE id=%s",(now(),invoice_id))
            event(cur,invoice_id,'issued','Счёт доставлен в кабинет сада' + (f'. {note}' if note else ''))
        elif action=='confirm-payment':
            if row['status'] not in ('issued','payment_reported'):
                abort(409,description='Оплату этого счёта нельзя подтвердить')
            cur.execute("UPDATE branch_invoices SET status='paid',paid_at=%s,paid_by_user_id=%s,revision=revision+1 WHERE id=%s",(now(),g.current_user.id,invoice_id))
            event(cur,invoice_id,'paid',note)
        elif action=='reject-payment':
            if row['status']!='payment_reported':
                abort(409,description='Нет сообщения об оплате для проверки')
            if not note:
                abort(400,description='Укажите причину, чтобы сад понял результат проверки')
            cur.execute("UPDATE branch_invoices SET status='issued',revision=revision+1 WHERE id=%s",(invoice_id,))
            event(cur,invoice_id,'payment_rejected',note)
        else:
            if row['status'] in ('paid','cancelled'):
                abort(409,description='Нельзя отменить оплаченный или уже отменённый счёт')
            if not note:
                abort(400,description='Укажите причину отмены')
            cur.execute("UPDATE branch_invoices SET status='cancelled',cancelled_at=%s,revision=revision+1 WHERE id=%s",(now(),invoice_id))
            event(cur,invoice_id,'cancelled',note)
        return _ok(invoice_detail(cur,invoice_id))


def printable_invoice(row):
    def esc(value):
        return escape(str(value or '')).replace('\n','<br>')
    rows = ''.join(f"<tr><td>{n+1}</td><td>{esc(i['description'])}<small>{esc(i.get('lesson_date'))} · {esc(i.get('teacher_name'))}</small></td><td>{i['quantity']}</td><td>{i['unit_price']:.2f}</td><td>{i['amount']:.2f}</td></tr>" for n,i in enumerate(row['items']))
    html = f'''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(row['number'])}</title>
    <style>body{{font:15px/1.5 Arial,sans-serif;color:#162522;max-width:900px;margin:40px auto;padding:0 24px}}h1{{font-size:28px}}h2{{font-size:16px;margin-top:26px}}small{{display:block;color:#64746e}}table{{width:100%;border-collapse:collapse;margin:24px 0}}td,th{{padding:12px;text-align:left;border-bottom:1px solid #dce3e0}}tr{{break-inside:avoid}}.total{{text-align:right;font-size:22px}}.notice{{padding:14px;background:#f1f6f4}}@page{{size:A4;margin:18mm}}@media print{{body{{margin:0;padding:0;font-size:11px}}button{{display:none}}thead{{display:table-header-group}}h2{{break-after:avoid}}}}</style>
    <button onclick="window.print()">Печать / сохранить PDF</button><h1>Счёт {esc(row['number'])}</h1>
    <p>{esc(row['title'])}<br>Дата счёта: {esc(str(row.get('issued_at') or row['created_at'])[:10])}<br>Период: {esc(row['month'])}<br>Срок оплаты: {esc(row['due_date']) or 'не указан'}</p>
    <h2>Исполнитель</h2><p>{esc(row['seller_details'])}</p><h2>Плательщик</h2><p>{esc(row['buyer_details'])}</p>
    <h2>Реквизиты для оплаты</h2><p>{esc(row['payment_details'])}</p>
    <table><thead><tr><th>№</th><th>Услуга</th><th>Кол-во</th><th>Цена, ₽</th><th>Сумма, ₽</th></tr></thead><tbody>{rows}</tbody></table>
    <p class="total">Итого: {row['total_amount']:.2f} ₽</p><p>{esc(row['note'])}</p>
    <p class="notice">{'ЧЕРНОВИК · не выставлен' if row['status']=='draft' else 'СЧЁТ ОТМЕНЁН' if row['status']=='cancelled' else 'ОПЛАЧЕН' if row['status']=='paid' else 'К оплате'}<br>В назначении платежа укажите номер счёта.</p></html>'''
    return Response(html, content_type='text/html; charset=utf-8', headers={'Content-Disposition':f'inline; filename="invoice-{row["id"]}.html"','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})


@portal_bp.get('/invoices/<int:invoice_id>/document')
@require_auth
@require_role('BRANCH')
def portal_document(invoice_id):
    with db_cursor() as (_,cur):
        return printable_invoice(invoice_detail(cur,invoice_id))


@invoices_bp.get('/invoices/<int:invoice_id>/document')
@require_auth
@require_role('OWNER')
def owner_document(invoice_id):
    with db_cursor() as (_,cur):
        return printable_invoice(invoice_detail(cur,invoice_id))


def branch_account(cur,user_id):
    clause,args = owner_scope()
    row = fetch_one(cur,f'''SELECT u.id,u.branch_id,b.name branch_name,b.is_active branch_is_active,u.login,u.is_active,u.created_at,u.updated_at
        FROM auf_users u JOIN branches b ON b.id=u.branch_id WHERE u.id=%s AND u.role='BRANCH' AND {clause}''',(user_id,*args))
    if not row:
        abort(404,description='Кабинет не найден или недоступен')
    return row


@invoices_bp.get('/branch-access')
@require_auth
@require_role('OWNER')
def list_branch_accounts():
    clause,args = owner_scope()
    with db_cursor() as (_,cur):
        rows = fetch_all(cur,f'''SELECT u.id,u.branch_id,b.name branch_name,b.is_active branch_is_active,u.login,u.is_active,u.created_at,u.updated_at
            FROM auf_users u JOIN branches b ON b.id=u.branch_id WHERE u.role='BRANCH' AND {clause} ORDER BY b.name,u.id''',args)
        return _ok(dict(items=rows))


@invoices_bp.post('/branch-access')
@require_auth
@require_role('OWNER')
def create_branch_account():
    data = body()
    login = text_value(data.get('login'),'Логин',64,True)
    password = hash_password(data.get('password'))
    if 'is_active' in data and data['is_active'] not in (True,False,0,1):
        abort(400,description='Некорректный признак активности')
    with db_cursor() as (_,cur):
        branch = branch_row(cur,data.get('branch_id'),lock=True)
        if fetch_one(cur,"SELECT id FROM auf_users WHERE branch_id=%s AND role='BRANCH'",(branch['id'],)):
            abort(409,description='У сада уже есть кабинет. Измените или включите существующий доступ.')
        user_id = exec_one(cur,"INSERT INTO auf_users(login,password_hash,role,branch_id,is_active) VALUES (%s,%s,'BRANCH',%s,%s)",
            (login,password,branch['id'],int(data.get('is_active',True))))
        return _ok(branch_account(cur,user_id))


@invoices_bp.put('/branch-access/<int:user_id>')
@require_auth
@require_role('OWNER')
def update_branch_account(user_id):
    data = body()
    with db_cursor() as (_,cur):
        current = branch_account(cur,user_id)
        if 'branch_id' in data and integer(data['branch_id']) != current['branch_id']:
            abort(400,description='Нельзя перенести кабинет в другой сад')
        fields,params = [],[]
        if 'login' in data:
            fields.append('login=%s')
            params.append(text_value(data['login'],'Логин',64,True))
        if data.get('password') not in (None,''):
            fields.append('password_hash=%s')
            params.append(hash_password(data['password']))
        if 'is_active' in data:
            if data['is_active'] not in (True,False,0,1):
                abort(400,description='Некорректный признак активности')
            fields.append('is_active=%s')
            params.append(int(data['is_active']))
        if not fields:
            abort(400,description='Нет изменений')
        cur.execute(f"UPDATE auf_users SET {','.join(fields)} WHERE id=%s",(*params,user_id))
        if 'password_hash=%s' in fields or ('is_active' in data and not data['is_active']):
            cur.execute('DELETE FROM auth_sessions WHERE user_id=%s',(user_id,))
        return _ok(branch_account(cur,user_id))
