"""
Ничаты — объединённый ИИ-ассистент CRM с доступом ко всем чатам.
Tools: все чаты, контекст любого чата, слоты, занятия, расписание, ветка.
Отправка сообщений — только через подтверждение на фронте (модель выводит блоки [PREPARE_MESSAGE]).
"""
from __future__ import annotations

import codecs
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Any

import requests
from flask import Flask, Response, abort, g, request, stream_with_context

from shared import db_cursor, fetch_all, fetch_one, get_current_user, require_auth

# Москва UTC+3
MOSCOW_OFFSET = timedelta(hours=3)


def _require_crm_access(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = getattr(g, "current_user", None) or get_current_user()
        g.current_user = u
        if u.role != "OWNER":
            abort(403, description="CRM access only for owners")
        with db_cursor() as (_, cur):
            row = fetch_one(cur, "SELECT crm_access FROM auf_users WHERE id=%s", (u.id,))
            if not row or int(row.get("crm_access") or 0) != 1:
                abort(403, description="CRM access not granted")
        return fn(*args, **kwargs)

    return wrapper


def _get_aitunnel_api_key() -> str | None:
    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT value_text FROM settings WHERE `key`=%s", ("aitunnel_api_key",))
        if not row or not row.get("value_text"):
            return None
        return str(row["value_text"]).strip() or None


def _moscow_now() -> str:
    now = datetime.now(timezone.utc) + MOSCOW_OFFSET
    return now.strftime("%d.%m.%Y, %H:%M")


def _moscow_date_iso() -> str:
    """YYYY-MM-DD для передачи в тулы."""
    now = datetime.now(timezone.utc) + MOSCOW_OFFSET
    return now.strftime("%Y-%m-%d")


def _month_range_iso() -> tuple[str, str]:
    """Первый и последний день текущего месяца по Москве."""
    now = datetime.now(timezone.utc) + MOSCOW_OFFSET
    first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if now.month == 12:
        last = now.replace(day=31)
    else:
        next_month = now.replace(month=now.month + 1, day=1)
        last = next_month - timedelta(days=1)
    return first.strftime("%Y-%m-%d"), last.strftime("%Y-%m-%d")


def _format_moscow(dt) -> str:
    if dt is None:
        return ""
    try:
        if getattr(dt, "tzinfo", None) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        utc = dt.astimezone(timezone.utc)
        moscow = utc.replace(tzinfo=None) + MOSCOW_OFFSET
        return moscow.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return str(dt)


# --- Tools (без branch_id — работа по chat_id) ---

def _tool_get_all_chats() -> list:
    """Все CRM-чаты с информацией о филиале."""
    with db_cursor() as (_, cur):
        rows = fetch_all(
            cur,
            """
            SELECT cc.id, cc.branch_id, cc.display_name, b.name AS branch_name, b.address
            FROM crm_chats cc
            JOIN branches b ON b.id = cc.branch_id
            JOIN crm_branches cb ON cb.branch_id = cc.branch_id
            ORDER BY b.name, cc.id
            """,
            (),
        )
        return [
            {
                "chat_id": r.get("id"),
                "branch_id": r.get("branch_id"),
                "display_name": r.get("display_name") or "",
                "branch_name": r.get("branch_name") or "",
                "address": (r.get("address") or "").strip() or "—",
            }
            for r in rows
        ]


def _tool_get_chat_context(chat_id: int, limit: int = 50) -> list:
    """Последние сообщения чата."""
    with db_cursor() as (_, cur):
        ok = fetch_one(cur, "SELECT id, branch_id FROM crm_chats WHERE id=%s", (chat_id,))
        if not ok:
            return []
        rows = fetch_all(
            cur,
            "SELECT m.direction, m.content, m.created_at FROM crm_messages m WHERE m.crm_chat_id=%s ORDER BY m.id DESC LIMIT %s",
            (chat_id, limit),
        )
    rows = list(reversed(rows))
    return [
        {
            "role": "Клиент" if r["direction"] == "in" else "Менеджер",
            "content": (r.get("content") or "").strip() or "—",
            "created_at_moscow": _format_moscow(r.get("created_at")),
        }
        for r in rows
    ]


def _tool_free_slots(day_of_week: int | None = None) -> list:
    with db_cursor() as (_, cur):
        where = "ts.status='free'"
        params: list[Any] = []
        if day_of_week is not None:
            where += " AND ts.day_of_week=%s"
            params.append(int(day_of_week))
        rows = fetch_all(
            cur,
            f"""
            SELECT ts.day_of_week, ts.start_time, t.full_name AS teacher_name
            FROM teacher_slots ts
            JOIN teachers t ON t.id=ts.teacher_id
            WHERE {where}
            ORDER BY ts.day_of_week, ts.start_time
            LIMIT 100
            """,
            tuple(params) if params else (),
        )
        days = ["", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
        return [
            {
                "day": days[int(r.get("day_of_week") or 0)] if 1 <= int(r.get("day_of_week") or 0) <= 7 else str(r.get("day_of_week")),
                "time": str(r.get("start_time") or "")[:5],
                "teacher": r.get("teacher_name"),
            }
            for r in rows
        ]


def _tool_lessons(branch_id: int, start_date: str, end_date: str) -> list:
    with db_cursor() as (_, cur):
        ok = fetch_one(cur, "SELECT 1 FROM crm_branches WHERE branch_id=%s", (branch_id,))
        if not ok:
            return []
        try:
            start_dt = datetime.fromisoformat(start_date[:10] + " 00:00:00")
            end_dt = datetime.fromisoformat(end_date[:10] + " 23:59:59")
        except Exception:
            return []
        branch_row = fetch_one(cur, "SELECT price_per_child FROM branches WHERE id=%s", (branch_id,))
        price_per_child = int(branch_row.get("price_per_child") or 0) if branch_row else 0
        rows = fetch_all(
            cur,
            """
            SELECT l.id, l.starts_at, l.paid_children, l.trial_children, t.full_name AS teacher_name
            FROM lessons l
            JOIN teachers t ON t.id=l.teacher_id
            WHERE l.branch_id=%s AND l.starts_at >= %s AND l.starts_at <= %s
            ORDER BY l.starts_at DESC
            LIMIT 100
            """,
            (branch_id, start_dt, end_dt),
        )
        months_ru = ["", "января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"]
        out = []
        for r in rows:
            st = r.get("starts_at")
            paid = int(r.get("paid_children") or 0)
            if hasattr(st, "strftime"):
                date_ru = f"{st.day} {months_ru[st.month]} {st.year}" if st else ""
                time_s = st.strftime("%H:%M")
            else:
                date_ru = str(st)[:10] if st else ""
                time_s = str(st)[11:16] if st and len(str(st)) >= 16 else ""
            sum_rub = paid * price_per_child if price_per_child else 0
            out.append({
                "id": r.get("id"),
                "date_ru": date_ru,
                "time": time_s,
                "teacher": r.get("teacher_name"),
                "paid": paid,
                "trial": int(r.get("trial_children") or 0),
                "price_per_child": price_per_child,
                "sum_rub": sum_rub,
            })
        return out


def _tool_branch_info(branch_id: int) -> dict:
    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT id, name, address, metro, price_per_child FROM branches WHERE id=%s", (branch_id,))
        if not row:
            return {}
        return {
            "id": row.get("id"),
            "name": row.get("name"),
            "address": row.get("address"),
            "metro": row.get("metro"),
            "price_per_child": int(row.get("price_per_child") or 0),
        }


def _tool_schedule(branch_id: int, weekday: int | None = None) -> list:
    with db_cursor() as (_, cur):
        ok = fetch_one(cur, "SELECT 1 FROM crm_branches WHERE branch_id=%s", (branch_id,))
        if not ok:
            return []
        where = "s.branch_id=%s"
        params: list[Any] = [branch_id]
        if weekday is not None:
            where += " AND s.weekday=%s"
            params.append(int(weekday))
        rows = fetch_all(
            cur,
            f"""
            SELECT s.weekday, s.starts_at, s.duration_minutes,
                   t.full_name AS teacher_name, b.name AS branch_name
            FROM schedules s
            JOIN branches b ON b.id=s.branch_id
            LEFT JOIN teachers t ON t.id=s.teacher_id
            WHERE {where}
            ORDER BY s.weekday, s.starts_at
            LIMIT 100
            """,
            tuple(params),
        )
        days = ["", "Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
        return [
            {
                "day": days[int(r.get("weekday") or 0)] if 1 <= int(r.get("weekday") or 0) <= 7 else str(r.get("weekday")),
                "time": str(r.get("starts_at") or "")[:5],
                "duration_min": int(r.get("duration_minutes") or 0),
                "teacher": r.get("teacher_name") or "—",
                "branch": r.get("branch_name"),
            }
            for r in rows
        ]


def _tool_invoices_all_branches(start_date: str, end_date: str) -> list:
    """Счета по ВСЕМ садикам (branch), сгруппированные по branch_name. Один садик = один счёт."""
    months_ru = ["", "января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"]
    try:
        start_dt = datetime.fromisoformat(start_date[:10] + " 00:00:00")
        end_dt = datetime.fromisoformat(end_date[:10] + " 23:59:59")
    except Exception:
        return []
    with db_cursor() as (_, cur):
        branches = fetch_all(
            cur,
            """
            SELECT cb.branch_id, b.name AS branch_name, b.price_per_child
            FROM crm_branches cb
            JOIN branches b ON b.id = cb.branch_id
            ORDER BY b.name
            """,
            (),
        )
        if not branches:
            return []
        out = []
        for br in branches:
            bid = int(br.get("branch_id") or 0)
            branch_name = (br.get("branch_name") or "").strip() or f"Филиал {bid}"
            price_per_child = int(br.get("price_per_child") or 0)
            lessons_rows = fetch_all(
                cur,
                """
                SELECT l.id, l.starts_at, l.paid_children, l.trial_children, t.full_name AS teacher_name
                FROM lessons l
                JOIN teachers t ON t.id = l.teacher_id
                WHERE l.branch_id = %s AND l.starts_at >= %s AND l.starts_at <= %s
                ORDER BY l.starts_at DESC
                LIMIT 100
                """,
                (bid, start_dt, end_dt),
            )
            chat_rows = fetch_all(
                cur,
                "SELECT id, display_name FROM crm_chats WHERE branch_id = %s ORDER BY id",
                (bid,),
            )
            chat_ids = [int(r["id"]) for r in chat_rows]
            chat_names = [r.get("display_name") or "" for r in chat_rows]
            lessons = []
            total_sum = 0
            for r in lessons_rows:
                st = r.get("starts_at")
                paid = int(r.get("paid_children") or 0)
                if hasattr(st, "strftime"):
                    date_ru = f"{st.day} {months_ru[st.month]} {st.year}" if st else ""
                    time_s = st.strftime("%H:%M")
                else:
                    date_ru = str(st)[:10] if st else ""
                    time_s = str(st)[11:16] if st and len(str(st)) >= 16 else ""
                sum_rub = paid * price_per_child if price_per_child else 0
                total_sum += sum_rub
                lessons.append({
                    "date_ru": date_ru,
                    "time": time_s,
                    "teacher": r.get("teacher_name"),
                    "paid": paid,
                    "trial": int(r.get("trial_children") or 0),
                    "sum_rub": sum_rub,
                })
            out.append({
                "branch_id": bid,
                "branch_name": branch_name,
                "chat_ids": chat_ids,
                "chat_display_names": chat_names,
                "lessons": lessons,
                "total_sum_rub": total_sum,
            })
        return out


NCHATS_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_all_chats",
            "description": "Список CRM-чатов. Возвращает chat_id, branch_id, display_name, branch_name, address. ВАЖНО: branch_name = название садика (Tiny Tony); display_name = имя контакта (Айсулу, Николай). Один садик (branch) может иметь несколько чатов (разные контакты). Для отправки сообщений нужен chat_id.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_invoices_all_branches",
            "description": "Счета по ВСЕМ садикам за период. Вызывай при запросах «счета по всем садикам», «счета за месяц», «что у нас по оплатам». Возвращает по каждому САДИКУ (branch_name): branch_id, branch_name, lessons, total_sum_rub, chat_ids. НЕ путай с чатами: садик (Tiny Tony) — один, чатов у него может быть несколько (Айсулу, Николай — это контакты, не садики).",
            "parameters": {
                "type": "object",
                "properties": {
                    "start_date": {"type": "string", "description": "YYYY-MM-DD"},
                    "end_date": {"type": "string", "description": "YYYY-MM-DD"},
                },
                "required": ["start_date", "end_date"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_chat_context",
            "description": "Последние сообщения из указанного чата. Используй, чтобы понять контекст переписки с садиком.",
            "parameters": {
                "type": "object",
                "properties": {
                    "chat_id": {"type": "integer", "description": "ID чата из get_all_chats"},
                    "limit": {"type": "integer", "description": "Количество сообщений (по умолчанию 50)"},
                },
                "required": ["chat_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_free_slots",
            "description": "Свободные слоты по всем преподавателям. Когда спрашивают о доступном времени.",
            "parameters": {
                "type": "object",
                "properties": {"day_of_week": {"type": "integer", "description": "1=Пн..7=Вс, необязательно"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_lessons_for_branch",
            "description": "Занятия филиала (садика) за период. Возвращает список с полями: date_ru, time, teacher, paid (платных мест), trial (пробных), price_per_child, sum_rub (сумма к оплате за занятие). Используй для счёта, выставления счёта, отчёта по занятиям. branch_id возьми из get_all_chats (Tiny Tony = branch_name). Для «этого месяца» — start_date=первый день, end_date=последний день месяца.",
            "parameters": {
                "type": "object",
                "properties": {
                    "branch_id": {"type": "integer", "description": "ID филиала из get_all_chats"},
                    "start_date": {"type": "string", "description": "YYYY-MM-DD, начало периода"},
                    "end_date": {"type": "string", "description": "YYYY-MM-DD, конец периода"},
                },
                "required": ["branch_id", "start_date", "end_date"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_branch_info",
            "description": "Информация о филиале: адрес, метро, цена за занятие.",
            "parameters": {
                "type": "object",
                "properties": {"branch_id": {"type": "integer"}},
                "required": ["branch_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_schedule",
            "description": "Расписание филиала: кто во сколько ведёт занятия.",
            "parameters": {
                "type": "object",
                "properties": {
                    "branch_id": {"type": "integer"},
                    "weekday": {"type": "integer", "description": "1=Пн..7=Вс, необязательно"},
                },
                "required": ["branch_id"],
            },
        },
    },
]


def _execute_nchats_tool(name: str, args: dict) -> Any:
    if name == "get_all_chats":
        return _tool_get_all_chats()
    if name == "get_invoices_all_branches":
        return _tool_invoices_all_branches(
            (args.get("start_date") or "")[:10],
            (args.get("end_date") or "")[:10],
        )
    if name == "get_chat_context":
        return _tool_get_chat_context(int(args.get("chat_id", 0)), int(args.get("limit", 50)))
    if name == "get_free_slots":
        return _tool_free_slots(args.get("day_of_week"))
    if name == "get_lessons_for_branch":
        return _tool_lessons(
            int(args.get("branch_id", 0)),
            (args.get("start_date") or "")[:10],
            (args.get("end_date") or "")[:10],
        )
    if name == "get_branch_info":
        return _tool_branch_info(int(args.get("branch_id", 0)))
    if name == "get_schedule":
        return _tool_schedule(int(args.get("branch_id", 0)), args.get("weekday"))
    return {"error": f"Unknown tool: {name}"}


def _build_system_prompt() -> str:
    now_moscow = _moscow_now()
    month_start, month_end = _month_range_iso()
    return f"""Ты — ИИ-ассистент менеджера CRM. У тебя есть доступ ко ВСЕМ чатам. Вы — IT-клуб/школа робототехники. Клиенты — это детские сады (садики).

СТРУКТУРА ДАННЫХ (не путай!):
- Садик (branch) = детский сад, наш клиент. Название: branch_name (Tiny Tony, Тинитони и т.п.).
- Чат (chat) = переписка с конкретным контактом. display_name = имя человека (Айсулу, Николай). Один садик может иметь НЕСКОЛЬКО чатов (разные люди).
- Счёт, занятия — привязаны к САДИКУ (branch), а не к чату. Tiny Tony = один счёт, даже если у него два чата (Айсулу и Николай).

Сейчас по Москве: {now_moscow}. Текущий месяц: с {month_start} по {month_end}.

СЧЁТА ПО ВСЕМ САДИКАМ — всегда вызывай get_invoices_all_branches("{month_start}", "{month_end}"). Этот тул возвращает счета, сгруппированные по branch_name (по садикам). НЕ вызывай get_lessons_for_branch для каждого чата — чаты не равны садикам!

Счёт по ОДНОМУ садику: get_lessons_for_branch(branch_id, ...). branch_id возьми из get_all_chats по branch_name.

Отправка сообщений: выводи в формате:
[PREPARE_MESSAGE chat_id=ЧИСЛО chat_name="Название садика"]
Текст сообщения для клиента
[/PREPARE_MESSAGE]

Один блок на одно сообщение. Менеджер увидит карточку, сможет отредактировать и подтвердить отправку.

При выдаче списка занятий оформляй каждое так:
**ДД месяц ГГГГ** — ЧЧ:ММ
Преподаватель: Имя
Платные: N
Пробные: N
Сумма к оплате: X ₽

При «счётах по всем садикам» выводи каждый садик по branch_name (Tiny Tony, не Айсулу/Николай!). Используй get_invoices_all_branches — он уже сгруппирован по садикам.

Инструменты: get_invoices_all_branches (для счётов по всем садикам), get_all_chats, get_chat_context, get_free_slots, get_lessons_for_branch, get_branch_info, get_schedule. Отвечай на русском."""


def _get_system_prompt() -> str:
    return _build_system_prompt()


def register_routes(app: Flask, api_base: str) -> None:
    @app.post(f"{api_base}/crm/nchats/ai-chat")
    @require_auth
    @_require_crm_access
    def crm_nchats_ai_chat():
        api_key = _get_aitunnel_api_key()
        if not api_key:
            abort(503, description="AITUNNEL API key not configured.")
        body = request.get_json(silent=True) or {}
        user_message = (body.get("message") or "").strip()
        if not user_message:
            abort(400, description="message is required")
        history = body.get("history") or []
        if not isinstance(history, list):
            history = []

        system_prompt = _get_system_prompt()
        messages_for_api: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}]
        for h in history[-20:]:
            role = h.get("role")
            content = (h.get("content") or "").strip()
            if role in ("user", "assistant") and content:
                messages_for_api.append({"role": role, "content": content})
        messages_for_api.append({"role": "user", "content": user_message})

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        max_rounds = 8
        final_content = ""
        for _ in range(max_rounds):
            payload = {
                "model": "deepseek-v3.2",
                "messages": messages_for_api,
                "tools": NCHATS_TOOLS,
                "stream": False,
                "max_tokens": 4000,
            }
            try:
                r = requests.post(
                    "https://api.aitunnel.ru/v1/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=120,
                )
                r.raise_for_status()
            except requests.RequestException as e:
                abort(502, description=f"AITUNNEL error: {str(e)}")
            data = r.json()
            msg = (data.get("choices") or [{}])[0].get("message") or {}
            messages_for_api.append(msg)
            tool_calls = msg.get("tool_calls")
            content = msg.get("content") or ""
            if tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function") or {}
                    fname = fn.get("name", "")
                    try:
                        fargs = json.loads(fn.get("arguments") or "{}")
                    except Exception:
                        fargs = {}
                    result = _execute_nchats_tool(fname, fargs)
                    messages_for_api.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id", ""),
                        "name": fname,
                        "content": json.dumps(result, ensure_ascii=False),
                    })
            else:
                final_content = (content or "").strip()
                break
        if not final_content:
            final_content = "Не удалось получить ответ."

        def gen():
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            chunk_size = 4
            for i in range(0, len(final_content), chunk_size):
                chunk = final_content[i : i + chunk_size]
                yield f"data: {json.dumps({'t': chunk})}\n\n"

        return Response(
            stream_with_context(gen()),
            mimetype="text/event-stream; charset=utf-8",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
