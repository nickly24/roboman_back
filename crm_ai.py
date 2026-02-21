"""
CRM ИИ: обобщение контекста чата, чат с ИИ и tools (слоты, занятия, расписание).
"""
from __future__ import annotations

import codecs
import json
from datetime import datetime, timezone, timedelta
from typing import Any

import requests
from flask import Flask, Response, abort, g, request, stream_with_context

from shared import db_cursor, fetch_all, fetch_one, get_current_user, require_auth

# Москва UTC+3
MOSCOW_OFFSET = timedelta(hours=3)


def _require_crm_access(fn):
    """OWNER с флагом crm_access=1."""
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


def _postprocess_transcription(raw: str, api_key: str) -> str:
    """Прогон через GPT-4o для исправления пунктуации и опечаток."""
    if not raw or len(raw.strip()) < 2:
        return raw
    prompt = """Исправь пунктуацию и возможные опечатки в тексте. Не меняй слова и смысл. Верни только исправленный текст, без пояснений."""
    try:
        r = requests.post(
            "https://api.aitunnel.ru/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": f"{prompt}\n\nТекст:\n{raw}"}], "max_tokens": 500},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        out = ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        return out.strip() or raw
    except Exception:
        return raw


def _get_aitunnel_api_key() -> str | None:
    """Ключ AITUNNEL для ИИ-функций."""
    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT value_text FROM settings WHERE `key`=%s", ("aitunnel_api_key",))
        if not row or not row.get("value_text"):
            return None
        return str(row["value_text"]).strip() or None


def _moscow_now() -> str:
    """Текущие дата и время по Москве (UTC+3) для промпта."""
    now = datetime.now(timezone.utc) + MOSCOW_OFFSET
    return now.strftime("%d.%m.%Y, %H:%M")


def _format_moscow(dt) -> str:
    """Форматирование datetime в московское время (ДД.ММ.ГГГГ ЧЧ:ММ)."""
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


def _business_context(cur, branch_id: int) -> str:
    """Контекст бизнеса и филиала для промптов ИИ."""
    branch = fetch_one(
        cur,
        "SELECT id, name, address, metro, price_per_child FROM branches WHERE id=%s",
        (branch_id,),
    )
    if not branch:
        return ""
    addr = (branch.get("address") or "").strip() or "—"
    metro = (branch.get("metro") or "").strip() or ""
    price = branch.get("price_per_child")
    price_s = f"{int(price)} ₽/ребёнок" if price is not None else ""
    branch_name = (branch.get("name") or "—").strip()
    parts = [
        "ВАЖНО: Ты — IT-клуб / школа робототехники. Твои клиенты — это детские сады (садики). "
        "Каждый чат = переписка с конкретным детским садом. Название филиала (branch) = название садика. "
        "Вы организуете занятия по робототехнике для детей в этих садиках. "
        "При приветствии и общении учитывай, что пишешь представителю детского сада, а не частному клиенту.",
        f"Текущий садик (клиент): «{branch_name}», адрес: {addr}.",
    ]
    if metro:
        parts.append(f"Метро: {metro}.")
    if price_s:
        parts.append(f"Цена за занятие: {price_s}.")
    return " ".join(parts)


def _tool_free_slots(day_of_week: int | None = None) -> list:
    """Свободные слоты по всем преподавателям (все филиалы)."""
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
        out = []
        for r in rows:
            d = int(r.get("day_of_week") or 0)
            t = str(r.get("start_time") or "")[:5]
            out.append({"day": days[d] if 1 <= d <= 7 else str(d), "time": t, "teacher": r.get("teacher_name")})
        return out


def _tool_lessons(branch_id: int, start_date: str, end_date: str) -> list:
    """Занятия филиала за период."""
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
    """Информация о филиале."""
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
    """Расписание филиала: какой преподаватель во сколько ведёт занятия."""
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


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_free_slots",
            "description": "Свободные слоты по всем преподавателям (все филиалы). Когда клиент спрашивает о доступном времени, записи.",
            "parameters": {
                "type": "object",
                "properties": {"day_of_week": {"type": "integer", "description": "1=Пн..7=Вс, необязательно"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_lessons_for_period",
            "description": "Занятия филиала за период. Когда спрашивают про прошлые/будущие занятия.",
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
            "name": "get_branch_info",
            "description": "Информация о филиале: адрес, метро, цена. Реквизиты для оплаты.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_schedule",
            "description": "Расписание филиала: какой преподаватель во сколько ведёт занятия. Используй при вопросах о времени занятий, расписании.",
            "parameters": {
                "type": "object",
                "properties": {"weekday": {"type": "integer", "description": "День недели 1=Пн..7=Вс, необязательно"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_message_to_chat",
            "description": "Отправить сообщение клиенту в текущий чат. Используй, когда менеджер просит отправить что-то клиенту или подтвердить отправку. Пишет в чат от имени менеджера.",
            "parameters": {
                "type": "object",
                "properties": {"content": {"type": "string", "description": "Текст сообщения для отправки клиенту"}},
                "required": ["content"],
            },
        },
    },
]


def _execute_tool(name: str, args: dict, branch_id: int, chat_id: int, user_id: int) -> Any:
    if name == "get_free_slots":
        return _tool_free_slots(args.get("day_of_week"))
    if name == "get_lessons_for_period":
        return _tool_lessons(branch_id, args.get("start_date", "")[:10], args.get("end_date", "")[:10])
    if name == "get_branch_info":
        return _tool_branch_info(branch_id)
    if name == "get_schedule":
        return _tool_schedule(branch_id, args.get("weekday"))
    if name == "send_message_to_chat":
        from crm_send import send_message_to_chat as do_send
        res = do_send(chat_id, args.get("content", ""), user_id)
        return res
    return {"error": f"Unknown tool: {name}"}


def register_routes(app: Flask, api_base: str) -> None:
    """Регистрация роутов CRM ИИ."""

    @app.post(f"{api_base}/crm/transcribe-voice")
    @require_auth
    @_require_crm_access
    def crm_transcribe_voice():
        """Транскрипция голоса через Whisper (AITUNNEL)."""
        api_key = _get_aitunnel_api_key()
        if not api_key:
            abort(503, description="AITUNNEL API key not configured.")
        if "file" not in request.files and "audio" not in request.files:
            abort(400, description="audio file required")
        f = request.files.get("file") or request.files.get("audio")
        if not f:
            abort(400, description="audio file required")
        file_bytes = f.read()
        if not file_bytes:
            abort(400, description="empty audio file")
        fname = f.filename or "audio.webm"
        ctype = f.content_type or "audio/webm"
        try:
            r = requests.post(
                "https://api.aitunnel.ru/v1/audio/transcriptions",
                headers={"Authorization": f"Bearer {api_key}"},
                files={"file": (fname, file_bytes, ctype)},
                data={"model": "whisper-1", "language": "ru"},
                timeout=60,
            )
            r.raise_for_status()
        except requests.RequestException as e:
            abort(502, description=f"AITUNNEL error: {str(e)}")
        data = r.json()
        text = (data.get("text") or "").strip()
        if text and api_key:
            text = _postprocess_transcription(text, api_key)
        return {"ok": True, "text": text}

    @app.get(f"{api_base}/crm/chats/<int:chat_id>/summarize")
    @require_auth
    @_require_crm_access
    def crm_chats_summarize(chat_id: int):
        api_key = _get_aitunnel_api_key()
        if not api_key:
            abort(503, description="AITUNNEL API key not configured.")
        with db_cursor() as (_, cur):
            chat = fetch_one(cur, "SELECT id, branch_id FROM crm_chats WHERE id=%s", (chat_id,))
            if not chat:
                abort(404)
            branch_id = int(chat.get("branch_id") or 0)
            business_ctx = _business_context(cur, branch_id) if branch_id else ""
            rows = fetch_all(cur, "SELECT m.direction, m.content, m.created_at FROM crm_messages m WHERE m.crm_chat_id=%s ORDER BY m.id DESC LIMIT 50", (chat_id,))
        rows = list(reversed(rows))
        lines = []
        for r in rows:
            role = "Контакт" if r["direction"] == "in" else "Менеджер"
            content = (r.get("content") or "").strip() or "—"
            ts_s = _format_moscow(r.get("created_at"))
            lines.append(f"{role} ({ts_s} МСК): {content}")
        history = "\n".join(lines) if lines else "Нет сообщений."
        ctx_block = f"\nКонтекст:\n{business_ctx}\n\n" if business_ctx else ""
        now_moscow = _moscow_now()
        prompt = f"""Ты помощник менеджера CRM. Клиенты — детские сады (садики), вы — IT-клуб, организуете занятия по робототехнике. Сейчас по Москве: {now_moscow}.{ctx_block}
Ниже — последние сообщения из переписки с детским садом. Кратко обобщи: о чём чат, в чём суть, что хочет садик, какой статус. Ответь на русском, 2–5 предложений.

---
{history}
---"""
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        try:
            r = requests.post(
                "https://api.aitunnel.ru/v1/chat/completions",
                json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}], "stream": True, "max_tokens": 500},
                headers=headers,
                stream=True,
                timeout=60,
            )
            r.raise_for_status()
        except requests.RequestException as e:
            abort(502, description=f"AITUNNEL error: {str(e)}")

        def gen():
            buffer = ""
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            for chunk in r.iter_content(chunk_size=256, decode_unicode=False):
                if chunk:
                    buffer += decoder.decode(chunk)
                while True:
                    line_end = buffer.find("\n")
                    if line_end == -1:
                        break
                    line = buffer[:line_end].strip()
                    buffer = buffer[line_end + 1 :]
                    if line.startswith("data: "):
                        data = line[6:]
                        if data == "[DONE]":
                            return
                        try:
                            obj = json.loads(data)
                            content = (obj.get("choices") or [{}])[0].get("delta", {}).get("content")
                            if content:
                                yield f"data: {json.dumps({'t': content})}\n\n"
                        except json.JSONDecodeError:
                            pass

        return Response(stream_with_context(gen()), mimetype="text/event-stream; charset=utf-8", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.post(f"{api_base}/crm/chats/<int:chat_id>/ai-chat")
    @require_auth
    @_require_crm_access
    def crm_chats_ai_chat(chat_id: int):
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
        with db_cursor() as (_, cur):
            chat = fetch_one(cur, "SELECT id, branch_id FROM crm_chats WHERE id=%s", (chat_id,))
            if not chat:
                abort(404)
            branch_id = int(chat.get("branch_id") or 0)
            business_ctx = _business_context(cur, branch_id) if branch_id else ""
            rows = fetch_all(cur, "SELECT m.direction, m.content, m.created_at FROM crm_messages m WHERE m.crm_chat_id=%s ORDER BY m.id DESC LIMIT 40", (chat_id,))
        rows = list(reversed(rows))
        lines = []
        for r in rows:
            role = "Клиент" if r["direction"] == "in" else "Менеджер"
            content = (r.get("content") or "").strip() or "—"
            ts_s = _format_moscow(r.get("created_at"))
            lines.append(f"{role} ({ts_s} МСК): {content}")
        crm_context = "\n".join(lines) if lines else "Нет сообщений."
        ctx_block = f"\nКонтекст:\n{business_ctx}\n\n" if business_ctx else ""
        now_moscow = _moscow_now()
        system_prompt = f"""Ты помощник менеджера CRM по взаимодействию с клиентами детских развивающих центров. Сейчас по Москве: {now_moscow}.{ctx_block}
Переписка с клиентом:
---
{crm_context}
---

Менеджер обращается к тебе с вопросами. Ты можешь вызывать инструменты: свободные слоты, занятия за период, расписание (кто во сколько ведёт), информация о филиале, отправить сообщение в чат. Отвечай на русском, по делу.

Когда менеджер просит составить сообщение клиенту: ОБЯЗАТЕЛЬНО помещай ТОЛЬКО текст для клиента в блок кода между тройными обратными кавычками. До блока — краткий комментарий менеджеру («Вот вариант:»), после — «Нужно изменить?». Пример:
Вот вариант:
```
Добрый день! Мы можем перенести занятия...
```
Нужно изменить?

Когда менеджер подтвердит отправку («отправь», «да») — вызови send_message_to_chat, передав ТОЛЬКО текст из блока, без комментариев, без «Вот текст», без «Как вам» и т.п.

При выдаче списка занятий оформляй каждое занятие так (с пустой строкой между занятиями):
**ДД месяц ГГГГ — ЧЧ:ММ** (дата и время жирным)
Преподаватель: Имя
Платные: N
Пробные: N
Сумма к оплате: X ₽
Используй поля date_ru, time, teacher, paid, trial, sum_rub из ответа инструмента. Сумма уже посчитана (sum_rub). Если пробных 0 — можно не указывать строку «Пробные»."""
        messages_for_api: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}]
        for h in history[-20:]:
            role = h.get("role")
            content = (h.get("content") or "").strip()
            if role in ("user", "assistant") and content:
                messages_for_api.append({"role": role, "content": content})
        messages_for_api.append({"role": "user", "content": user_message})

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        max_rounds = 5
        final_content = ""
        for _ in range(max_rounds):
            payload = {"model": "gpt-4o-mini", "messages": messages_for_api, "tools": TOOLS, "stream": False, "max_tokens": 2000}
            try:
                r = requests.post("https://api.aitunnel.ru/v1/chat/completions", json=payload, headers=headers, timeout=90)
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
                    u = getattr(g, "current_user", None) or get_current_user()
                    result = _execute_tool(fname, fargs, branch_id, chat_id, u.id)
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
            # Стримим по кусочкам, чтобы клиент видел печать в реальном времени
            chunk_size = 3
            for i in range(0, len(final_content), chunk_size):
                yield f"data: {json.dumps({'t': final_content[i : i + chunk_size]})}\n\n"

        return Response(stream_with_context(gen()), mimetype="text/event-stream; charset=utf-8", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
