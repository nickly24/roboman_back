"""
Отправка сообщений в CRM-чаты (Telegram).
Вынесено для переиспользования: ИИ-помощник, будущий агент по нескольким чатам и т.д.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
import urllib.error

from shared import db_cursor, exec_one, fetch_one

TELEGRAM_BOT_ENV = os.environ.get("TELEGRAM_BOT_ENV", "dev")


def markdown_to_telegram_html(text: str) -> str:
    """
    Конвертирует markdown-подобную разметку (**жирный**, *курсив*, `код`, ---) в Telegram HTML.
    Экранирует <, >, & в обычном тексте.
    """
    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Порядок важен: ** до *, иначе * из ** заматчит раньше
    # **жирный**
    text = re.sub(r"\*\*(.+?)\*\*", lambda m: f"<b>{esc(m.group(1))}</b>", text, flags=re.DOTALL)
    # *курсив* (не **)
    text = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", lambda m: f"<i>{esc(m.group(1))}</i>", text)
    # `код`
    text = re.sub(r"`([^`]+?)`", lambda m: f"<code>{esc(m.group(1))}</code>", text)
    # --- горизонтальная линия -> em-dash линия
    text = re.sub(r"\n---+[ \t]*\n", "\n—————\n", text)

    # Экранируем < > & в тексте вне наших тегов
    parts = re.split(r"(</?b>|</?i>|</?code>)", text)
    for i in range(0, len(parts), 2):
        parts[i] = esc(parts[i])
    return "".join(parts)


def _get_telegram_token() -> str | None:
    env = (TELEGRAM_BOT_ENV or "prod").strip().lower()
    key = "telegram_bot_token_dev" if env == "dev" else "telegram_bot_token"
    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT value_text FROM settings WHERE `key`=%s", (key,))
        if not row or not row.get("value_text"):
            return None
        return str(row["value_text"]).strip() or None


def _telegram_send(token: str, tg_chat_id: int, text: str) -> bool:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    html = markdown_to_telegram_html(text)
    payload = {"chat_id": tg_chat_id, "text": html, "parse_mode": "HTML"}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.HTTPError, OSError):
        return False


def send_message_to_chat(chat_id: int, content: str, user_id: int | None = None) -> dict:
    """
    Отправить сообщение в CRM-чат. Пишет в БД и отправляет в Telegram.
    Returns: {"ok": True, "message_id": int} or {"ok": False, "error": str}
    """
    content = (content or "").strip()
    if not content:
        return {"ok": False, "error": "content is required"}
    token = _get_telegram_token()
    if not token:
        return {"ok": False, "error": "Telegram bot token not configured"}
    with db_cursor() as (_, cur):
        chat = fetch_one(cur, "SELECT id, telegram_chat_id FROM crm_chats WHERE id=%s", (chat_id,))
        if not chat:
            return {"ok": False, "error": "Chat not found"}
        tg_chat_id = int(chat["telegram_chat_id"])
        sent = _telegram_send(token, tg_chat_id, content)
        mid = exec_one(
            cur,
            "INSERT INTO crm_messages (crm_chat_id, direction, content, telegram_message_id, sent_by_user_id) VALUES (%s,'out',%s,NULL,%s)",
            (chat_id, content, user_id),
        )
    return {"ok": True, "message_id": mid}
