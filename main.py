from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from functools import wraps
from typing import Any, Callable, Iterator, Literal, TypeVar

import mysql.connector  # type: ignore
from flask import Flask, Request, Response, abort, g, request, send_file
from flask_cors import CORS
from mysql.connector import Error as MySQLError  # type: ignore

"""
Один гигантский файл backend/main.py (как просили):
- конфиг БД
- пул/курсоры
- auth (Bearer user_id без безопасности)
- все роуты
- внизу app.run
"""

# ------------------------------------------------------------
# Config (раньше было в config.py)
# ------------------------------------------------------------

# MySQL
DB_HOST = "147.45.138.77"
DB_PORT = 3306
DB_USER = "itmasters"
DB_PASSWORD = "itmasters"
DB_NAME = "roboman"

# Pool
DB_POOL_SIZE = 10

# Upload limits
MAX_PDF_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_PHOTO_BYTES = 5 * 1024 * 1024  # 5 MB

# Какой токен бота использовать. Одна БД на прод и дев — переключатель только тут в коде.
# "prod" → telegram_bot_token, "dev" → telegram_bot_token_dev
TELEGRAM_BOT_ENV = "prod"


# ------------------------------------------------------------
# DB helpers — используем shared (единый пул для main и blueprints)
# ------------------------------------------------------------
from shared import db_cursor, exec_one, fetch_all, fetch_one


# ------------------------------------------------------------
# Telegram CRM helpers (модульный уровень для бота в потоке)
# ------------------------------------------------------------

def _get_telegram_token_from_settings() -> str | None:
    """Берёт токен из БД: ключ зависит от TELEGRAM_BOT_ENV вверху main.py (prod → telegram_bot_token, dev → telegram_bot_token_dev)."""
    env = (TELEGRAM_BOT_ENV or "prod").strip().lower()
    key = "telegram_bot_token_dev" if env == "dev" else "telegram_bot_token"
    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT value_text FROM settings WHERE `key`=%s", (key,))
        if not row or not row.get("value_text"):
            return None
        return str(row["value_text"]).strip() or None


def telegram_send_message(token: str, chat_id: int, text: str) -> bool:
    """Отправить сообщение в Telegram. Возвращает True при успехе."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _telegram_bot_poll_loop() -> None:
    """Фоновый цикл long polling Telegram. Запускать в отдельном потоке."""
    offset: int | None = None
    while True:
        try:
            token = _get_telegram_token_from_settings()
            if not token:
                time.sleep(60)
                continue
            url = f"https://api.telegram.org/bot{token}/getUpdates?timeout=30"
            if offset is not None:
                url += f"&offset={offset}"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=35) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if not data.get("ok"):
                time.sleep(2)
                continue
            updates = data.get("result") or []
            for upd in updates:
                offset = int(upd["update_id"]) + 1
                msg = upd.get("message") or upd.get("edited_message")
                if not msg:
                    continue
                chat_id = msg.get("chat", {}).get("id")
                text = (msg.get("text") or "").strip()
                tg_message_id = msg.get("message_id")
                is_edit = "edited_message" in upd

                with db_cursor() as (conn, cur):
                    if is_edit and tg_message_id:
                        cur.execute(
                            "UPDATE crm_messages SET content=%s, updated_at=NOW() WHERE telegram_message_id=%s",
                            (text or "", tg_message_id),
                        )
                    else:
                        row = fetch_one(
                            cur,
                            """
                            SELECT cc.id AS crm_chat_id, cc.display_name, b.name AS branch_name
                            FROM crm_chats cc
                            JOIN branches b ON b.id = cc.branch_id
                            WHERE cc.telegram_chat_id=%s
                            """,
                            (chat_id,),
                        )
                        if row:
                            exec_one(
                                cur,
                                "INSERT INTO crm_messages (crm_chat_id, direction, content, telegram_message_id, sent_by_user_id) VALUES (%s,'in',%s,%s,NULL)",
                                (row["crm_chat_id"], text or "", tg_message_id),
                            )
                            label = row["display_name"] or row["branch_name"] or str(chat_id)
                            notif_text = f"Новое сообщение в CRM ({label}): { (text[:80] + '…') if text and len(text) > 80 else (text or '') }"
                            subs = fetch_all(cur, "SELECT telegram_chat_id FROM crm_notification_subscribers")
                            for s in subs:
                                try:
                                    telegram_send_message(token, int(s["telegram_chat_id"]), notif_text)
                                except Exception:
                                    pass
                        else:
                            if (text or "").lower() in ("/start", "start", "старт"):
                                reply = f"Ваш chat_id: {chat_id}. Отправьте его руководителю IT-клуба для регистрации в CRM."
                                telegram_send_message(token, chat_id, reply)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                offset = None
            time.sleep(5)
        except Exception:
            time.sleep(5)


# ------------------------------------------------------------
# Auth helpers (раньше было в auth.py)
# ------------------------------------------------------------

Role = Literal["OWNER", "TEACHER"]


@dataclass(frozen=True)
class CurrentUser:
    id: int
    role: Role
    owner_id: int | None
    teacher_id: int | None
    login: str


def _extract_token(req: Request) -> str | None:
    # Простая схема без безопасности:
    # Authorization: Bearer <user_id>
    auth = req.headers.get("Authorization", "").strip()
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def get_current_user() -> CurrentUser:
    tok = _extract_token(request)
    if not tok:
        abort(401, description="Missing Authorization Bearer token")
    try:
        user_id = int(tok)
    except ValueError:
        abort(401, description="Invalid token format")

    with db_cursor() as (_, cur):
        row = fetch_one(
            cur,
            """
            SELECT id, login, role, owner_id, teacher_id, is_active
            FROM auf_users
            WHERE id=%s
            """,
            (user_id,),
        )
        if not row:
            abort(401, description="Unknown user")
        if int(row["is_active"]) != 1:
            abort(403, description="User is inactive")

        role = row["role"]
        if role not in ("OWNER", "TEACHER"):
            abort(403, description="Invalid user role")

        return CurrentUser(
            id=int(row["id"]),
            login=str(row["login"]),
            role=role,  # type: ignore[arg-type]
            owner_id=int(row["owner_id"]) if row["owner_id"] is not None else None,
            teacher_id=int(row["teacher_id"]) if row["teacher_id"] is not None else None,
        )


F = TypeVar("F", bound=Callable[..., Any])


def require_auth(fn: F) -> F:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        g.current_user = get_current_user()
        return fn(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def require_role(*allowed: Role) -> Callable[[F], F]:
    def deco(fn: F) -> F:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            u: CurrentUser = getattr(g, "current_user", None) or get_current_user()
            g.current_user = u
            if u.role not in allowed:
                abort(403, description="Forbidden for this role")
            return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return deco


def require_crm_access(fn: F) -> F:
    """OWNER с флагом crm_access=1."""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        u: CurrentUser = getattr(g, "current_user", None) or get_current_user()
        g.current_user = u
        if u.role != "OWNER":
            abort(403, description="CRM access only for owners")
        with db_cursor() as (_, cur):
            row = fetch_one(cur, "SELECT crm_access FROM auf_users WHERE id=%s", (u.id,))
            if not row or int(row.get("crm_access") or 0) != 1:
                abort(403, description="CRM access not granted")
        return fn(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


# ------------------------------------------------------------
# App code (перенесено из app.py)
# ------------------------------------------------------------


def _to_jsonable(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, Decimal):
        # денежные поля можно вернуть как float (для UI достаточно)
        return float(v)
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray)):
        return base64.b64encode(bytes(v)).decode("ascii")
    return str(v)


def _jsonify(data: Any, status: int = 200) -> Response:
    def default(o: Any) -> Any:
        return _to_jsonable(o)

    return Response(
        json.dumps(data, ensure_ascii=False, default=default),
        status=status,
        content_type="application/json; charset=utf-8",
    )


def _ok(data: Any | None = None) -> Response:
    return _jsonify({"ok": True, "data": data})


def _err(message: str, *, status: int, code: str | None = None, details: Any | None = None) -> Response:
    payload: dict[str, Any] = {"ok": False, "error": {"message": message}}
    if code:
        payload["error"]["code"] = code
    if details is not None:
        payload["error"]["details"] = details
    return _jsonify(payload, status=status)


def _parse_int(name: str, v: Any, *, min_v: int | None = None, max_v: int | None = None) -> int:
    try:
        n = int(v)
    except Exception:
        abort(400, description=f"Invalid int for {name}")
    if min_v is not None and n < min_v:
        abort(400, description=f"{name} must be >= {min_v}")
    if max_v is not None and n > max_v:
        abort(400, description=f"{name} must be <= {max_v}")
    return n


def _parse_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    s = str(v).strip().lower()
    return s in {"1", "true", "yes", "y", "on"}


def _month_range(month: str) -> tuple[datetime, datetime]:
    # month: YYYY-MM
    try:
        y, m = month.split("-", 1)
        year = int(y)
        mon = int(m)
        start = datetime(year, mon, 1)
    except Exception:
        abort(400, description="month must be YYYY-MM")
    # next month
    if start.month == 12:
        end = datetime(start.year + 1, 1, 1)
    else:
        end = datetime(start.year, start.month + 1, 1)
    return start, end


def _parse_period(args: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    month = args.get("month")
    if month:
        return _month_range(str(month))
    start_s = args.get("start")
    end_s = args.get("end")
    if not start_s and not end_s:
        return None, None
    try:
        start = datetime.fromisoformat(start_s) if start_s else None
        end = datetime.fromisoformat(end_s) if end_s else None
    except Exception:
        abort(400, description="start/end must be ISO datetime")
    return start, end


def _paginate(args: dict[str, Any], *, default_limit: int = 50, max_limit: int = 500) -> tuple[int, int]:
    limit = args.get("limit", default_limit)
    offset = args.get("offset", 0)
    limit_i = _parse_int("limit", limit, min_v=1, max_v=max_limit)
    offset_i = _parse_int("offset", offset, min_v=0)
    return limit_i, offset_i


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    API_BASE = os.environ.get("API_BASE", "/api").rstrip("/")
    app.config["MAX_CONTENT_LENGTH"] = MAX_PDF_BYTES

    # ------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------
    @app.errorhandler(400)
    def _e400(e):  # type: ignore[no-untyped-def]
        return _err(getattr(e, "description", "Bad request"), status=400, code="BAD_REQUEST")

    @app.errorhandler(401)
    def _e401(e):  # type: ignore[no-untyped-def]
        return _err(getattr(e, "description", "Unauthorized"), status=401, code="UNAUTHORIZED")

    @app.errorhandler(403)
    def _e403(e):  # type: ignore[no-untyped-def]
        return _err(getattr(e, "description", "Forbidden"), status=403, code="FORBIDDEN")

    @app.errorhandler(404)
    def _e404(e):  # type: ignore[no-untyped-def]
        return _err("Not found", status=404, code="NOT_FOUND")

    @app.errorhandler(MySQLError)
    def _edb(e):  # type: ignore[no-untyped-def]
        # Пробрасываем понятную ошибку клиенту (без “секьюрити”)
        return _err(str(e), status=400, code="DB_ERROR")

    @app.errorhandler(Exception)
    def _e500(e):  # type: ignore[no-untyped-def]
        return _err(str(e), status=500, code="INTERNAL_ERROR")

    # ------------------------------------------------------------
    # Blueprint: Бухгалтерия
    # ------------------------------------------------------------
    from blueprints.accounting import bp as accounting_bp
    app.register_blueprint(accounting_bp, url_prefix=f"{API_BASE}/accounting")

    # ------------------------------------------------------------
    # Helpers for scoping
    # ------------------------------------------------------------
    def _current_user() -> CurrentUser:
        u = getattr(g, "current_user", None)
        if u is None:
            abort(401)
        return u

    def _owner_department_ids(owner_id: int) -> list[int]:
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, "SELECT department_id FROM department_owners WHERE owner_id=%s", (owner_id,))
        return [int(r["department_id"]) for r in rows]

    def _owner_branch_ids(owner_id: int) -> list[int]:
        dep_ids = _owner_department_ids(owner_id)
        if not dep_ids:
            return []
        placeholders = ",".join(["%s"] * len(dep_ids))
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                f"SELECT id FROM branches WHERE department_id IN ({placeholders})",
                tuple(dep_ids),
            )
        return [int(r["id"]) for r in rows]

    def _teacher_branch_ids(teacher_id: int) -> list[int]:
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, "SELECT branch_id FROM branch_teachers WHERE teacher_id=%s", (teacher_id,))
        return [int(r["branch_id"]) for r in rows]

    def _lesson_owner_scope_sql(owner_id: int) -> tuple[str, tuple[Any, ...]]:
        # Ограничение по отделам владельца через department_owners -> branches
        return (
            """
            EXISTS (
              SELECT 1
              FROM branches b
              JOIN department_owners do2 ON do2.department_id = b.department_id
              WHERE b.id = l.branch_id AND do2.owner_id = %s
            )
            """,
            (owner_id,),
        )

    # ------------------------------------------------------------
    # Meta / health
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/health")
    def health() -> Response:
        return _ok({"status": "ok", "time": datetime.utcnow().isoformat()})

    @app.get(f"{API_BASE}/meta")
    def meta() -> Response:
        return _ok(
            {
                "api_base": API_BASE,
                "server_time_utc": datetime.utcnow().isoformat(),
            }
        )

    @app.get(f"{API_BASE}/docs/routes")
    def docs_routes() -> Response:
        routes: list[dict[str, Any]] = []
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
            if not str(rule.rule).startswith(API_BASE):
                continue
            methods = sorted([m for m in (rule.methods or []) if m not in {"HEAD", "OPTIONS"}])
            routes.append({"rule": rule.rule, "methods": methods, "endpoint": rule.endpoint})
        return _ok(routes)

    # ------------------------------------------------------------
    # Auth (без безопасности: token == user_id)
    # ------------------------------------------------------------
    @app.post(f"{API_BASE}/auth/login")
    def auth_login() -> Response:
        body = request.get_json(silent=True) or {}
        login = (body.get("login") or "").strip()
        password = body.get("password")
        if not login or password is None:
            abort(400, description="login and password are required")

        with db_cursor() as (_, cur):
            user = fetch_one(
                cur,
                "SELECT id, login, password_hash, role, owner_id, teacher_id, is_active, crm_access FROM auf_users WHERE login=%s",
                (login,),
            )
            if not user:
                abort(401, description="Invalid login/password")
            if int(user["is_active"]) != 1:
                abort(403, description="User is inactive")
            # По требованиям проекта: без безопасности.
            # Пароль в БД может быть "хэш-плейсхолдером" (см. seed_db.py), поэтому пароль НЕ валидируем.

            role = user["role"]
            profile: dict[str, Any] | None = None
            if role == "OWNER":
                profile = fetch_one(cur, "SELECT * FROM owners WHERE id=%s", (user["owner_id"],)) or None
            elif role == "TEACHER":
                profile = fetch_one(cur, "SELECT * FROM teachers WHERE id=%s", (user["teacher_id"],)) or None

        token = str(int(user["id"]))
        return _ok({"token": token, "role": role, "user": user, "profile": profile})

    @app.post(f"{API_BASE}/auth/logout")
    @require_auth
    def auth_logout() -> Response:
        # Нечего делать: токен не хранится
        return _ok({"logged_out": True})

    @app.get(f"{API_BASE}/auth/me")
    @require_auth
    def auth_me() -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            user = fetch_one(
                cur,
                "SELECT id, login, role, owner_id, teacher_id, is_active, crm_access, created_at, updated_at FROM auf_users WHERE id=%s",
                (u.id,),
            )
            profile = None
            if u.role == "OWNER" and u.owner_id:
                profile = fetch_one(cur, "SELECT * FROM owners WHERE id=%s", (u.owner_id,))
            if u.role == "TEACHER" and u.teacher_id:
                profile = fetch_one(cur, "SELECT * FROM teachers WHERE id=%s", (u.teacher_id,))
        return _ok({"user": user, "profile": profile})

    # ------------------------------------------------------------
    # Далее: остальная часть create_app ровно из backend/app.py
    # ------------------------------------------------------------

    # !!! ВАЖНО: блок ниже полностью повторяет исходный `backend/app.py` (строки ~282..2299).
    # Он большой, но нужен, чтобы был один файл.

    # --- START: pasted from app.py (part 1) ---

    # ------------------------------------------------------------
    # Users (auf_users) - only OWNER
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/users")
    @require_auth
    @require_role("OWNER")
    def users_list() -> Response:
        args = dict(request.args)
        role = args.get("role")
        is_active = args.get("is_active")
        q = (args.get("q") or "").strip()
        limit, offset = _paginate(args)

        where: list[str] = ["1=1"]
        params: list[Any] = []
        if role:
            where.append("role=%s")
            params.append(role)
        if is_active is not None and str(is_active) != "":
            where.append("is_active=%s")
            params.append(1 if _parse_bool(is_active) else 0)
        if q:
            where.append("login LIKE %s")
            params.append(f"%{q}%")

        sql = f"""
            SELECT id, login, role, owner_id, teacher_id, is_active, crm_access, created_at, updated_at
            FROM auf_users
            WHERE {' AND '.join(where)}
            ORDER BY id DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, sql, tuple(params))
        return _ok({"items": rows, "limit": limit, "offset": offset})

    @app.post(f"{API_BASE}/users")
    @require_auth
    @require_role("OWNER")
    def users_create() -> Response:
        body = request.get_json(silent=True) or {}
        login = (body.get("login") or "").strip()
        password = body.get("password")
        role = body.get("role")
        owner_id = body.get("owner_id")
        teacher_id = body.get("teacher_id")
        is_active = 1 if _parse_bool(body.get("is_active", True)) else 0

        if not login or password is None or role not in ("OWNER", "TEACHER"):
            abort(400, description="login, password, role are required")

        if role == "OWNER":
            if owner_id is None or teacher_id is not None:
                abort(400, description="For OWNER provide owner_id only")
        if role == "TEACHER":
            if teacher_id is None or owner_id is not None:
                abort(400, description="For TEACHER provide teacher_id only")

        with db_cursor() as (_, cur):
            new_id = exec_one(
                cur,
                """
                INSERT INTO auf_users(login, password_hash, role, owner_id, teacher_id, is_active)
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                (login, str(password), role, owner_id, teacher_id, is_active),
            )
            row = fetch_one(
                cur,
                "SELECT id, login, role, owner_id, teacher_id, is_active, created_at, updated_at FROM auf_users WHERE id=%s",
                (new_id,),
            )
        return _ok(row)

    @app.get(f"{API_BASE}/users/<int:user_id>")
    @require_auth
    @require_role("OWNER")
    def users_get(user_id: int) -> Response:
        with db_cursor() as (_, cur):
            row = fetch_one(
                cur,
                "SELECT id, login, role, owner_id, teacher_id, is_active, crm_access, created_at, updated_at FROM auf_users WHERE id=%s",
                (user_id,),
            )
        if not row:
            abort(404)
        return _ok(row)

    @app.put(f"{API_BASE}/users/<int:user_id>")
    @require_auth
    @require_role("OWNER")
    def users_update(user_id: int) -> Response:
        body = request.get_json(silent=True) or {}
        fields: list[str] = []
        params: list[Any] = []
        if "login" in body:
            fields.append("login=%s")
            params.append((body.get("login") or "").strip())
        if "password" in body:
            fields.append("password_hash=%s")
            params.append(str(body.get("password")))
        if "is_active" in body:
            fields.append("is_active=%s")
            params.append(1 if _parse_bool(body.get("is_active")) else 0)
        if "crm_access" in body:
            with db_cursor() as (_, cur):
                existing = fetch_one(cur, "SELECT role FROM auf_users WHERE id=%s", (user_id,))
                if existing and existing.get("role") != "OWNER":
                    abort(400, description="crm_access only for OWNER users")
            fields.append("crm_access=%s")
            params.append(1 if _parse_bool(body.get("crm_access")) else 0)
        if not fields:
            abort(400, description="No fields to update")

        params.append(user_id)
        with db_cursor() as (_, cur):
            cur.execute(f"UPDATE auf_users SET {', '.join(fields)} WHERE id=%s", tuple(params))
            row = fetch_one(
                cur,
                "SELECT id, login, role, owner_id, teacher_id, is_active, crm_access, created_at, updated_at FROM auf_users WHERE id=%s",
                (user_id,),
            )
        if not row:
            abort(404)
        return _ok(row)

    @app.put(f"{API_BASE}/users/<int:user_id>/activate")
    @require_auth
    @require_role("OWNER")
    def users_activate(user_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("UPDATE auf_users SET is_active=1 WHERE id=%s", (user_id,))
        return users_get(user_id)

    @app.put(f"{API_BASE}/users/<int:user_id>/deactivate")
    @require_auth
    @require_role("OWNER")
    def users_deactivate(user_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("UPDATE auf_users SET is_active=0 WHERE id=%s", (user_id,))
        return users_get(user_id)

    @app.delete(f"{API_BASE}/users/<int:user_id>")
    @require_auth
    @require_role("OWNER")
    def users_delete(user_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM auf_users WHERE id=%s", (user_id,))
        return _ok({"deleted": True})

    # ------------------------------------------------------------
    # Teacher accounts (auf_users linked to teachers) - only OWNER
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/teacher-accounts")
    @require_auth
    @require_role("OWNER")
    def teacher_accounts_list() -> Response:
        args = dict(request.args)
        status = (args.get("status") or "").strip()
        q = (args.get("q") or "").strip()
        limit, offset = _paginate(args)

        where: list[str] = ["1=1"]
        params: list[Any] = []
        if status:
            where.append("t.status=%s")
            params.append(status)
        if q:
            where.append("(t.full_name LIKE %s OR u.login LIKE %s)")
            params.extend([f"%{q}%", f"%{q}%"])

        sql = f"""
            SELECT
                t.id AS teacher_id,
                t.full_name,
                t.status,
                t.color,
                t.is_salary_free,
                u.id AS user_id,
                u.login,
                u.password_hash AS password,
                u.is_active,
                u.created_at AS user_created_at,
                u.updated_at AS user_updated_at
            FROM teachers t
            LEFT JOIN auf_users u ON u.teacher_id=t.id AND u.role='TEACHER'
            WHERE {' AND '.join(where)}
            ORDER BY t.id DESC
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, sql, tuple(params))
        return _ok({"items": rows, "limit": limit, "offset": offset})

    @app.post(f"{API_BASE}/teacher-accounts")
    @require_auth
    @require_role("OWNER")
    def teacher_accounts_create() -> Response:
        body = request.get_json(silent=True) or {}
        teacher_id = body.get("teacher_id")
        login = (body.get("login") or "").strip()
        password = body.get("password")
        is_active = 1 if _parse_bool(body.get("is_active", True)) else 0

        if teacher_id is None or not login or password is None:
            abort(400, description="teacher_id, login, password are required")

        with db_cursor() as (_, cur):
            teacher = fetch_one(cur, "SELECT id FROM teachers WHERE id=%s", (teacher_id,))
            if not teacher:
                abort(404, description="Teacher not found")
            exists = fetch_one(
                cur,
                "SELECT id FROM auf_users WHERE teacher_id=%s AND role='TEACHER'",
                (teacher_id,),
            )
            if exists:
                abort(400, description="Teacher already has account")

            exec_one(
                cur,
                """
                INSERT INTO auf_users(login, password_hash, role, teacher_id, is_active)
                VALUES (%s,%s,'TEACHER',%s,%s)
                """,
                (login, str(password), teacher_id, is_active),
            )

            row = fetch_one(
                cur,
                """
                SELECT
                    t.id AS teacher_id,
                    t.full_name,
                    t.status,
                    t.color,
                    t.is_salary_free,
                    u.id AS user_id,
                    u.login,
                    u.password_hash AS password,
                    u.is_active,
                    u.created_at AS user_created_at,
                    u.updated_at AS user_updated_at
                FROM teachers t
                LEFT JOIN auf_users u ON u.teacher_id=t.id AND u.role='TEACHER'
                WHERE t.id=%s
                """,
                (teacher_id,),
            )
        return _ok(row)

    # ------------------------------------------------------------
    # Owners - only OWNER
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/owners")
    @require_auth
    @require_role("OWNER")
    def owners_list() -> Response:
        args = dict(request.args)
        q = (args.get("q") or "").strip()
        limit, offset = _paginate(args)

        where = "1=1"
        params: list[Any] = []
        if q:
            where = "full_name LIKE %s"
            params.append(f"%{q}%")
        params.extend([limit, offset])
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                f"SELECT * FROM owners WHERE {where} ORDER BY id DESC LIMIT %s OFFSET %s",
                tuple(params),
            )
        return _ok({"items": rows, "limit": limit, "offset": offset})

    @app.post(f"{API_BASE}/owners")
    @require_auth
    @require_role("OWNER")
    def owners_create() -> Response:
        body = request.get_json(silent=True) or {}
        full_name = (body.get("full_name") or "").strip()
        if not full_name:
            abort(400, description="full_name is required")
        with db_cursor() as (_, cur):
            new_id = exec_one(cur, "INSERT INTO owners(full_name) VALUES (%s)", (full_name,))
            row = fetch_one(cur, "SELECT * FROM owners WHERE id=%s", (new_id,))
        return _ok(row)

    @app.put(f"{API_BASE}/owners/<int:owner_id>")
    @require_auth
    @require_role("OWNER")
    def owners_update(owner_id: int) -> Response:
        body = request.get_json(silent=True) or {}
        full_name = (body.get("full_name") or "").strip()
        if not full_name:
            abort(400, description="full_name is required")
        with db_cursor() as (_, cur):
            cur.execute("UPDATE owners SET full_name=%s WHERE id=%s", (full_name, owner_id))
            row = fetch_one(cur, "SELECT * FROM owners WHERE id=%s", (owner_id,))
        if not row:
            abort(404)
        return _ok(row)

    @app.delete(f"{API_BASE}/owners/<int:owner_id>")
    @require_auth
    @require_role("OWNER")
    def owners_delete(owner_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM owners WHERE id=%s", (owner_id,))
        return _ok({"deleted": True})

    # ------------------------------------------------------------
    # Departments + owners mapping - only OWNER (scoped)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/departments")
    @require_auth
    @require_role("OWNER")
    def departments_list() -> Response:
        u = _current_user()
        dep_ids = _owner_department_ids(u.owner_id or 0)
        if not dep_ids:
            return _ok({"items": []})
        placeholders = ",".join(["%s"] * len(dep_ids))
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, f"SELECT * FROM departments WHERE id IN ({placeholders}) ORDER BY id DESC", tuple(dep_ids))
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/departments")
    @require_auth
    @require_role("OWNER")
    def departments_create() -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        comment = body.get("comment")
        owner_ids = body.get("owner_ids") or []
        if not name:
            abort(400, description="name is required")
        if not isinstance(owner_ids, list):
            abort(400, description="owner_ids must be list")
        # если не передали owners — добавим текущего владельца
        if not owner_ids:
            if not u.owner_id:
                abort(400, description="current user has no owner profile")
            owner_ids = [u.owner_id]
        if len(owner_ids) > 3:
            abort(400, description="department can have at most 3 owners")

        with db_cursor() as (_, cur):
            dep_id = exec_one(cur, "INSERT INTO departments(name, comment) VALUES (%s,%s)", (name, comment))
            for oid in owner_ids:
                cur.execute("INSERT INTO department_owners(department_id, owner_id) VALUES (%s,%s)", (dep_id, int(oid)))
            row = fetch_one(cur, "SELECT * FROM departments WHERE id=%s", (dep_id,))
        return _ok(row)

    @app.get(f"{API_BASE}/departments/<int:dep_id>")
    @require_auth
    @require_role("OWNER")
    def departments_get(dep_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            row = fetch_one(
                cur,
                """
                SELECT d.*
                FROM departments d
                JOIN department_owners do2 ON do2.department_id = d.id
                WHERE d.id=%s AND do2.owner_id=%s
                """,
                (dep_id, u.owner_id),
            )
        if not row:
            abort(404)
        return _ok(row)

    @app.put(f"{API_BASE}/departments/<int:dep_id>")
    @require_auth
    @require_role("OWNER")
    def departments_update(dep_id: int) -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        name = body.get("name")
        comment = body.get("comment")
        fields: list[str] = []
        params: list[Any] = []
        if name is not None:
            fields.append("name=%s")
            params.append((str(name)).strip())
        if comment is not None:
            fields.append("comment=%s")
            params.append(comment)
        if not fields:
            abort(400, description="No fields to update")

        # проверка доступа
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s",
                (dep_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute(f"UPDATE departments SET {', '.join(fields)} WHERE id=%s", tuple(params + [dep_id]))
            row = fetch_one(cur, "SELECT * FROM departments WHERE id=%s", (dep_id,))
        return _ok(row)

    @app.delete(f"{API_BASE}/departments/<int:dep_id>")
    @require_auth
    @require_role("OWNER")
    def departments_delete(dep_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s",
                (dep_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("DELETE FROM departments WHERE id=%s", (dep_id,))
        return _ok({"deleted": True})

    @app.get(f"{API_BASE}/departments/<int:dep_id>/branches")
    @require_auth
    @require_role("OWNER")
    def departments_branches(dep_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s",
                (dep_id, u.owner_id),
            )
            if not ok:
                abort(404)
            rows = fetch_all(
                cur,
                """
                SELECT b.*, d.name AS department_name
                FROM branches b
                JOIN departments d ON d.id=b.department_id
                WHERE b.department_id=%s
                ORDER BY b.id DESC
                """,
                (dep_id,),
            )
        return _ok({"items": rows})

    @app.get(f"{API_BASE}/departments/<int:dep_id>/owners")
    @require_auth
    @require_role("OWNER")
    def departments_owners_list(dep_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s",
                (dep_id, u.owner_id),
            )
            if not ok:
                abort(404)
            rows = fetch_all(
                cur,
                """
                SELECT o.*
                FROM department_owners do2
                JOIN owners o ON o.id = do2.owner_id
                WHERE do2.department_id=%s
                ORDER BY o.full_name
                """,
                (dep_id,),
            )
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/departments/<int:dep_id>/owners/<int:owner_id>")
    @require_auth
    @require_role("OWNER")
    def departments_owner_add(dep_id: int, owner_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s",
                (dep_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("INSERT INTO department_owners(department_id, owner_id) VALUES (%s,%s)", (dep_id, owner_id))
        return _ok({"added": True})

    @app.delete(f"{API_BASE}/departments/<int:dep_id>/owners/<int:owner_id>")
    @require_auth
    @require_role("OWNER")
    def departments_owner_remove(dep_id: int, owner_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s",
                (dep_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("DELETE FROM department_owners WHERE department_id=%s AND owner_id=%s", (dep_id, owner_id))
        return _ok({"deleted": True})

    # ------------------------------------------------------------
    # Branches (OWNER scoped, TEACHER assigned)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/branches")
    @require_auth
    def branches_list() -> Response:
        u = _current_user()
        args = dict(request.args)
        limit, offset = _paginate(args)
        include_inactive = _parse_bool(args.get("include_inactive", False))

        if u.role == "OWNER":
            where = ["do2.owner_id=%s"]
            params = [u.owner_id]
            if not include_inactive:
                where.append("b.is_active=1")
            sql = f"""
                SELECT b.*, d.name AS department_name
                FROM branches b
                JOIN departments d ON d.id=b.department_id
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE {' AND '.join(where)}
                ORDER BY b.id DESC
                LIMIT %s OFFSET %s
            """
            params.extend([limit, offset])
            with db_cursor() as (_, cur):
                rows = fetch_all(cur, sql, tuple(params))
            return _ok({"items": rows, "limit": limit, "offset": offset})

        # TEACHER
        sql = """
            SELECT b.id, b.department_id, b.name, b.address, b.metro, b.is_active, b.created_at, b.updated_at,
                   d.name AS department_name
            FROM branches b
            JOIN branch_teachers bt ON bt.branch_id=b.id
            JOIN departments d ON d.id=b.department_id
            WHERE bt.teacher_id=%s
            ORDER BY b.id DESC
            LIMIT %s OFFSET %s
        """
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, sql, (u.teacher_id, limit, offset))
        return _ok({"items": rows, "limit": limit, "offset": offset})

    @app.post(f"{API_BASE}/branches")
    @require_auth
    @require_role("OWNER")
    def branches_create() -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        department_id = body.get("department_id")
        name = (body.get("name") or "").strip()
        address = (body.get("address") or "").strip()
        metro = body.get("metro")
        price = body.get("price_per_child")
        is_active = 1 if _parse_bool(body.get("is_active", True)) else 0
        teacher_base_rate = body.get("teacher_base_rate")
        if teacher_base_rate is None:
            teacher_base_rate = 1200
        teacher_base_rate = int(teacher_base_rate)

        if department_id is None or not name or not address or price is None:
            abort(400, description="department_id, name, address, price_per_child are required")

        # доступ к отделу
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s",
                (int(department_id), u.owner_id),
            )
            if not ok:
                abort(403, description="No access to department")
            bid = exec_one(
                cur,
                """
                INSERT INTO branches(department_id, name, address, metro, price_per_child, is_active, teacher_base_rate)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                """,
                (int(department_id), name, address, metro, price, is_active, teacher_base_rate),
            )
            row = fetch_one(cur, "SELECT * FROM branches WHERE id=%s", (bid,))
        return _ok(row)

    @app.put(f"{API_BASE}/branches/<int:branch_id>")
    @require_auth
    @require_role("OWNER")
    def branches_update(branch_id: int) -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        fields: list[str] = []
        params: list[Any] = []
        new_department_id_int: int | None = None
        for k in ["name", "address", "metro", "price_per_child", "is_active", "teacher_base_rate"]:
            if k in body:
                fields.append(f"{k}=%s")
                if k == "is_active":
                    params.append(1 if _parse_bool(body.get(k)) else 0)
                elif k == "teacher_base_rate":
                    params.append(int(body.get(k)))
                else:
                    params.append(body.get(k))

        # Опциональная смена отдела филиала
        if "department_id" in body:
            dep_raw = body.get("department_id")
            try:
                new_department_id_int = int(dep_raw)
            except Exception:
                abort(400, description="Invalid department_id")
            fields.append("department_id=%s")
            params.append(new_department_id_int)

        if not fields:
            abort(400, description="No fields to update")

        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM branches b
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE b.id=%s AND do2.owner_id=%s
                """,
                (branch_id, u.owner_id),
            )
            if not ok:
                abort(404)

            # Если отдел меняется — проверяем доступ владельца к целевому отделу
            if new_department_id_int is not None:
                ok_dep = fetch_one(
                    cur,
                    "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s",
                    (new_department_id_int, u.owner_id),
                )
                if not ok_dep:
                    abort(403, description="No access to target department")

            cur.execute(f"UPDATE branches SET {', '.join(fields)} WHERE id=%s", tuple(params + [branch_id]))
            row = fetch_one(cur, "SELECT * FROM branches WHERE id=%s", (branch_id,))
        return _ok(row)

    @app.put(f"{API_BASE}/branches/<int:branch_id>/price")
    @require_auth
    @require_role("OWNER")
    def branches_update_price(branch_id: int) -> Response:
        body = request.get_json(silent=True) or {}
        if "price_per_child" not in body:
            abort(400, description="price_per_child is required")
        return branches_update(branch_id)

    @app.get(f"{API_BASE}/branches/<int:branch_id>")
    @require_auth
    def branches_get(branch_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            if u.role == "OWNER":
                row = fetch_one(
                    cur,
                    """
                    SELECT b.*, d.name AS department_name
                    FROM branches b
                    JOIN departments d ON d.id=b.department_id
                    JOIN department_owners do2 ON do2.department_id=b.department_id
                    WHERE b.id=%s AND do2.owner_id=%s
                    """,
                    (branch_id, u.owner_id),
                )
            else:
                row = fetch_one(
                    cur,
                    """
                    SELECT b.id, b.department_id, b.name, b.address, b.metro, b.is_active, b.created_at, b.updated_at,
                           d.name AS department_name
                    FROM branches b
                    JOIN departments d ON d.id=b.department_id
                    JOIN branch_teachers bt ON bt.branch_id=b.id
                    WHERE b.id=%s AND bt.teacher_id=%s
                    """,
                    (branch_id, u.teacher_id),
                )
        if not row:
            abort(404)
        return _ok(row)

    @app.delete(f"{API_BASE}/branches/<int:branch_id>")
    @require_auth
    @require_role("OWNER")
    def branches_delete(branch_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM branches b
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE b.id=%s AND do2.owner_id=%s
                """,
                (branch_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("DELETE FROM branches WHERE id=%s", (branch_id,))
        return _ok({"deleted": True})

    @app.put(f"{API_BASE}/branches/<int:branch_id>/activate")
    @require_auth
    @require_role("OWNER")
    def branches_activate(branch_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM branches b
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE b.id=%s AND do2.owner_id=%s
                """,
                (branch_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("UPDATE branches SET is_active=1 WHERE id=%s", (branch_id,))
        return branches_get(branch_id)

    @app.put(f"{API_BASE}/branches/<int:branch_id>/deactivate")
    @require_auth
    @require_role("OWNER")
    def branches_deactivate(branch_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM branches b
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE b.id=%s AND do2.owner_id=%s
                """,
                (branch_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("UPDATE branches SET is_active=0 WHERE id=%s", (branch_id,))
        return branches_get(branch_id)

    # ------------------------------------------------------------
    # Branch <-> Teachers bindings (OWNER)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/branches/<int:branch_id>/teachers")
    @require_auth
    def branch_teachers_list(branch_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            if u.role == "OWNER":
                ok = fetch_one(
                    cur,
                    """
                    SELECT 1
                    FROM branches b
                    JOIN department_owners do2 ON do2.department_id=b.department_id
                    WHERE b.id=%s AND do2.owner_id=%s
                    """,
                    (branch_id, u.owner_id),
                )
                if not ok:
                    abort(404)
            else:
                ok = fetch_one(
                    cur,
                    "SELECT 1 FROM branch_teachers WHERE branch_id=%s AND teacher_id=%s",
                    (branch_id, u.teacher_id),
                )
                if not ok:
                    abort(404)

            rows = fetch_all(
                cur,
                """
                SELECT t.*
                FROM branch_teachers bt
                JOIN teachers t ON t.id=bt.teacher_id
                WHERE bt.branch_id=%s
                ORDER BY t.full_name
                """,
                (branch_id,),
            )
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/branches/<int:branch_id>/teachers/<int:teacher_id>")
    @require_auth
    @require_role("OWNER")
    def branch_teacher_add(branch_id: int, teacher_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM branches b
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE b.id=%s AND do2.owner_id=%s
                """,
                (branch_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("INSERT INTO branch_teachers(branch_id, teacher_id) VALUES (%s,%s)", (branch_id, teacher_id))
        return _ok({"added": True})

    @app.delete(f"{API_BASE}/branches/<int:branch_id>/teachers/<int:teacher_id>")
    @require_auth
    @require_role("OWNER")
    def branch_teacher_remove(branch_id: int, teacher_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM branches b
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE b.id=%s AND do2.owner_id=%s
                """,
                (branch_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("DELETE FROM branch_teachers WHERE branch_id=%s AND teacher_id=%s", (branch_id, teacher_id))
        return _ok({"deleted": True})

    @app.put(f"{API_BASE}/branches/<int:branch_id>/teachers")
    @require_auth
    @require_role("OWNER")
    def branch_teachers_replace(branch_id: int) -> Response:
        """
        Заменить список преподавателей филиала целиком (удобно для UI):
        body: { teacher_ids: [..] }
        """
        u = _current_user()
        body = request.get_json(silent=True) or {}
        teacher_ids = body.get("teacher_ids") or []
        if not isinstance(teacher_ids, list):
            abort(400, description="teacher_ids must be list")

        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM branches b
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE b.id=%s AND do2.owner_id=%s
                """,
                (branch_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("DELETE FROM branch_teachers WHERE branch_id=%s", (branch_id,))
            for tid in teacher_ids:
                cur.execute("INSERT INTO branch_teachers(branch_id, teacher_id) VALUES (%s,%s)", (branch_id, int(tid)))
        return branch_teachers_list(branch_id)

    # ------------------------------------------------------------
    # Teachers
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/teachers")
    @require_auth
    @require_role("OWNER")
    def teachers_list() -> Response:
        args = dict(request.args)
        status = args.get("status")
        q = (args.get("q") or "").strip()
        limit, offset = _paginate(args)
        where = ["1=1"]
        params: list[Any] = []
        if status:
            where.append("status=%s")
            params.append(status)
        if q:
            where.append("full_name LIKE %s")
            params.append(f"%{q}%")
        params.extend([limit, offset])
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                f"SELECT * FROM teachers WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT %s OFFSET %s",
                tuple(params),
            )
        return _ok({"items": rows, "limit": limit, "offset": offset})

    @app.post(f"{API_BASE}/teachers")
    @require_auth
    @require_role("OWNER")
    def teachers_create() -> Response:
        body = request.get_json(silent=True) or {}
        full_name = (body.get("full_name") or "").strip()
        color = (body.get("color") or "").strip()
        status = (body.get("status") or "working").strip()
        is_salary_free = 1 if _parse_bool(body.get("is_salary_free", False)) else 0
        create_user = _parse_bool(body.get("create_user", False))
        login = (body.get("login") or "").strip()
        password = body.get("password")
        if not full_name or not color:
            abort(400, description="full_name and color are required")
        if status not in ("working", "vacation", "fired"):
            abort(400, description="Invalid status")
        with db_cursor() as (_, cur):
            tid = exec_one(
                cur,
                "INSERT INTO teachers(full_name, color, status, is_salary_free) VALUES (%s,%s,%s,%s)",
                (full_name, color, status, is_salary_free),
            )
            if create_user:
                if not login or password is None:
                    abort(400, description="login/password required to create user")
                exec_one(
                    cur,
                    "INSERT INTO auf_users(login, password_hash, role, teacher_id, is_active) VALUES (%s,%s,'TEACHER',%s,1)",
                    (login, str(password), tid),
                )
            row = fetch_one(cur, "SELECT * FROM teachers WHERE id=%s", (tid,))
        return _ok(row)

    @app.get(f"{API_BASE}/teachers/<int:teacher_id>")
    @require_auth
    def teachers_get(teacher_id: int) -> Response:
        u = _current_user()
        if u.role == "TEACHER" and u.teacher_id != teacher_id:
            abort(403)
        with db_cursor() as (_, cur):
            row = fetch_one(cur, "SELECT * FROM teachers WHERE id=%s", (teacher_id,))
            if not row:
                abort(404)
            # удобные агрегации
            agg = fetch_one(
                cur,
                "SELECT COUNT(*) AS lessons_count FROM lessons WHERE teacher_id=%s",
                (teacher_id,),
            )
        return _ok({"teacher": row, "stats": agg})

    @app.put(f"{API_BASE}/teachers/<int:teacher_id>")
    @require_auth
    @require_role("OWNER")
    def teachers_update(teacher_id: int) -> Response:
        body = request.get_json(silent=True) or {}
        fields: list[str] = []
        params: list[Any] = []
        will_fire = False
        for k in ["full_name", "color", "status", "is_salary_free"]:
            if k in body:
                if k == "status" and body.get(k) not in ("working", "vacation", "fired"):
                    abort(400, description="Invalid status")
                if k == "is_salary_free":
                    fields.append("is_salary_free=%s")
                    params.append(1 if _parse_bool(body.get(k)) else 0)
                else:
                    fields.append(f"{k}=%s")
                    params.append(body.get(k))
                if k == "status" and body.get(k) == "fired":
                    will_fire = True
        if not fields:
            abort(400, description="No fields to update")
        with db_cursor() as (_, cur):
            cur.execute(f"UPDATE teachers SET {', '.join(fields)} WHERE id=%s", tuple(params + [teacher_id]))
            if will_fire:
                cur.execute("DELETE FROM branch_teachers WHERE teacher_id=%s", (teacher_id,))
            row = fetch_one(cur, "SELECT * FROM teachers WHERE id=%s", (teacher_id,))
        if not row:
            abort(404)
        return _ok(row)

    @app.put(f"{API_BASE}/teachers/<int:teacher_id>/status")
    @require_auth
    @require_role("OWNER")
    def teachers_update_status(teacher_id: int) -> Response:
        body = request.get_json(silent=True) or {}
        status = (body.get("status") or "").strip()
        if status not in ("working", "vacation", "fired"):
            abort(400, description="status must be working/vacation/fired")
        with db_cursor() as (_, cur):
            cur.execute("UPDATE teachers SET status=%s WHERE id=%s", (status, teacher_id))
            if status == "fired":
                cur.execute("DELETE FROM branch_teachers WHERE teacher_id=%s", (teacher_id,))
            row = fetch_one(cur, "SELECT * FROM teachers WHERE id=%s", (teacher_id,))
        if not row:
            abort(404)
        return _ok(row)

    @app.delete(f"{API_BASE}/teachers/<int:teacher_id>")
    @require_auth
    @require_role("OWNER")
    def teachers_delete(teacher_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM teachers WHERE id=%s", (teacher_id,))
        return _ok({"deleted": True})

    @app.get(f"{API_BASE}/teachers/<int:teacher_id>/branches")
    @require_auth
    def teachers_branches(teacher_id: int) -> Response:
        u = _current_user()
        if u.role == "TEACHER" and u.teacher_id != teacher_id:
            abort(403)
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                """
                SELECT b.id, b.department_id, d.name AS department_name, b.name, b.address, b.metro, b.is_active
                FROM branch_teachers bt
                JOIN branches b ON b.id=bt.branch_id
                LEFT JOIN departments d ON d.id=b.department_id
                WHERE bt.teacher_id=%s AND b.is_active=1
                ORDER BY b.name
                """,
                (teacher_id,),
            )
        # TEACHER не отдаём price_per_child
        return _ok({"items": rows})

    @app.put(f"{API_BASE}/teachers/<int:teacher_id>/branches")
    @require_auth
    @require_role("OWNER")
    def teachers_branches_replace(teacher_id: int) -> Response:
        """
        Заменить список филиалов преподавателя целиком:
        body: { branch_ids: [..] }
        """
        body = request.get_json(silent=True) or {}
        branch_ids = body.get("branch_ids") or []
        if not isinstance(branch_ids, list):
            abort(400, description="branch_ids must be list")
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM branch_teachers WHERE teacher_id=%s", (teacher_id,))
            for bid in branch_ids:
                cur.execute("INSERT INTO branch_teachers(branch_id, teacher_id) VALUES (%s,%s)", (int(bid), teacher_id))
        return teachers_branches(teacher_id)

    # ------------------------------------------------------------
    # Instruction sections + instructions
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/instruction-sections")
    @require_auth
    @require_role("OWNER")
    def instruction_sections_list() -> Response:
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, "SELECT * FROM instruction_sections ORDER BY name")
        return _ok({"items": rows})

    @app.get(f"{API_BASE}/instruction-sections/public")
    @require_auth
    def instruction_sections_public() -> Response:
        # Для TEACHER — чтобы удобнее фильтровать инструкции; без прав на изменение.
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, "SELECT id, name, description FROM instruction_sections ORDER BY name")
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/instruction-sections")
    @require_auth
    @require_role("OWNER")
    def instruction_sections_create() -> Response:
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        description = body.get("description")
        if not name:
            abort(400, description="name is required")
        with db_cursor() as (_, cur):
            sid = exec_one(cur, "INSERT INTO instruction_sections(name, description) VALUES (%s,%s)", (name, description))
            row = fetch_one(cur, "SELECT * FROM instruction_sections WHERE id=%s", (sid,))
        return _ok(row)

    @app.put(f"{API_BASE}/instruction-sections/<int:section_id>")
    @require_auth
    @require_role("OWNER")
    def instruction_sections_update(section_id: int) -> Response:
        body = request.get_json(silent=True) or {}
        fields: list[str] = []
        params: list[Any] = []
        for k in ["name", "description"]:
            if k in body:
                fields.append(f"{k}=%s")
                params.append(body.get(k))
        if not fields:
            abort(400, description="No fields to update")
        with db_cursor() as (_, cur):
            cur.execute(f"UPDATE instruction_sections SET {', '.join(fields)} WHERE id=%s", tuple(params + [section_id]))
            row = fetch_one(cur, "SELECT * FROM instruction_sections WHERE id=%s", (section_id,))
        if not row:
            abort(404)
        return _ok(row)

    @app.delete(f"{API_BASE}/instruction-sections/<int:section_id>")
    @require_auth
    @require_role("OWNER")
    def instruction_sections_delete(section_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM instruction_sections WHERE id=%s", (section_id,))
        return _ok({"deleted": True})

    @app.get(f"{API_BASE}/instructions")
    @require_auth
    def instructions_list() -> Response:
        args = dict(request.args)
        section_id = args.get("section_id")
        q = (args.get("q") or "").strip()
        limit, offset = _paginate(args, default_limit=100, max_limit=1000)
        where = ["1=1"]
        params: list[Any] = []
        if section_id:
            where.append("i.section_id=%s")
            params.append(int(section_id))
        if q:
            where.append("i.name LIKE %s")
            params.append(f"%{q}%")
        params.extend([limit, offset])

        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                f"""
                SELECT
                    i.id,
                    i.section_id,
                    s.name AS section_name,
                    i.name,
                    i.description,
                    i.pdf_filename,
                    i.pdf_mime,
                    i.created_at,
                    i.updated_at,
                    (i.photo_blob IS NOT NULL) AS has_photo
                FROM instructions i
                JOIN instruction_sections s ON s.id=i.section_id
                WHERE {' AND '.join(where)}
                ORDER BY i.id DESC
                LIMIT %s OFFSET %s
                """,
                tuple(params),
            )
        return _ok({"items": rows, "limit": limit, "offset": offset})

    @app.post(f"{API_BASE}/instructions")
    @require_auth
    @require_role("OWNER")
    def instructions_create() -> Response:
        # Поддерживаем:
        # - multipart/form-data: file=... + section_id/name/description
        # - json: pdf_base64 + pdf_filename/pdf_mime
        body_json = request.get_json(silent=True) or {}
        section_id = request.form.get("section_id") or body_json.get("section_id")
        name = request.form.get("name") or body_json.get("name")
        description = request.form.get("description") or body_json.get("description")

        if section_id is None or not name:
            abort(400, description="section_id and name are required")

        pdf_bytes: bytes | None = None
        pdf_filename: str | None = None
        pdf_mime: str | None = None
        photo_bytes: bytes | None = None
        photo_filename: str | None = None
        photo_mime: str | None = None

        if "file" in request.files:
            f = request.files["file"]
            pdf_bytes = f.read()
            pdf_filename = f.filename
            pdf_mime = f.mimetype or "application/pdf"
        else:
            b64 = body_json.get("pdf_base64")
            if not b64:
                abort(400, description="Provide PDF file (multipart) or pdf_base64 (json)")
            pdf_bytes = base64.b64decode(b64)
            pdf_filename = body_json.get("pdf_filename")
            pdf_mime = body_json.get("pdf_mime") or "application/pdf"

        if not pdf_bytes:
            abort(400, description="Empty PDF")
        if len(pdf_bytes) > MAX_PDF_BYTES:
            abort(413, description=f"PDF too large (max {MAX_PDF_BYTES // (1024 * 1024)} MB)")

        if "photo" in request.files:
            pf = request.files["photo"]
            photo_bytes = pf.read()
            if not photo_bytes:
                abort(400, description="Empty photo")
            if len(photo_bytes) > MAX_PHOTO_BYTES:
                abort(413, description=f"Photo too large (max {MAX_PHOTO_BYTES // (1024 * 1024)} MB)")
            photo_filename = pf.filename
            photo_mime = pf.mimetype or "image/jpeg"
        else:
            photo_b64 = body_json.get("photo_base64")
            if photo_b64:
                photo_bytes = base64.b64decode(photo_b64)
                if not photo_bytes:
                    abort(400, description="Empty photo")
                if len(photo_bytes) > MAX_PHOTO_BYTES:
                    abort(413, description=f"Photo too large (max {MAX_PHOTO_BYTES // (1024 * 1024)} MB)")
                photo_filename = body_json.get("photo_filename")
                photo_mime = body_json.get("photo_mime") or "image/jpeg"

        with db_cursor() as (_, cur):
            iid = exec_one(
                cur,
                """
                INSERT INTO instructions(
                    section_id,
                    name,
                    description,
                    photo_filename,
                    photo_mime,
                    photo_blob,
                    pdf_filename,
                    pdf_mime,
                    pdf_blob
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    int(section_id),
                    str(name).strip(),
                    description,
                    photo_filename,
                    photo_mime,
                    photo_bytes,
                    pdf_filename,
                    pdf_mime,
                    pdf_bytes,
                ),
            )
            row = fetch_one(
                cur,
                """
                SELECT
                    id,
                    section_id,
                    name,
                    description,
                    pdf_filename,
                    pdf_mime,
                    created_at,
                    updated_at,
                    (photo_blob IS NOT NULL) AS has_photo
                FROM instructions
                WHERE id=%s
                """,
                (iid,),
            )
        return _ok(row)

    @app.get(f"{API_BASE}/instructions/<int:instruction_id>")
    @require_auth
    def instructions_get(instruction_id: int) -> Response:
        with db_cursor() as (_, cur):
            row = fetch_one(
                cur,
                """
                SELECT
                    id,
                    section_id,
                    name,
                    description,
                    pdf_filename,
                    pdf_mime,
                    created_at,
                    updated_at,
                    (photo_blob IS NOT NULL) AS has_photo
                FROM instructions
                WHERE id=%s
                """,
                (instruction_id,),
            )
        if not row:
            abort(404)
        return _ok(row)

    @app.put(f"{API_BASE}/instructions/<int:instruction_id>")
    @require_auth
    @require_role("OWNER")
    def instructions_update(instruction_id: int) -> Response:
        body = request.get_json(silent=True) or {}
        fields: list[str] = []
        params: list[Any] = []
        for k in ["section_id", "name", "description", "pdf_filename", "pdf_mime"]:
            if k in body:
                fields.append(f"{k}=%s")
                params.append(body.get(k))
        if not fields:
            abort(400, description="No fields to update")
        with db_cursor() as (_, cur):
            cur.execute(f"UPDATE instructions SET {', '.join(fields)} WHERE id=%s", tuple(params + [instruction_id]))
            row = fetch_one(
                cur,
                """
                SELECT
                    id,
                    section_id,
                    name,
                    description,
                    pdf_filename,
                    pdf_mime,
                    created_at,
                    updated_at,
                    (photo_blob IS NOT NULL) AS has_photo
                FROM instructions
                WHERE id=%s
                """,
                (instruction_id,),
            )
        if not row:
            abort(404)
        return _ok(row)

    @app.put(f"{API_BASE}/instructions/<int:instruction_id>/pdf")
    @require_auth
    @require_role("OWNER")
    def instructions_update_pdf(instruction_id: int) -> Response:
        pdf_bytes: bytes | None = None
        pdf_filename: str | None = None
        pdf_mime: str | None = None

        if "file" in request.files:
            f = request.files["file"]
            pdf_bytes = f.read()
            pdf_filename = f.filename
            pdf_mime = f.mimetype or "application/pdf"
        else:
            body = request.get_json(silent=True) or {}
            b64 = body.get("pdf_base64")
            if not b64:
                abort(400, description="Provide file or pdf_base64")
            pdf_bytes = base64.b64decode(b64)
            pdf_filename = body.get("pdf_filename")
            pdf_mime = body.get("pdf_mime") or "application/pdf"

        if not pdf_bytes:
            abort(400, description="Empty PDF")

        with db_cursor() as (_, cur):
            cur.execute(
                "UPDATE instructions SET pdf_blob=%s, pdf_filename=%s, pdf_mime=%s WHERE id=%s",
                (pdf_bytes, pdf_filename, pdf_mime, instruction_id),
            )
        return _ok({"updated": True})

    @app.put(f"{API_BASE}/instructions/<int:instruction_id>/photo")
    @require_auth
    @require_role("OWNER")
    def instructions_update_photo(instruction_id: int) -> Response:
        if _parse_bool((request.get_json(silent=True) or {}).get("remove", False)):
            with db_cursor() as (_, cur):
                cur.execute(
                    "UPDATE instructions SET photo_blob=NULL, photo_filename=NULL, photo_mime=NULL WHERE id=%s",
                    (instruction_id,),
                )
            return _ok({"updated": True})

        photo_bytes: bytes | None = None
        photo_filename: str | None = None
        photo_mime: str | None = None

        if "photo" in request.files:
            pf = request.files["photo"]
            photo_bytes = pf.read()
            photo_filename = pf.filename
            photo_mime = pf.mimetype or "image/jpeg"
        else:
            body = request.get_json(silent=True) or {}
            b64 = body.get("photo_base64")
            if not b64:
                abort(400, description="Provide photo file or photo_base64")
            photo_bytes = base64.b64decode(b64)
            photo_filename = body.get("photo_filename")
            photo_mime = body.get("photo_mime") or "image/jpeg"

        if not photo_bytes:
            abort(400, description="Empty photo")
        if len(photo_bytes) > MAX_PHOTO_BYTES:
            abort(413, description=f"Photo too large (max {MAX_PHOTO_BYTES // (1024 * 1024)} MB)")

        with db_cursor() as (_, cur):
            cur.execute(
                "UPDATE instructions SET photo_blob=%s, photo_filename=%s, photo_mime=%s WHERE id=%s",
                (photo_bytes, photo_filename, photo_mime, instruction_id),
            )
        return _ok({"updated": True})

    @app.get(f"{API_BASE}/instructions/<int:instruction_id>/pdf")
    @require_auth
    def instructions_pdf(instruction_id: int) -> Response:
        # TEACHER разрешаем — по ТЗ “по необходимости”
        with db_cursor(dictionary=False) as (_, cur):
            cur.execute("SELECT pdf_blob, pdf_mime, pdf_filename FROM instructions WHERE id=%s", (instruction_id,))
            row = cur.fetchone()
        if not row:
            abort(404)
        pdf_blob, pdf_mime, pdf_filename = row
        # send_file требует file-like — используем BytesIO
        from io import BytesIO

        bio = BytesIO(pdf_blob)
        return send_file(
            bio,
            mimetype=pdf_mime or "application/pdf",
            as_attachment=False,
            download_name=pdf_filename or f"instruction_{instruction_id}.pdf",
            max_age=0,
        )

    @app.get(f"{API_BASE}/instructions/<int:instruction_id>/photo")
    @require_auth
    def instructions_photo(instruction_id: int) -> Response:
        with db_cursor(dictionary=False) as (_, cur):
            cur.execute("SELECT photo_blob, photo_mime, photo_filename FROM instructions WHERE id=%s", (instruction_id,))
            row = cur.fetchone()
        if not row:
            abort(404)
        photo_blob, photo_mime, photo_filename = row
        if not photo_blob:
            abort(404)
        from io import BytesIO

        bio = BytesIO(photo_blob)
        return send_file(
            bio,
            mimetype=photo_mime or "image/jpeg",
            as_attachment=False,
            download_name=photo_filename or f"instruction_{instruction_id}.jpg",
            max_age=0,
        )

    @app.delete(f"{API_BASE}/instructions/<int:instruction_id>")
    @require_auth
    @require_role("OWNER")
    def instructions_delete(instruction_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM instructions WHERE id=%s", (instruction_id,))
        return _ok({"deleted": True})

    # --- END: pasted from app.py (part 1) ---

    # ------------------------------------------------------------
    # Lessons
    # ------------------------------------------------------------
    LessonSort = Literal["starts_at", "id", "paid_children", "trial_children", "total_children", "revenue", "teacher_salary"]

    def _lessons_sort_clause(sort: str | None, order: str | None) -> str:
        sort_whitelist: dict[str, str] = {
            "id": "l.id",
            "starts_at": "l.starts_at",
            "paid_children": "l.paid_children",
            "trial_children": "l.trial_children",
            "total_children": "l.total_children",
            "revenue": "l.revenue",
            "teacher_salary": "l.teacher_salary",
        }
        col = sort_whitelist.get(sort or "starts_at", "l.starts_at")
        ord_sql = "DESC" if str(order or "desc").lower() == "desc" else "ASC"
        return f"ORDER BY {col} {ord_sql}"

    def _lessons_base_select(*, include_financial: bool) -> str:
        if include_financial:
            return """
                SELECT
                  l.id,
                  l.starts_at,
                  l.branch_id,
                  b.name AS branch_name,
                  b.department_id,
                  d.name AS department_name,
                  l.teacher_id,
                  t.full_name AS teacher_name,
                  t.color AS teacher_color,
                  t.status AS teacher_status,
                  l.paid_children,
                  l.trial_children,
                  l.total_children,
                  l.is_creative,
                  l.instruction_id,
                  i.name AS instruction_name,
                  l.is_salary_free,
                  l.price_snapshot,
                  l.revenue,
                  l.teacher_salary,
                  l.created_by_user_id,
                  l.created_at,
                  l.updated_at
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                JOIN departments d ON d.id=b.department_id
                JOIN teachers t ON t.id=l.teacher_id
                LEFT JOIN instructions i ON i.id=l.instruction_id
            """
        return """
            SELECT
              l.id,
              l.starts_at,
              l.branch_id,
              b.name AS branch_name,
              b.department_id,
              d.name AS department_name,
              l.teacher_id,
              t.full_name AS teacher_name,
              t.color AS teacher_color,
              t.status AS teacher_status,
              l.paid_children,
              l.trial_children,
              l.total_children,
              l.is_creative,
              l.instruction_id,
              i.name AS instruction_name,
              l.is_salary_free,
              l.teacher_salary,
              l.created_by_user_id,
              l.created_at,
              l.updated_at
            FROM v_lessons_calc l
            JOIN branches b ON b.id=l.branch_id
            JOIN departments d ON d.id=b.department_id
            JOIN teachers t ON t.id=l.teacher_id
            LEFT JOIN instructions i ON i.id=l.instruction_id
        """

    @app.get(f"{API_BASE}/lessons")
    @require_auth
    def lessons_list() -> Response:
        u = _current_user()
        args = dict(request.args)
        limit, offset = _paginate(args)
        start, end = _parse_period(args)
        department_id = args.get("department_id")
        branch_id = args.get("branch_id")
        teacher_id = args.get("teacher_id")
        is_creative = args.get("is_creative")

        sort = args.get("sort")
        order = args.get("order")
        order_by = _lessons_sort_clause(sort, order)

        where: list[str] = ["1=1"]
        params: list[Any] = []

        if start:
            where.append("l.starts_at >= %s")
            params.append(start.strftime("%Y-%m-%d %H:%M:%S"))
        if end:
            where.append("l.starts_at < %s")
            params.append(end.strftime("%Y-%m-%d %H:%M:%S"))
        if department_id:
            where.append("b.department_id=%s")
            params.append(int(department_id))
        if branch_id:
            where.append("l.branch_id=%s")
            params.append(int(branch_id))
        if teacher_id:
            where.append("l.teacher_id=%s")
            params.append(int(teacher_id))
        if is_creative is not None and str(is_creative) != "":
            where.append("l.is_creative=%s")
            params.append(1 if _parse_bool(is_creative) else 0)

        include_financial = u.role == "OWNER"
        base = _lessons_base_select(include_financial=include_financial)

        if u.role == "OWNER":
            scope_sql, scope_params = _lesson_owner_scope_sql(u.owner_id or 0)
            where.append(scope_sql)
            params.extend(scope_params)
        else:
            where.append("l.teacher_id=%s")
            params.append(u.teacher_id)

        sql = f"""
            {base}
            WHERE {' AND '.join(where)}
            {order_by}
            LIMIT %s OFFSET %s
        """
        params.extend([limit, offset])
        with db_cursor() as (_, cur):
            items = fetch_all(cur, sql, tuple(params))
        return _ok({"items": items, "limit": limit, "offset": offset})

    @app.get(f"{API_BASE}/lessons/<int:lesson_id>")
    @require_auth
    def lessons_get(lesson_id: int) -> Response:
        u = _current_user()
        include_financial = u.role == "OWNER"
        base = _lessons_base_select(include_financial=include_financial)
        where = ["l.id=%s"]
        params: list[Any] = [lesson_id]
        if u.role == "OWNER":
            scope_sql, scope_params = _lesson_owner_scope_sql(u.owner_id or 0)
            where.append(scope_sql)
            params.extend(scope_params)
        else:
            where.append("l.teacher_id=%s")
            params.append(u.teacher_id)
        sql = f"{base} WHERE {' AND '.join(where)}"
        with db_cursor() as (_, cur):
            row = fetch_one(cur, sql, tuple(params))
        if not row:
            abort(404)
        return _ok(row)

    @app.post(f"{API_BASE}/lessons")
    @require_auth
    def lessons_create() -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}

        branch_id = body.get("branch_id")
        starts_at = body.get("starts_at")
        paid_children = body.get("paid_children")
        trial_children = body.get("trial_children")
        is_creative = body.get("is_creative")
        instruction_id = body.get("instruction_id")
        is_salary_free: int | None = None

        if branch_id is None or starts_at is None or paid_children is None or trial_children is None or is_creative is None:
            abort(400, description="branch_id, starts_at, paid_children, trial_children, is_creative are required")

        # teacher_id: TEACHER всегда сам, OWNER может передать
        teacher_id = body.get("teacher_id")
        if u.role == "TEACHER":
            teacher_id = u.teacher_id
        else:
            if teacher_id is None:
                abort(400, description="teacher_id is required for OWNER create")

        # валидация типа занятия
        is_creative_b = 1 if _parse_bool(is_creative) else 0
        if is_creative_b == 1 and instruction_id is not None:
            abort(400, description="Creative lesson cannot have instruction_id")
        if is_creative_b == 0 and instruction_id is None:
            abort(400, description="Non-creative lesson must have instruction_id")

        paid_i = _parse_int("paid_children", paid_children, min_v=0)
        trial_i = _parse_int("trial_children", trial_children, min_v=0)
        if paid_i + trial_i <= 0:
            abort(400, description="paid_children + trial_children must be > 0")

        try:
            starts_dt = datetime.fromisoformat(str(starts_at))
        except Exception:
            abort(400, description="starts_at must be ISO datetime")

        with db_cursor() as (_, cur):
            # scope checks
            if u.role == "OWNER":
                ok = fetch_one(
                    cur,
                    """
                    SELECT 1
                    FROM branches b
                    JOIN department_owners do2 ON do2.department_id=b.department_id
                    WHERE b.id=%s AND do2.owner_id=%s
                    """,
                    (int(branch_id), u.owner_id),
                )
                if not ok:
                    abort(403, description="No access to branch")
            else:
                ok = fetch_one(
                    cur,
                    "SELECT 1 FROM branch_teachers WHERE branch_id=%s AND teacher_id=%s",
                    (int(branch_id), int(teacher_id)),
                )
                if not ok:
                    abort(403, description="Teacher is not assigned to this branch")

            br = fetch_one(cur, "SELECT price_per_child FROM branches WHERE id=%s", (int(branch_id),))
            if not br:
                abort(400, description="Unknown branch")
            price_snapshot = br["price_per_child"]

            if is_salary_free is None:
                trow = fetch_one(cur, "SELECT is_salary_free FROM teachers WHERE id=%s", (int(teacher_id),))
                is_salary_free = 1 if (trow and _parse_bool(trow.get("is_salary_free"))) else 0

            lid = exec_one(
                cur,
                """
                INSERT INTO lessons(
                  branch_id, teacher_id, starts_at, paid_children, trial_children,
                  is_creative, instruction_id, is_salary_free, price_snapshot, created_by_user_id
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (
                    int(branch_id),
                    int(teacher_id),
                    starts_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    paid_i,
                    trial_i,
                    is_creative_b,
                    int(instruction_id) if instruction_id is not None else None,
                    is_salary_free,
                    price_snapshot,
                    u.id,
                ),
            )
        return lessons_get(lid)

    @app.put(f"{API_BASE}/lessons/<int:lesson_id>")
    @require_auth
    def lessons_update(lesson_id: int) -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}

        with db_cursor() as (_, cur):
            row = fetch_one(cur, "SELECT * FROM lessons WHERE id=%s", (lesson_id,))
            if not row:
                abort(404)

            if u.role == "TEACHER":
                if int(row["teacher_id"]) != int(u.teacher_id or 0):
                    abort(403, description="Can edit only own lessons")

                allowed = {"starts_at", "paid_children", "trial_children"}
                forbidden = set(body.keys()) - allowed
                if forbidden:
                    abort(403, description=f"Teacher cannot edit fields: {sorted(forbidden)}")

            # OWNER scope check
            if u.role == "OWNER":
                ok = fetch_one(
                    cur,
                    """
                    SELECT 1
                    FROM lessons l
                    JOIN branches b ON b.id=l.branch_id
                    JOIN department_owners do2 ON do2.department_id=b.department_id
                    WHERE l.id=%s AND do2.owner_id=%s
                    """,
                    (lesson_id, u.owner_id),
                )
                if not ok:
                    abort(404)

            fields: list[str] = []
            params: list[Any] = []

            if "starts_at" in body:
                try:
                    dt = datetime.fromisoformat(str(body.get("starts_at")))
                except Exception:
                    abort(400, description="starts_at must be ISO datetime")
                fields.append("starts_at=%s")
                params.append(dt.strftime("%Y-%m-%d %H:%M:%S"))

            if "paid_children" in body:
                fields.append("paid_children=%s")
                params.append(_parse_int("paid_children", body.get("paid_children"), min_v=0))

            if "trial_children" in body:
                fields.append("trial_children=%s")
                params.append(_parse_int("trial_children", body.get("trial_children"), min_v=0))

            if u.role == "OWNER":
                for k in ["branch_id", "teacher_id", "is_creative", "instruction_id", "price_snapshot"]:
                    if k in body:
                        if k == "is_creative":
                            fields.append("is_creative=%s")
                            params.append(1 if _parse_bool(body.get(k)) else 0)
                        else:
                            fields.append(f"{k}=%s")
                            params.append(body.get(k))

            if not fields:
                abort(400, description="No fields to update")

            # базовая валидация "пустых" занятий
            new_paid = int(body.get("paid_children", row["paid_children"]))
            new_trial = int(body.get("trial_children", row["trial_children"]))
            if new_paid + new_trial <= 0:
                abort(400, description="paid_children + trial_children must be > 0")

            cur.execute(f"UPDATE lessons SET {', '.join(fields)} WHERE id=%s", tuple(params + [lesson_id]))

        return lessons_get(lesson_id)

    @app.post(f"{API_BASE}/lessons/<int:lesson_id>/reprice")
    @require_auth
    @require_role("OWNER")
    def lessons_reprice(lesson_id: int) -> Response:
        # Переписать price_snapshot = текущая цена филиала (осознанная операция владельца)
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM lessons l
                JOIN branches b ON b.id=l.branch_id
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE l.id=%s AND do2.owner_id=%s
                """,
                (lesson_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute(
                """
                UPDATE lessons l
                JOIN branches b ON b.id=l.branch_id
                SET l.price_snapshot=b.price_per_child
                WHERE l.id=%s
                """,
                (lesson_id,),
            )
        return lessons_get(lesson_id)

    def _lessons_set_salary_free(lesson_id: int, is_free: bool) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM lessons l
                JOIN branches b ON b.id=l.branch_id
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE l.id=%s AND do2.owner_id=%s
                """,
                (lesson_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("UPDATE lessons SET is_salary_free=%s WHERE id=%s", (1 if is_free else 0, lesson_id))
        return lessons_get(lesson_id)

    @app.put(f"{API_BASE}/lessons/<int:lesson_id>/salary-free")
    @require_auth
    @require_role("OWNER")
    def lessons_salary_free(lesson_id: int) -> Response:
        return _lessons_set_salary_free(lesson_id, True)

    @app.put(f"{API_BASE}/lessons/<int:lesson_id>/salary-paid")
    @require_auth
    @require_role("OWNER")
    def lessons_salary_paid(lesson_id: int) -> Response:
        return _lessons_set_salary_free(lesson_id, False)

    @app.delete(f"{API_BASE}/lessons/<int:lesson_id>")
    @require_auth
    @require_role("OWNER")
    def lessons_delete(lesson_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM lessons l
                JOIN branches b ON b.id=l.branch_id
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE l.id=%s AND do2.owner_id=%s
                """,
                (lesson_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("DELETE FROM lessons WHERE id=%s", (lesson_id,))
        return _ok({"deleted": True})

    @app.get(f"{API_BASE}/lessons/export.csv")
    @require_auth
    def lessons_export_csv() -> Response:
        u = _current_user()
        # переиспользуем lessons_list логику, но без пагинации (с лимитом)
        args = dict(request.args)
        args.setdefault("limit", "5000")
        args.setdefault("offset", "0")
        # временно подменяем request.args нельзя, поэтому просто вызовем SQL повторно упрощённо:
        start, end = _parse_period(args)
        department_id = args.get("department_id")
        branch_id = args.get("branch_id")
        teacher_id = args.get("teacher_id")

        where: list[str] = ["1=1"]
        params: list[Any] = []
        if start:
            where.append("l.starts_at >= %s")
            params.append(start.strftime("%Y-%m-%d %H:%M:%S"))
        if end:
            where.append("l.starts_at < %s")
            params.append(end.strftime("%Y-%m-%d %H:%M:%S"))
        if department_id:
            where.append("b.department_id=%s")
            params.append(int(department_id))
        if branch_id:
            where.append("l.branch_id=%s")
            params.append(int(branch_id))
        if teacher_id:
            where.append("l.teacher_id=%s")
            params.append(int(teacher_id))

        include_financial = u.role == "OWNER"
        base = _lessons_base_select(include_financial=include_financial)
        if u.role == "OWNER":
            scope_sql, scope_params = _lesson_owner_scope_sql(u.owner_id or 0)
            where.append(scope_sql)
            params.extend(scope_params)
        else:
            where.append("l.teacher_id=%s")
            params.append(u.teacher_id)

        sql = f"""
            {base}
            WHERE {' AND '.join(where)}
            ORDER BY l.starts_at DESC
            LIMIT 5000
        """
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, sql, tuple(params))

        # CSV
        import csv
        from io import StringIO

        buf = StringIO()
        if include_financial:
            cols = [
                "id",
                "starts_at",
                "department_name",
                "branch_name",
                "teacher_name",
                "paid_children",
                "trial_children",
                "total_children",
                "is_creative",
                "instruction_name",
                "price_snapshot",
                "revenue",
                "teacher_salary",
            ]
        else:
            cols = [
                "id",
                "starts_at",
                "department_name",
                "branch_name",
                "teacher_name",
                "paid_children",
                "trial_children",
                "total_children",
                "is_creative",
                "instruction_name",
                "teacher_salary",
            ]
        w = csv.DictWriter(buf, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: _to_jsonable(r.get(c)) for c in cols})

        return Response(
            buf.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=lessons.csv"},
        )

    # ------------------------------------------------------------
    # Settings (OWNER)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/settings")
    @require_auth
    @require_role("OWNER")
    def settings_list() -> Response:
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, "SELECT * FROM settings ORDER BY `key`")
        return _ok({"items": rows})

    @app.get(f"{API_BASE}/settings/<string:key>")
    @require_auth
    @require_role("OWNER")
    def settings_get(key: str) -> Response:
        with db_cursor() as (_, cur):
            row = fetch_one(cur, "SELECT * FROM settings WHERE `key`=%s", (key,))
        if not row:
            abort(404)
        return _ok(row)

    @app.put(f"{API_BASE}/settings/<string:key>")
    @require_auth
    @require_role("OWNER")
    def settings_put(key: str) -> Response:
        body = request.get_json(silent=True) or {}
        # можно передать одно из value_*; остальные NULL
        value_int = body.get("value_int")
        value_decimal = body.get("value_decimal")
        value_bool = body.get("value_bool")
        value_text = body.get("value_text")
        description = body.get("description")
        with db_cursor() as (_, cur):
            cur.execute(
                """
                INSERT INTO settings(`key`, value_int, value_decimal, value_bool, value_text, description)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                  value_int=VALUES(value_int),
                  value_decimal=VALUES(value_decimal),
                  value_bool=VALUES(value_bool),
                  value_text=VALUES(value_text),
                  description=VALUES(description)
                """,
                (
                    key,
                    value_int,
                    value_decimal,
                    1 if (value_bool is not None and _parse_bool(value_bool)) else (0 if value_bool is not None else None),
                    value_text,
                    description,
                ),
            )
            row = fetch_one(cur, "SELECT * FROM settings WHERE `key`=%s", (key,))
        return _ok(row)

    @app.get(f"{API_BASE}/settings/salary")
    @require_auth
    @require_role("OWNER")
    def settings_salary_get() -> Response:
        keys = ["teacher_base_rate", "teacher_threshold_children", "teacher_bonus_per_child"]
        placeholders = ",".join(["%s"] * len(keys))
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, f"SELECT * FROM settings WHERE `key` IN ({placeholders})", tuple(keys))
        by_key = {r["key"]: r for r in rows}
        return _ok({"items": [by_key.get(k) for k in keys]})

    @app.put(f"{API_BASE}/settings/salary")
    @require_auth
    @require_role("OWNER")
    def settings_salary_put() -> Response:
        body = request.get_json(silent=True) or {}
        base_rate = body.get("teacher_base_rate")
        threshold = body.get("teacher_threshold_children")
        bonus = body.get("teacher_bonus_per_child")
        if base_rate is None or threshold is None or bonus is None:
            abort(400, description="teacher_base_rate, teacher_threshold_children, teacher_bonus_per_child are required")
        with db_cursor() as (_, cur):
            for k, v in [
                ("teacher_base_rate", int(base_rate)),
                ("teacher_threshold_children", int(threshold)),
                ("teacher_bonus_per_child", int(bonus)),
            ]:
                cur.execute(
                    """
                    INSERT INTO settings(`key`, value_int, description)
                    VALUES (%s,%s,%s)
                    ON DUPLICATE KEY UPDATE value_int=VALUES(value_int)
                    """,
                    (k, v, "salary setting"),
                )
        return settings_salary_get()

    # ------------------------------------------------------------
    # Dashboards / reports
    # ------------------------------------------------------------
    def _dashboard_filters_sql(u: CurrentUser, args: dict[str, Any]) -> tuple[str, list[Any]]:
        start, end = _parse_period(args)
        department_id = args.get("department_id")
        branch_id = args.get("branch_id")
        teacher_id = args.get("teacher_id")
        where: list[str] = ["1=1"]
        params: list[Any] = []
        if start:
            where.append("l.starts_at >= %s")
            params.append(start.strftime("%Y-%m-%d %H:%M:%S"))
        if end:
            where.append("l.starts_at < %s")
            params.append(end.strftime("%Y-%m-%d %H:%M:%S"))
        if department_id:
            where.append("b.department_id=%s")
            params.append(int(department_id))
        if branch_id:
            where.append("l.branch_id=%s")
            params.append(int(branch_id))
        if teacher_id:
            where.append("l.teacher_id=%s")
            params.append(int(teacher_id))

        if u.role == "OWNER":
            scope_sql, scope_params = _lesson_owner_scope_sql(u.owner_id or 0)
            where.append(scope_sql)
            params.extend(scope_params)
        else:
            where.append("l.teacher_id=%s")
            params.append(u.teacher_id)

        return " AND ".join(where), params

    @app.get(f"{API_BASE}/dashboard/owner")
    @require_auth
    @require_role("OWNER")
    def dashboard_owner() -> Response:
        u = _current_user()
        args = dict(request.args)
        where_sql, params = _dashboard_filters_sql(u, args)

        with db_cursor() as (_, cur):
            kpi = fetch_one(
                cur,
                f"""
                SELECT
                  COALESCE(SUM(l.revenue),0) AS revenue_sum,
                  COALESCE(SUM(l.paid_children),0) AS paid_sum,
                  COALESCE(SUM(l.trial_children),0) AS trial_sum,
                  COALESCE(SUM(l.total_children),0) AS total_children_sum,
                  COALESCE(COUNT(*),0) AS lessons_count,
                  COALESCE(AVG(l.total_children),0) AS avg_children_per_lesson
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                """,
                tuple(params),
            )

            series = fetch_all(
                cur,
                f"""
                SELECT DATE_FORMAT(l.starts_at, '%%Y-%%m') AS period,
                       COALESCE(SUM(l.revenue),0) AS revenue_sum,
                       COALESCE(SUM(l.total_children),0) AS total_children_sum,
                       COALESCE(COUNT(*),0) AS lessons_count
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                GROUP BY period
                ORDER BY period
                """,
                tuple(params),
            )

            top_branches = fetch_all(
                cur,
                f"""
                SELECT b.id AS branch_id, b.name AS branch_name,
                       COALESCE(SUM(l.revenue),0) AS revenue_sum,
                       COALESCE(SUM(l.total_children),0) AS total_children_sum,
                       COALESCE(COUNT(*),0) AS lessons_count
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                GROUP BY b.id, b.name
                ORDER BY revenue_sum DESC
                LIMIT 10
                """,
                tuple(params),
            )

            top_teachers = fetch_all(
                cur,
                f"""
                SELECT t.id AS teacher_id, t.full_name AS teacher_name,
                       COALESCE(SUM(l.revenue),0) AS revenue_sum,
                       COALESCE(SUM(l.total_children),0) AS total_children_sum,
                       COALESCE(COUNT(*),0) AS lessons_count
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                JOIN teachers t ON t.id=l.teacher_id
                WHERE {where_sql}
                GROUP BY t.id, t.full_name
                ORDER BY revenue_sum DESC
                LIMIT 10
                """,
                tuple(params),
            )

        return _ok({"kpi": kpi, "series_by_month": series, "top_branches": top_branches, "top_teachers": top_teachers})

    @app.get(f"{API_BASE}/dashboard/teacher")
    @require_auth
    @require_role("TEACHER")
    def dashboard_teacher() -> Response:
        u = _current_user()
        args = dict(request.args)
        where_sql, params = _dashboard_filters_sql(u, args)

        with db_cursor() as (_, cur):
            kpi = fetch_one(
                cur,
                f"""
                SELECT
                  COALESCE(SUM(l.teacher_salary),0) AS salary_sum,
                  COALESCE(SUM(l.total_children),0) AS total_children_sum,
                  COALESCE(COUNT(*),0) AS lessons_count
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                """,
                tuple(params),
            )
            total_lessons = fetch_one(
                cur,
                "SELECT COUNT(*) AS total_lessons_count FROM lessons WHERE teacher_id=%s",
                (u.teacher_id,),
            )
        return _ok({"kpi": kpi, "total": total_lessons})

    # ------------------------------------------------------------
    # Salary by department (TEACHER: my salary per department; OWNER: per department, per teacher)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/salary/teacher-by-department")
    @require_auth
    @require_role("TEACHER")
    def salary_teacher_by_department() -> Response:
        u = _current_user()
        args = dict(request.args)
        where_sql, params = _dashboard_filters_sql(u, args)
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                f"""
                SELECT
                  b.department_id,
                  d.name AS department_name,
                  COALESCE(SUM(l.teacher_salary),0) AS salary_sum,
                  COALESCE(COUNT(*),0) AS lessons_count
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                JOIN departments d ON d.id=b.department_id
                WHERE {where_sql}
                GROUP BY b.department_id, d.name
                ORDER BY d.name
                """,
                tuple(params),
            )
            total_row = fetch_one(
                cur,
                f"""
                SELECT COALESCE(SUM(l.teacher_salary),0) AS total_salary
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                """,
                tuple(params),
            )
        total_salary = (total_row or {}).get("total_salary") or 0
        return _ok({"total_salary": total_salary, "by_department": rows or []})

    @app.get(f"{API_BASE}/salary/owner-by-department")
    @require_auth
    @require_role("OWNER")
    def salary_owner_by_department() -> Response:
        u = _current_user()
        args = dict(request.args)
        start, end = _parse_period(args)
        where: list[str] = [
            "EXISTS (SELECT 1 FROM branches b JOIN department_owners do2 ON do2.department_id=b.department_id WHERE b.id=l.branch_id AND do2.owner_id=%s)",
        ]
        params: list[Any] = [u.owner_id]
        if start:
            where.append("l.starts_at >= %s")
            params.append(start.strftime("%Y-%m-%d %H:%M:%S"))
        if end:
            where.append("l.starts_at < %s")
            params.append(end.strftime("%Y-%m-%d %H:%M:%S"))
        where_sql = " AND ".join(where)
        # Граница 16-го числа для разбивки 1–15 и 16–конец месяца
        start_16 = (start + timedelta(days=15)) if start else None
        start_fmt = start.strftime("%Y-%m-%d %H:%M:%S") if start else ""
        start_16_fmt = start_16.strftime("%Y-%m-%d %H:%M:%S") if start_16 else ""
        end_fmt = end.strftime("%Y-%m-%d %H:%M:%S") if end else ""
        with db_cursor() as (_, cur):
            # Разбивка по датам: 1–15 (starts_at < start_16), 16–конец (starts_at >= start_16)
            if start and start_16 and end:
                # Порядок %s в SQL: сначала 8 в SELECT (CASE), потом 3 в WHERE — параметры в том же порядке
                params_ext = [
                    start_fmt, start_16_fmt,  # salary_1_15
                    start_fmt, start_16_fmt,  # lessons_1_15
                    start_16_fmt, end_fmt,    # salary_16_end
                    start_16_fmt, end_fmt,    # lessons_16_end
                ] + list(params)
                rows = fetch_all(
                    cur,
                    f"""
                    SELECT
                      b.department_id,
                      d.name AS department_name,
                      l.teacher_id,
                      t.full_name AS teacher_name,
                      COALESCE(SUM(l.teacher_salary),0) AS salary_sum,
                      COALESCE(COUNT(*),0) AS lessons_count,
                      COALESCE(SUM(CASE WHEN l.starts_at >= %s AND l.starts_at < %s THEN l.teacher_salary ELSE 0 END),0) AS salary_1_15,
                      COALESCE(SUM(CASE WHEN l.starts_at >= %s AND l.starts_at < %s THEN 1 ELSE 0 END),0) AS lessons_1_15,
                      COALESCE(SUM(CASE WHEN l.starts_at >= %s AND l.starts_at < %s THEN l.teacher_salary ELSE 0 END),0) AS salary_16_end,
                      COALESCE(SUM(CASE WHEN l.starts_at >= %s AND l.starts_at < %s THEN 1 ELSE 0 END),0) AS lessons_16_end
                    FROM v_lessons_calc l
                    JOIN branches b ON b.id=l.branch_id
                    JOIN departments d ON d.id=b.department_id
                    JOIN teachers t ON t.id=l.teacher_id
                    WHERE {where_sql}
                    GROUP BY b.department_id, d.name, l.teacher_id, t.full_name
                    ORDER BY d.name, t.full_name
                    """,
                    tuple(params_ext),
                )
            else:
                rows = fetch_all(
                    cur,
                    f"""
                    SELECT
                      b.department_id,
                      d.name AS department_name,
                      l.teacher_id,
                      t.full_name AS teacher_name,
                      COALESCE(SUM(l.teacher_salary),0) AS salary_sum,
                      COALESCE(COUNT(*),0) AS lessons_count,
                      0 AS salary_1_15,
                      0 AS lessons_1_15,
                      0 AS salary_16_end,
                      0 AS lessons_16_end
                    FROM v_lessons_calc l
                    JOIN branches b ON b.id=l.branch_id
                    JOIN departments d ON d.id=b.department_id
                    JOIN teachers t ON t.id=l.teacher_id
                    WHERE {where_sql}
                    GROUP BY b.department_id, d.name, l.teacher_id, t.full_name
                    ORDER BY d.name, t.full_name
                    """,
                    tuple(params),
                )
        # Группируем по отделам
        by_dep: dict[int, dict[str, Any]] = {}
        for r in rows or []:
            dep_id = int(r["department_id"])
            if dep_id not in by_dep:
                by_dep[dep_id] = {
                    "department_id": dep_id,
                    "department_name": r["department_name"],
                    "teachers": [],
                    "department_total": 0,
                }
            salary_sum = float(r["salary_sum"] or 0)
            by_dep[dep_id]["teachers"].append({
                "teacher_id": r["teacher_id"],
                "teacher_name": r["teacher_name"],
                "salary_sum": salary_sum,
                "lessons_count": int(r["lessons_count"] or 0),
                "salary_1_15": float(r["salary_1_15"] or 0),
                "lessons_1_15": int(r["lessons_1_15"] or 0),
                "salary_16_end": float(r["salary_16_end"] or 0),
                "lessons_16_end": int(r["lessons_16_end"] or 0),
            })
            by_dep[dep_id]["department_total"] += salary_sum
        result = list(by_dep.values())
        result.sort(key=lambda x: (x["department_name"], x["department_id"]))
        return _ok({"by_department": result})

    @app.get(f"{API_BASE}/reports/revenue-by-month")
    @require_auth
    @require_role("OWNER")
    def report_revenue_by_month() -> Response:
        u = _current_user()
        args = dict(request.args)
        where_sql, params = _dashboard_filters_sql(u, args)
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                f"""
                SELECT DATE_FORMAT(l.starts_at, '%%Y-%%m') AS month,
                       COALESCE(SUM(l.revenue),0) AS revenue_sum,
                       COALESCE(SUM(l.paid_children),0) AS paid_sum,
                       COALESCE(SUM(l.trial_children),0) AS trial_sum,
                       COALESCE(COUNT(*),0) AS lessons_count
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                GROUP BY month
                ORDER BY month
                """,
                tuple(params),
            )
        return _ok({"items": rows})

    @app.get(f"{API_BASE}/reports/attendance-by-month")
    @require_auth
    @require_role("OWNER")
    def report_attendance_by_month() -> Response:
        u = _current_user()
        args = dict(request.args)
        where_sql, params = _dashboard_filters_sql(u, args)
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                f"""
                SELECT DATE_FORMAT(l.starts_at, '%%Y-%%m') AS month,
                       COALESCE(SUM(l.total_children),0) AS total_children_sum,
                       COALESCE(SUM(l.paid_children),0) AS paid_sum,
                       COALESCE(SUM(l.trial_children),0) AS trial_sum
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                GROUP BY month
                ORDER BY month
                """,
                tuple(params),
            )
        return _ok({"items": rows})

    @app.get(f"{API_BASE}/reports/branch/<int:branch_id>/summary")
    @require_auth
    def report_branch_summary(branch_id: int) -> Response:
        u = _current_user()
        args = dict(request.args)
        args["branch_id"] = str(branch_id)
        where_sql, params = _dashboard_filters_sql(u, args)
        if u.role != "OWNER":
            abort(403)
        with db_cursor() as (_, cur):
            kpi = fetch_one(
                cur,
                f"""
                SELECT
                  COALESCE(SUM(l.revenue),0) AS revenue_sum,
                  COALESCE(SUM(l.total_children),0) AS total_children_sum,
                  COALESCE(COUNT(*),0) AS lessons_count
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                """,
                tuple(params),
            )
        return _ok({"branch_id": branch_id, "kpi": kpi})

    @app.get(f"{API_BASE}/reports/teacher/<int:teacher_id>/summary")
    @require_auth
    def report_teacher_summary(teacher_id: int) -> Response:
        u = _current_user()
        args = dict(request.args)
        args["teacher_id"] = str(teacher_id)
        if u.role == "TEACHER" and u.teacher_id != teacher_id:
            abort(403)
        where_sql, params = _dashboard_filters_sql(u, args)
        with db_cursor() as (_, cur):
            kpi = fetch_one(
                cur,
                f"""
                SELECT
                  COALESCE(SUM(l.teacher_salary),0) AS salary_sum,
                  COALESCE(SUM(l.total_children),0) AS total_children_sum,
                  COALESCE(COUNT(*),0) AS lessons_count
                FROM v_lessons_calc l
                JOIN branches b ON b.id=l.branch_id
                WHERE {where_sql}
                """,
                tuple(params),
            )
            out: dict[str, Any] = {"teacher_id": teacher_id, "kpi": kpi}
            if u.role == "OWNER":
                # owner может видеть и выручку по преподавателю
                kpi2 = fetch_one(
                    cur,
                    f"""
                    SELECT COALESCE(SUM(l.revenue),0) AS revenue_sum
                    FROM v_lessons_calc l
                    JOIN branches b ON b.id=l.branch_id
                    WHERE {where_sql}
                    """,
                    tuple(params),
                )
                out["kpi"]["revenue_sum"] = (kpi2 or {}).get("revenue_sum", 0)
        return _ok(out)

    # ------------------------------------------------------------
    # Lookups (для фронта: селекты/фильтры)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/lookup/branches")
    @require_auth
    def lookup_branches() -> Response:
        # alias к branches_list без лишнего
        return branches_list()

    @app.get(f"{API_BASE}/lookup/teachers")
    @require_auth
    def lookup_teachers() -> Response:
        u = _current_user()
        if u.role == "TEACHER":
            return _ok({"items": [{"id": u.teacher_id, "self": True}]})
        return teachers_list()

    def _schedule_one(cur, schedule_id: int) -> dict[str, Any] | None:
        """Fetch one schedule row with assigned_teacher and teachers list."""
        row = fetch_one(
            cur,
            """
            SELECT s.*, b.name AS branch_name, b.department_id, d.name AS department_name,
                   t.id AS assigned_teacher_id, t.full_name AS assigned_teacher_name, t.color AS assigned_teacher_color
            FROM schedules s
            JOIN branches b ON b.id = s.branch_id
            JOIN departments d ON d.id = b.department_id
            LEFT JOIN teachers t ON t.id = s.teacher_id
            WHERE s.id = %s
            """,
            (schedule_id,),
        )
        if not row:
            return None
        branch_id = int(row["branch_id"])
        trows = fetch_all(
            cur,
            """
            SELECT t.id, t.full_name, t.color, t.status
            FROM branch_teachers bt
            JOIN teachers t ON t.id = bt.teacher_id
            WHERE bt.branch_id = %s AND t.status = 'working'
            ORDER BY t.full_name
            """,
            (branch_id,),
        )
        row["teachers"] = [
            {"id": tr["id"], "full_name": tr["full_name"], "color": tr["color"], "status": tr["status"]}
            for tr in trows
        ]
        tid = row.get("assigned_teacher_id")
        if tid is not None:
            row["assigned_teacher"] = {
                "id": int(tid),
                "full_name": row.get("assigned_teacher_name"),
                "color": row.get("assigned_teacher_color"),
            }
        else:
            row["assigned_teacher"] = None
        for k in ["assigned_teacher_id", "assigned_teacher_name", "assigned_teacher_color"]:
            row.pop(k, None)
        return row

    # ------------------------------------------------------------
    # Schedule (weekly plan)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/schedules")
    @require_auth
    def schedules_list() -> Response:
        u = _current_user()
        args = dict(request.args)
        department_id = args.get("department_id")
        branch_id = args.get("branch_id")
        weekday = args.get("weekday")

        where: list[str] = ["1=1"]
        params: list[Any] = []

        if u.role == "OWNER":
            if department_id:
                where.append("b.department_id=%s")
                params.append(int(department_id))
            else:
                scope_sql, scope_params = _lesson_owner_scope_sql(u.owner_id or 0)
                where.append(scope_sql.replace("l.", "s."))
                params.extend(scope_params)
        else:
            where.append(
                """
                EXISTS (
                  SELECT 1 FROM branch_teachers bt
                  WHERE bt.branch_id = s.branch_id AND bt.teacher_id = %s
                )
                """
            )
            params.append(u.teacher_id)

        if branch_id:
            where.append("s.branch_id=%s")
            params.append(int(branch_id))
        if weekday:
            where.append("s.weekday=%s")
            params.append(int(weekday))

        sql = f"""
            SELECT s.*, b.name AS branch_name, b.department_id, d.name AS department_name,
                   t.id AS assigned_teacher_id, t.full_name AS assigned_teacher_name, t.color AS assigned_teacher_color
            FROM schedules s
            JOIN branches b ON b.id = s.branch_id
            JOIN departments d ON d.id = b.department_id
            LEFT JOIN teachers t ON t.id = s.teacher_id
            WHERE {' AND '.join(where)}
            ORDER BY s.weekday, s.starts_at, s.id
        """
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, sql, tuple(params))

            if rows:
                branch_ids = sorted({int(r["branch_id"]) for r in rows})
                placeholders = ",".join(["%s"] * len(branch_ids))
                trows = fetch_all(
                    cur,
                    f"""
                    SELECT bt.branch_id, t.id, t.full_name, t.color, t.status
                    FROM branch_teachers bt
                    JOIN teachers t ON t.id = bt.teacher_id
                    WHERE bt.branch_id IN ({placeholders}) AND t.status = 'working'
                    ORDER BY t.full_name
                    """,
                    tuple(branch_ids),
                )
            else:
                trows = []

        teachers_by_branch: dict[int, list[dict[str, Any]]] = {}
        for tr in trows:
            bid = int(tr["branch_id"])
            teachers_by_branch.setdefault(bid, []).append(
                {
                    "id": tr["id"],
                    "full_name": tr["full_name"],
                    "color": tr["color"],
                    "status": tr["status"],
                }
            )

        for r in rows:
            r["teachers"] = teachers_by_branch.get(int(r["branch_id"]), [])
            tid = r.get("assigned_teacher_id")
            if tid is not None:
                r["assigned_teacher"] = {
                    "id": int(tid),
                    "full_name": r.get("assigned_teacher_name"),
                    "color": r.get("assigned_teacher_color"),
                }
            else:
                r["assigned_teacher"] = None
            for k in ["assigned_teacher_id", "assigned_teacher_name", "assigned_teacher_color"]:
                r.pop(k, None)
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/schedules")
    @require_auth
    @require_role("OWNER")
    def schedules_create() -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        branch_id = body.get("branch_id")
        weekday = body.get("weekday")
        starts_at = body.get("starts_at")
        duration_minutes = body.get("duration_minutes")
        teacher_id = body.get("teacher_id")

        if branch_id is None or weekday is None or starts_at is None or duration_minutes is None:
            abort(400, description="branch_id, weekday, starts_at, duration_minutes are required")

        weekday_i = _parse_int("weekday", weekday, min_v=1, max_v=7)
        duration_i = _parse_int("duration_minutes", duration_minutes, min_v=1, max_v=600)
        starts_at_s = str(starts_at)
        if len(starts_at_s.split(":")) < 2:
            abort(400, description="starts_at must be HH:MM")

        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM branches b
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE b.id=%s AND do2.owner_id=%s
                """,
                (int(branch_id), u.owner_id),
            )
            if not ok:
                abort(403, description="No access to branch")

            if teacher_id is not None and teacher_id != "":
                tid = int(teacher_id)
                ok_t = fetch_one(
                    cur,
                    "SELECT 1 FROM branch_teachers WHERE branch_id=%s AND teacher_id=%s",
                    (int(branch_id), tid),
                )
                if not ok_t:
                    abort(400, description="Teacher must be assigned to this branch")
            else:
                tid = None

            sid = exec_one(
                cur,
                """
                INSERT INTO schedules(branch_id, weekday, starts_at, duration_minutes, teacher_id)
                VALUES (%s,%s,%s,%s,%s)
                """,
                (int(branch_id), weekday_i, starts_at_s, duration_i, tid),
            )
            row = _schedule_one(cur, sid)
        return _ok(row)

    @app.put(f"{API_BASE}/schedules/<int:schedule_id>")
    @require_auth
    @require_role("OWNER")
    def schedules_update(schedule_id: int) -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        fields: list[str] = []
        params: list[Any] = []

        if "branch_id" in body:
            fields.append("branch_id=%s")
            params.append(int(body.get("branch_id")))
        if "weekday" in body:
            fields.append("weekday=%s")
            params.append(_parse_int("weekday", body.get("weekday"), min_v=1, max_v=7))
        if "starts_at" in body:
            starts_at_s = str(body.get("starts_at"))
            if len(starts_at_s.split(":")) < 2:
                abort(400, description="starts_at must be HH:MM")
            fields.append("starts_at=%s")
            params.append(starts_at_s)
        if "duration_minutes" in body:
            fields.append("duration_minutes=%s")
            params.append(_parse_int("duration_minutes", body.get("duration_minutes"), min_v=1, max_v=600))
        if "teacher_id" in body:
            fields.append("teacher_id=%s")
            tid_val = body.get("teacher_id")
            params.append(int(tid_val) if (tid_val is not None and tid_val != "") else None)

        if not fields:
            abort(400, description="No fields to update")

        with db_cursor() as (_, cur):
            row_check = fetch_one(
                cur,
                """
                SELECT s.branch_id
                FROM schedules s
                JOIN branches b ON b.id=s.branch_id
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE s.id=%s AND do2.owner_id=%s
                """,
                (schedule_id, u.owner_id),
            )
            if not row_check:
                abort(404)
            current_branch_id = int(row_check["branch_id"])

            if "branch_id" in body:
                ok2 = fetch_one(
                    cur,
                    """
                    SELECT 1
                    FROM branches b
                    JOIN department_owners do2 ON do2.department_id=b.department_id
                    WHERE b.id=%s AND do2.owner_id=%s
                    """,
                    (int(body.get("branch_id")), u.owner_id),
                )
                if not ok2:
                    abort(403, description="No access to branch")
                current_branch_id = int(body.get("branch_id"))

            if "teacher_id" in body:
                tid_val = body.get("teacher_id")
                if tid_val is not None and tid_val != "":
                    tid = int(tid_val)
                    ok_t = fetch_one(
                        cur,
                        "SELECT 1 FROM branch_teachers WHERE branch_id=%s AND teacher_id=%s",
                        (current_branch_id, tid),
                    )
                    if not ok_t:
                        abort(400, description="Teacher must be assigned to this branch")

            cur.execute(f"UPDATE schedules SET {', '.join(fields)} WHERE id=%s", tuple(params + [schedule_id]))
            row = _schedule_one(cur, schedule_id)
        return _ok(row)

    @app.delete(f"{API_BASE}/schedules/<int:schedule_id>")
    @require_auth
    @require_role("OWNER")
    def schedules_delete(schedule_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(
                cur,
                """
                SELECT 1
                FROM schedules s
                JOIN branches b ON b.id=s.branch_id
                JOIN department_owners do2 ON do2.department_id=b.department_id
                WHERE s.id=%s AND do2.owner_id=%s
                """,
                (schedule_id, u.owner_id),
            )
            if not ok:
                abort(404)
            cur.execute("DELETE FROM schedules WHERE id=%s", (schedule_id,))
        return _ok({"deleted": True})

    # ------------------------------------------------------------
    # Teacher slots (свободные часы преподавателей по дням недели)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/slots")
    @require_auth
    def slots_list() -> Response:
        u = _current_user()
        args = dict(request.args)
        teacher_id_arg = args.get("teacher_id")
        day_of_week_arg = args.get("day_of_week")

        where: list[str] = ["1=1"]
        params: list[Any] = []

        if u.role == "TEACHER":
            where.append("ts.teacher_id=%s")
            params.append(u.teacher_id)
        else:
            if teacher_id_arg:
                where.append("ts.teacher_id=%s")
                params.append(int(teacher_id_arg))
        if day_of_week_arg:
            where.append("ts.day_of_week=%s")
            params.append(int(day_of_week_arg))

        if u.role == "OWNER" and u.owner_id:
            owner_id = u.owner_id
            sql = f"""
                SELECT ts.id, ts.teacher_id, ts.day_of_week, ts.start_time, ts.status, ts.occupied_by_department_id,
                       ts.created_at, ts.updated_at,
                       t.full_name AS teacher_name, t.color AS teacher_color,
                       (SELECT d.name FROM departments d
                        INNER JOIN department_owners do ON do.department_id = d.id AND do.owner_id = %s
                        WHERE d.id = ts.occupied_by_department_id LIMIT 1) AS occupied_by_department_name
                FROM teacher_slots ts
                JOIN teachers t ON t.id = ts.teacher_id
                WHERE {' AND '.join(where)}
                ORDER BY ts.day_of_week, ts.start_time, ts.id
            """
            params = list(params) + [owner_id]
        else:
            sql = f"""
                SELECT ts.id, ts.teacher_id, ts.day_of_week, ts.start_time, ts.status, ts.occupied_by_department_id,
                       ts.created_at, ts.updated_at,
                       t.full_name AS teacher_name, t.color AS teacher_color
                FROM teacher_slots ts
                JOIN teachers t ON t.id = ts.teacher_id
                WHERE {' AND '.join(where)}
                ORDER BY ts.day_of_week, ts.start_time, ts.id
            """
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, sql, tuple(params))
        for r in rows:
            if r.get("start_time"):
                r["start_time"] = str(r["start_time"])[:5]
            if r.get("occupied_by_department_id") is None:
                r["occupied_by_department_name"] = None
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/slots")
    @require_auth
    def slots_create() -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        day_of_week = body.get("day_of_week")
        start_time = body.get("start_time")

        if day_of_week is None or start_time is None:
            abort(400, description="day_of_week and start_time are required")

        day_i = _parse_int("day_of_week", day_of_week, min_v=1, max_v=7)
        start_time_s = str(start_time).strip()
        if len(start_time_s.split(":")) < 2:
            abort(400, description="start_time must be HH:MM or HH:MM:SS")

        teacher_id: int
        if u.role == "TEACHER":
            teacher_id = u.teacher_id or 0
            if not teacher_id:
                abort(403, description="No teacher linked")
        else:
            tid = body.get("teacher_id")
            if tid is not None:
                teacher_id = int(tid)
            else:
                abort(400, description="For OWNER provide teacher_id")

        status = (body.get("status") or "free").strip().lower()
        if status not in ("free", "occupied"):
            status = "free"
        occupied_by_department_id = body.get("occupied_by_department_id")
        if u.role == "TEACHER":
            occupied_by_department_id = None
        elif u.role == "OWNER" and occupied_by_department_id is not None:
            occupied_by_department_id = int(occupied_by_department_id)
            dep_ids = _owner_department_ids(u.owner_id or 0)
            if dep_ids and occupied_by_department_id not in dep_ids:
                occupied_by_department_id = None
        else:
            occupied_by_department_id = None

        with db_cursor() as (_, cur):
            sid = exec_one(
                cur,
                "INSERT INTO teacher_slots(teacher_id, day_of_week, start_time, status, occupied_by_department_id) VALUES (%s,%s,%s,%s,%s)",
                (teacher_id, day_i, start_time_s, status, occupied_by_department_id),
            )
            row = fetch_one(
                cur,
                """
                SELECT ts.id, ts.teacher_id, ts.day_of_week, ts.start_time, ts.status, ts.occupied_by_department_id,
                       ts.created_at, ts.updated_at,
                       t.full_name AS teacher_name, t.color AS teacher_color
                FROM teacher_slots ts
                JOIN teachers t ON t.id = ts.teacher_id
                WHERE ts.id=%s
                """,
                (sid,),
            )
        if row and row.get("start_time"):
            row["start_time"] = str(row["start_time"])[:5]
        return _ok(row)

    @app.get(f"{API_BASE}/slots/<int:slot_id>")
    @require_auth
    def slots_get(slot_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            if u.role == "OWNER" and u.owner_id:
                row = fetch_one(
                    cur,
                    """
                    SELECT ts.id, ts.teacher_id, ts.day_of_week, ts.start_time, ts.status, ts.occupied_by_department_id,
                           ts.created_at, ts.updated_at,
                           t.full_name AS teacher_name, t.color AS teacher_color,
                           (SELECT d.name FROM departments d
                            INNER JOIN department_owners do ON do.department_id = d.id AND do.owner_id = %s
                            WHERE d.id = ts.occupied_by_department_id LIMIT 1) AS occupied_by_department_name
                    FROM teacher_slots ts
                    JOIN teachers t ON t.id = ts.teacher_id
                    WHERE ts.id=%s
                    """,
                    (u.owner_id, slot_id),
                )
            else:
                row = fetch_one(
                    cur,
                    """
                    SELECT ts.id, ts.teacher_id, ts.day_of_week, ts.start_time, ts.status, ts.occupied_by_department_id,
                           ts.created_at, ts.updated_at,
                           t.full_name AS teacher_name, t.color AS teacher_color
                    FROM teacher_slots ts
                    JOIN teachers t ON t.id = ts.teacher_id
                    WHERE ts.id=%s
                    """,
                    (slot_id,),
                )
            if not row:
                abort(404)
            if u.role == "TEACHER" and u.teacher_id != row["teacher_id"]:
                abort(404)
        if row.get("start_time"):
            row["start_time"] = str(row["start_time"])[:5]
        return _ok(row)

    @app.patch(f"{API_BASE}/slots/<int:slot_id>")
    @require_auth
    def slots_update(slot_id: int) -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        fields: list[str] = []
        params: list[Any] = []

        if "day_of_week" in body:
            fields.append("day_of_week=%s")
            params.append(_parse_int("day_of_week", body.get("day_of_week"), min_v=1, max_v=7))
        if "start_time" in body:
            start_time_s = str(body.get("start_time")).strip()
            if len(start_time_s.split(":")) < 2:
                abort(400, description="start_time must be HH:MM or HH:MM:SS")
            fields.append("start_time=%s")
            params.append(start_time_s)
        if "status" in body:
            status = str(body.get("status")).strip().lower()
            if status not in ("free", "occupied"):
                abort(400, description="status must be free or occupied")
            fields.append("status=%s")
            params.append(status)
            if status == "free":
                fields.append("occupied_by_department_id=NULL")
        if "occupied_by_department_id" in body:
            if u.role == "TEACHER":
                abort(400, description="TEACHER cannot set occupied_by_department_id")
            already_null_from_status = "status" in body and str(body.get("status")).strip().lower() == "free"
            if not already_null_from_status:
                val = body.get("occupied_by_department_id")
                if val is None or val == "":
                    fields.append("occupied_by_department_id=NULL")
                else:
                    dep_id = int(val)
                    dep_ids = _owner_department_ids(u.owner_id or 0)
                    if dep_id not in dep_ids:
                        abort(403, description="Not your department")
                    fields.append("occupied_by_department_id=%s")
                    params.append(dep_id)

        if not fields:
            abort(400, description="No fields to update")

        with db_cursor() as (_, cur):
            existing = fetch_one(cur, "SELECT teacher_id FROM teacher_slots WHERE id=%s", (slot_id,))
            if not existing:
                abort(404)
            if u.role == "TEACHER" and u.teacher_id != existing["teacher_id"]:
                abort(404)
            cur.execute(f"UPDATE teacher_slots SET {', '.join(fields)} WHERE id=%s", tuple(params + [slot_id]))
            if u.role == "OWNER" and u.owner_id:
                row = fetch_one(
                    cur,
                    """
                    SELECT ts.id, ts.teacher_id, ts.day_of_week, ts.start_time, ts.status, ts.occupied_by_department_id,
                           ts.created_at, ts.updated_at,
                           t.full_name AS teacher_name, t.color AS teacher_color,
                           (SELECT d.name FROM departments d
                            INNER JOIN department_owners do ON do.department_id = d.id AND do.owner_id = %s
                            WHERE d.id = ts.occupied_by_department_id LIMIT 1) AS occupied_by_department_name
                    FROM teacher_slots ts
                    JOIN teachers t ON t.id = ts.teacher_id
                    WHERE ts.id=%s
                    """,
                    (u.owner_id, slot_id),
                )
            else:
                row = fetch_one(
                    cur,
                    """
                    SELECT ts.id, ts.teacher_id, ts.day_of_week, ts.start_time, ts.status, ts.occupied_by_department_id,
                           ts.created_at, ts.updated_at,
                           t.full_name AS teacher_name, t.color AS teacher_color
                    FROM teacher_slots ts
                    JOIN teachers t ON t.id = ts.teacher_id
                    WHERE ts.id=%s
                    """,
                    (slot_id,),
                )
        if row and row.get("start_time"):
            row["start_time"] = str(row["start_time"])[:5]
        return _ok(row)

    @app.delete(f"{API_BASE}/slots/<int:slot_id>")
    @require_auth
    def slots_delete(slot_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            existing = fetch_one(cur, "SELECT teacher_id FROM teacher_slots WHERE id=%s", (slot_id,))
            if not existing:
                abort(404)
            if u.role == "TEACHER" and u.teacher_id != existing["teacher_id"]:
                abort(404)
            cur.execute("DELETE FROM teacher_slots WHERE id=%s", (slot_id,))
        return _ok({"deleted": True})

    # ------------------------------------------------------------
    # CRM + Telegram (доступ: OWNER с crm_access=1)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/crm/branches")
    @require_auth
    @require_crm_access
    def crm_branches_list() -> Response:
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                """
                SELECT cb.branch_id, cb.created_at AS crm_added_at,
                       b.name, b.address, b.metro, b.department_id, b.is_active
                FROM crm_branches cb
                JOIN branches b ON b.id = cb.branch_id
                ORDER BY b.name
                """,
            )
            for r in rows:
                r["crm_added_at"] = r["crm_added_at"].isoformat() if r.get("crm_added_at") else None
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/crm/branches")
    @require_auth
    @require_crm_access
    def crm_branches_add() -> Response:
        body = request.get_json(silent=True) or {}
        branch_id = body.get("branch_id")
        if branch_id is None:
            abort(400, description="branch_id is required")
        branch_id = int(branch_id)
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT id FROM branches WHERE id=%s", (branch_id,))
            if not ok:
                abort(404, description="Branch not found")
            try:
                exec_one(cur, "INSERT INTO crm_branches (branch_id) VALUES (%s)", (branch_id,))
            except MySQLError as e:
                if "Duplicate" in str(e):
                    abort(400, description="Branch already in CRM")
                raise
            row = fetch_one(cur, "SELECT branch_id, created_at FROM crm_branches WHERE branch_id=%s", (branch_id,))
        row["created_at"] = row["created_at"].isoformat() if row.get("created_at") else None
        return _ok(row)

    @app.delete(f"{API_BASE}/crm/branches/<int:branch_id>")
    @require_auth
    @require_crm_access
    def crm_branches_remove(branch_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM crm_branches WHERE branch_id=%s", (branch_id,))
            if cur.rowcount == 0:
                abort(404)
        return _ok({"deleted": True})

    def _crm_chats_enrich_with_last_and_unread(cur: Any, rows: list[dict], user_id: int) -> None:
        if not rows:
            return
        chat_ids = [int(r["id"]) for r in rows]
        placeholders = ",".join(["%s"] * len(chat_ids))
        last_msgs = fetch_all(
            cur,
            f"""
            SELECT m.crm_chat_id, m.id AS last_id, LEFT(m.content, 80) AS last_preview, m.created_at AS last_at, m.direction AS last_direction, m.sent_by_user_id AS last_sent_by
            FROM crm_messages m
            INNER JOIN (SELECT crm_chat_id, MAX(id) AS mid FROM crm_messages GROUP BY crm_chat_id) t
              ON m.crm_chat_id = t.crm_chat_id AND m.id = t.mid
            WHERE m.crm_chat_id IN ({placeholders})
            """,
            tuple(chat_ids),
        )
        last_by_chat = {int(x["crm_chat_id"]): x for x in last_msgs}
        read_state = fetch_all(
            cur,
            f"SELECT crm_chat_id, last_read_message_id FROM crm_chat_read_state WHERE user_id=%s AND crm_chat_id IN ({placeholders})",
            (user_id, *chat_ids),
        )
        read_by_chat = {int(x["crm_chat_id"]): (x["last_read_message_id"] or 0) for x in read_state}
        unread_rows = fetch_all(
            cur,
            f"""
            SELECT m.crm_chat_id,
                   SUM(CASE WHEN m.direction='in' THEN 1 ELSE 0 END) AS unread_from_client,
                   SUM(CASE WHEN m.direction='out' AND (m.sent_by_user_id IS NULL OR m.sent_by_user_id != %s) THEN 1 ELSE 0 END) AS unread_from_team
            FROM crm_messages m
            LEFT JOIN crm_chat_read_state r ON r.crm_chat_id = m.crm_chat_id AND r.user_id = %s
            WHERE m.crm_chat_id IN ({placeholders}) AND m.id > COALESCE(r.last_read_message_id, 0)
            GROUP BY m.crm_chat_id
            """,
            (user_id, user_id, *chat_ids),
        )
        unread_by_chat = {int(x["crm_chat_id"]): (int(x["unread_from_client"] or 0), int(x["unread_from_team"] or 0)) for x in unread_rows}
        for r in rows:
            cid = int(r["id"])
            lm = last_by_chat.get(cid)
            if lm:
                r["last_message"] = {
                    "id": lm["last_id"],
                    "content_preview": (lm["last_preview"] or "")[:80],
                    "created_at": lm["last_at"].isoformat() if lm.get("last_at") else None,
                    "direction": lm["last_direction"],
                    "sent_by_user_id": lm.get("last_sent_by"),
                }
            else:
                r["last_message"] = None
            u = unread_by_chat.get(cid, (0, 0))
            r["unread_from_client"] = u[0]
            r["unread_from_team"] = u[1]

    @app.get(f"{API_BASE}/crm/branches/<int:branch_id>/chats")
    @require_auth
    @require_crm_access
    def crm_branch_chats(branch_id: int) -> Response:
        u = _current_user()
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT 1 FROM crm_branches WHERE branch_id=%s", (branch_id,))
            if not ok:
                abort(404)
            rows = fetch_all(
                cur,
                "SELECT id, branch_id, telegram_chat_id, display_name, created_at, updated_at FROM crm_chats WHERE branch_id=%s ORDER BY id",
                (branch_id,),
            )
            for r in rows:
                for k in ("created_at", "updated_at"):
                    if r.get(k):
                        r[k] = r[k].isoformat()
            _crm_chats_enrich_with_last_and_unread(cur, rows, u.id)
        return _ok({"items": rows})

    @app.get(f"{API_BASE}/crm/chats")
    @require_auth
    @require_crm_access
    def crm_chats_list() -> Response:
        u = _current_user()
        args = dict(request.args)
        branch_id = args.get("branch_id")
        with db_cursor() as (_, cur):
            where = "1=1"
            params: list[Any] = []
            if branch_id is not None:
                where += " AND cc.branch_id=%s"
                params.append(int(branch_id))
            rows = fetch_all(
                cur,
                f"""
                SELECT cc.id, cc.branch_id, cc.telegram_chat_id, cc.display_name, cc.created_at, cc.updated_at,
                       b.name AS branch_name, b.address AS branch_address
                FROM crm_chats cc
                JOIN branches b ON b.id = cc.branch_id
                JOIN crm_branches cb ON cb.branch_id = cc.branch_id
                WHERE {where}
                ORDER BY b.name, cc.id
                """,
                tuple(params),
            )
            for r in rows:
                for k in ("created_at", "updated_at"):
                    if r.get(k):
                        r[k] = r[k].isoformat()
            _crm_chats_enrich_with_last_and_unread(cur, rows, u.id)
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/crm/chats")
    @require_auth
    @require_crm_access
    def crm_chats_create() -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        branch_id = body.get("branch_id")
        telegram_chat_id = body.get("telegram_chat_id")
        display_name = (body.get("display_name") or "").strip() or None
        if branch_id is None or telegram_chat_id is None:
            abort(400, description="branch_id and telegram_chat_id are required")
        branch_id = int(branch_id)
        try:
            telegram_chat_id = int(telegram_chat_id)
        except (TypeError, ValueError):
            abort(400, description="telegram_chat_id must be integer")
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT 1 FROM crm_branches WHERE branch_id=%s", (branch_id,))
            if not ok:
                abort(400, description="Branch not in CRM")
            branch_row = fetch_one(cur, "SELECT name, address FROM branches WHERE id=%s", (branch_id,))
            try:
                cid = exec_one(
                    cur,
                    "INSERT INTO crm_chats (branch_id, telegram_chat_id, display_name) VALUES (%s,%s,%s)",
                    (branch_id, telegram_chat_id, display_name),
                )
            except MySQLError as e:
                if "Duplicate" in str(e):
                    abort(400, description="This chat_id already linked to this branch")
                raise
            row = fetch_one(
                cur,
                "SELECT id, branch_id, telegram_chat_id, display_name, created_at, updated_at FROM crm_chats WHERE id=%s",
                (cid,),
            )
        for k in ("created_at", "updated_at"):
            if row.get(k):
                row[k] = row[k].isoformat()
        token = _get_telegram_token_from_settings()
        if token and branch_row:
            msg = f"Вы зарегистрированы. Филиал: {branch_row['name']}. Адрес: {branch_row['address'] or '—'}."
            telegram_send_message(token, telegram_chat_id, msg)
        return _ok(row)

    @app.post(f"{API_BASE}/crm/chats/<int:chat_id>/read")
    @require_auth
    @require_crm_access
    def crm_chats_read(chat_id: int) -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        last_message_id = body.get("last_message_id")
        if last_message_id is None:
            abort(400, description="last_message_id is required")
        last_message_id = int(last_message_id)
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT id FROM crm_chats WHERE id=%s", (chat_id,))
            if not ok:
                abort(404)
            cur.execute(
                """
                INSERT INTO crm_chat_read_state (user_id, crm_chat_id, last_read_message_id)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE last_read_message_id = GREATEST(COALESCE(last_read_message_id, 0), %s)
                """,
                (u.id, chat_id, last_message_id, last_message_id),
            )
        return _ok({"ok": True})

    @app.get(f"{API_BASE}/crm/chats/<int:chat_id>")
    @require_auth
    @require_crm_access
    def crm_chats_get(chat_id: int) -> Response:
        with db_cursor() as (_, cur):
            row = fetch_one(
                cur,
                """
                SELECT cc.id, cc.branch_id, cc.telegram_chat_id, cc.display_name, cc.created_at, cc.updated_at,
                       b.name AS branch_name, b.address AS branch_address
                FROM crm_chats cc
                JOIN branches b ON b.id = cc.branch_id
                WHERE cc.id=%s
                """,
                (chat_id,),
            )
            if not row:
                abort(404)
            for k in ("created_at", "updated_at"):
                if row.get(k):
                    row[k] = row[k].isoformat()
        return _ok(row)

    @app.patch(f"{API_BASE}/crm/chats/<int:chat_id>")
    @require_auth
    @require_crm_access
    def crm_chats_update(chat_id: int) -> Response:
        body = request.get_json(silent=True) or {}
        display_name = (body.get("display_name") or "").strip() if body.get("display_name") is not None else None
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT id FROM crm_chats WHERE id=%s", (chat_id,))
            if not ok:
                abort(404)
            if display_name is not None:
                cur.execute("UPDATE crm_chats SET display_name=%s WHERE id=%s", (display_name or None, chat_id))
            row = fetch_one(
                cur,
                "SELECT id, branch_id, telegram_chat_id, display_name, created_at, updated_at FROM crm_chats WHERE id=%s",
                (chat_id,),
            )
        for k in ("created_at", "updated_at"):
            if row.get(k):
                row[k] = row[k].isoformat()
        return _ok(row)

    @app.delete(f"{API_BASE}/crm/chats/<int:chat_id>")
    @require_auth
    @require_crm_access
    def crm_chats_delete(chat_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM crm_chats WHERE id=%s", (chat_id,))
            if cur.rowcount == 0:
                abort(404)
        return _ok({"deleted": True})

    @app.get(f"{API_BASE}/crm/chats/<int:chat_id>/messages")
    @require_auth
    @require_crm_access
    def crm_chats_messages_list(chat_id: int) -> Response:
        u = _current_user()
        args = dict(request.args)
        limit, offset = _paginate(args, default_limit=100, max_limit=500)
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT id FROM crm_chats WHERE id=%s", (chat_id,))
            if not ok:
                abort(404)
            rows = fetch_all(
                cur,
                """
                SELECT m.id, m.crm_chat_id, m.direction, m.content, m.telegram_message_id, m.sent_by_user_id,
                       m.created_at, m.updated_at,
                       u.login AS sent_by_login
                FROM crm_messages m
                LEFT JOIN auf_users u ON u.id = m.sent_by_user_id
                WHERE m.crm_chat_id=%s
                ORDER BY m.id DESC
                LIMIT %s OFFSET %s
                """,
                (chat_id, limit, offset),
            )
            last_read = fetch_one(cur, "SELECT last_read_message_id FROM crm_chat_read_state WHERE user_id=%s AND crm_chat_id=%s", (u.id, chat_id))
            last_read_id = int(last_read["last_read_message_id"]) if last_read and last_read.get("last_read_message_id") else 0
            for r in rows:
                for k in ("created_at", "updated_at"):
                    if r.get(k):
                        r[k] = r[k].isoformat()
                r["read_by_me"] = int(r["id"]) <= last_read_id
        return _ok({"items": rows, "last_read_message_id": last_read_id})

    @app.post(f"{API_BASE}/crm/chats/<int:chat_id>/messages")
    @require_auth
    @require_crm_access
    def crm_chats_messages_send(chat_id: int) -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        content = (body.get("content") or "").strip()
        if not content:
            abort(400, description="content is required")
        with db_cursor() as (_, cur):
            chat = fetch_one(cur, "SELECT id, telegram_chat_id FROM crm_chats WHERE id=%s", (chat_id,))
            if not chat:
                abort(404)
            token = _get_telegram_token_from_settings()
            if not token:
                abort(503, description="Telegram bot token not configured")
            sent = telegram_send_message(token, int(chat["telegram_chat_id"]), content)
            mid = exec_one(
                cur,
                "INSERT INTO crm_messages (crm_chat_id, direction, content, telegram_message_id, sent_by_user_id) VALUES (%s,'out',%s,NULL,%s)",
                (chat_id, content, u.id),
            )
            row = fetch_one(
                cur,
                """
                SELECT m.id, m.crm_chat_id, m.direction, m.content, m.telegram_message_id, m.sent_by_user_id, m.created_at, m.updated_at
                FROM crm_messages m WHERE m.id=%s
                """,
                (mid,),
            )
        for k in ("created_at", "updated_at"):
            if row.get(k):
                row[k] = row[k].isoformat()
        row["sent_by_login"] = u.login
        return _ok(row)

    @app.get(f"{API_BASE}/crm/chats/<int:chat_id>/comments")
    @require_auth
    @require_crm_access
    def crm_chats_comments_list(chat_id: int) -> Response:
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT id FROM crm_chats WHERE id=%s", (chat_id,))
            if not ok:
                abort(404)
            rows = fetch_all(
                cur,
                """
                SELECT c.id, c.crm_chat_id, c.user_id, c.comment_text, c.created_at,
                       u.login AS user_login
                FROM crm_chat_comments c
                JOIN auf_users u ON u.id = c.user_id
                WHERE c.crm_chat_id=%s
                ORDER BY c.id
                """,
                (chat_id,),
            )
            for r in rows:
                if r.get("created_at"):
                    r["created_at"] = r["created_at"].isoformat()
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/crm/chats/<int:chat_id>/comments")
    @require_auth
    @require_crm_access
    def crm_chats_comments_create(chat_id: int) -> Response:
        u = _current_user()
        body = request.get_json(silent=True) or {}
        comment_text = (body.get("comment_text") or "").strip()
        if not comment_text:
            abort(400, description="comment_text is required")
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT id FROM crm_chats WHERE id=%s", (chat_id,))
            if not ok:
                abort(404)
            cid = exec_one(
                cur,
                "INSERT INTO crm_chat_comments (crm_chat_id, user_id, comment_text) VALUES (%s,%s,%s)",
                (chat_id, u.id, comment_text),
            )
            row = fetch_one(cur, "SELECT id, crm_chat_id, user_id, comment_text, created_at FROM crm_chat_comments WHERE id=%s", (cid,))
            if row.get("created_at"):
                row["created_at"] = row["created_at"].isoformat()
            row["user_login"] = u.login
        return _ok(row)

    @app.get(f"{API_BASE}/crm/notification-subscribers")
    @require_auth
    @require_crm_access
    def crm_notification_subscribers_list() -> Response:
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, "SELECT id, telegram_chat_id, label, created_at FROM crm_notification_subscribers ORDER BY id")
            for r in rows:
                if r.get("created_at"):
                    r["created_at"] = r["created_at"].isoformat()
        return _ok({"items": rows})

    @app.post(f"{API_BASE}/crm/notification-subscribers")
    @require_auth
    @require_crm_access
    def crm_notification_subscribers_add() -> Response:
        body = request.get_json(silent=True) or {}
        telegram_chat_id = body.get("telegram_chat_id")
        label = (body.get("label") or "").strip() or None
        if telegram_chat_id is None:
            abort(400, description="telegram_chat_id is required")
        try:
            telegram_chat_id = int(telegram_chat_id)
        except (TypeError, ValueError):
            abort(400, description="telegram_chat_id must be integer")
        with db_cursor() as (_, cur):
            try:
                nid = exec_one(
                    cur,
                    "INSERT INTO crm_notification_subscribers (telegram_chat_id, label) VALUES (%s,%s)",
                    (telegram_chat_id, label),
                )
            except MySQLError as e:
                if "Duplicate" in str(e):
                    abort(400, description="This chat_id already subscribed")
                raise
            row = fetch_one(cur, "SELECT id, telegram_chat_id, label, created_at FROM crm_notification_subscribers WHERE id=%s", (nid,))
            if row.get("created_at"):
                row["created_at"] = row["created_at"].isoformat()
        return _ok(row)

    @app.delete(f"{API_BASE}/crm/notification-subscribers/<int:sub_id>")
    @require_auth
    @require_crm_access
    def crm_notification_subscribers_remove(sub_id: int) -> Response:
        with db_cursor() as (_, cur):
            cur.execute("DELETE FROM crm_notification_subscribers WHERE id=%s", (sub_id,))
            if cur.rowcount == 0:
                abort(404)
        return _ok({"deleted": True})

    @app.get(f"{API_BASE}/crm/settings")
    @require_auth
    @require_crm_access
    def crm_settings_get() -> Response:
        with db_cursor() as (_, cur):
            prod = fetch_one(cur, "SELECT value_text FROM settings WHERE `key`=%s", ("telegram_bot_token",))
            dev = fetch_one(cur, "SELECT value_text FROM settings WHERE `key`=%s", ("telegram_bot_token_dev",))
        return _ok({
            "telegram_bot_configured": bool(prod and prod.get("value_text")),
            "telegram_bot_dev_configured": bool(dev and dev.get("value_text")),
        })

    @app.put(f"{API_BASE}/crm/settings")
    @require_auth
    @require_crm_access
    def crm_settings_put() -> Response:
        body = request.get_json(silent=True) or {}
        token_prod = (body.get("telegram_bot_token") or "").strip() or None
        token_dev = (body.get("telegram_bot_token_dev") or "").strip() or None
        with db_cursor() as (_, cur):
            if "telegram_bot_token" in body:
                cur.execute(
                    "INSERT INTO settings (`key`, value_int, value_decimal, value_bool, value_text, description) VALUES (%s,NULL,NULL,NULL,%s,%s) ON DUPLICATE KEY UPDATE value_text=VALUES(value_text), description=VALUES(description)",
                    ("telegram_bot_token", token_prod, "Токен Telegram-бота для CRM (PROD)"),
                )
            if "telegram_bot_token_dev" in body:
                cur.execute(
                    "INSERT INTO settings (`key`, value_int, value_decimal, value_bool, value_text, description) VALUES (%s,NULL,NULL,NULL,%s,%s) ON DUPLICATE KEY UPDATE value_text=VALUES(value_text), description=VALUES(description)",
                    ("telegram_bot_token_dev", token_dev, "Токен Telegram-бота для CRM (DEV)"),
                )
        with db_cursor() as (_, cur):
            prod = fetch_one(cur, "SELECT value_text FROM settings WHERE `key`=%s", ("telegram_bot_token",))
            dev = fetch_one(cur, "SELECT value_text FROM settings WHERE `key`=%s", ("telegram_bot_token_dev",))
        return _ok({
            "telegram_bot_configured": bool(prod and prod.get("value_text")),
            "telegram_bot_dev_configured": bool(dev and dev.get("value_text")),
        })

    # ------------------------------------------------------------
    # Minimal OpenAPI stub (для дальнейшей документации)
    # ------------------------------------------------------------
    @app.get(f"{API_BASE}/openapi.json")
    def openapi_json() -> Response:
        paths: dict[str, Any] = {}
        for rule in app.url_map.iter_rules():
            if not str(rule.rule).startswith(API_BASE):
                continue
            methods = sorted([m for m in (rule.methods or []) if m not in {"HEAD", "OPTIONS"}])
            item: dict[str, Any] = paths.get(str(rule.rule), {})
            for m in methods:
                item[m.lower()] = {"summary": rule.endpoint}
            paths[str(rule.rule)] = item
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "RoboMan API", "version": "0.1"},
            "paths": paths,
        }
        return _jsonify(spec)

    return app


app = create_app()

_telegram_bot_thread: threading.Thread | None = None


def start_telegram_bot_thread() -> None:
    global _telegram_bot_thread
    if _telegram_bot_thread is not None and _telegram_bot_thread.is_alive():
        return
    _telegram_bot_thread = threading.Thread(target=_telegram_bot_poll_loop, daemon=True)
    _telegram_bot_thread.start()


# Запуск бота в фоне (один поток на процесс; при gunicorn с несколькими воркерами лучше бота вынести в отдельный процесс)
start_telegram_bot_thread()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "80"))
    debug = _parse_bool(os.environ.get("FLASK_DEBUG"))
    app.run(host="0.0.0.0", port=port, debug=debug)

