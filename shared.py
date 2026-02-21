"""
Общие хелперы для main и blueprints: БД, auth, ответы API.
Импортируется и main, и blueprints — без циклических зависимостей.
"""
from __future__ import annotations

import base64
import json
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from functools import wraps
from typing import Any, Callable, Iterator, Literal, TypeVar

from flask import Response, abort, g, request

# Импорт конфига и mysql — shared не должен импортировать main
from mysql.connector import pooling  # type: ignore

# Конфиг БД (можно переопределить через env)
import os
DB_HOST = os.environ.get("DB_HOST", "147.45.138.77")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "itmasters")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "itmasters")
DB_NAME = os.environ.get("DB_NAME", "roboman")
DB_POOL_SIZE = int(os.environ.get("DB_POOL_SIZE", "10"))

_POOL: pooling.MySQLConnectionPool | None = None


def get_pool() -> pooling.MySQLConnectionPool:
    global _POOL
    if _POOL is None:
        _POOL = pooling.MySQLConnectionPool(
            pool_name="roboman_pool",
            pool_size=int(DB_POOL_SIZE),
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD or "",
            database=DB_NAME,
            port=int(DB_PORT),
            autocommit=False,
            pool_reset_session=True,
        )
    return _POOL


@contextmanager
def db_cursor(*, dictionary: bool = True) -> Iterator[tuple[Any, Any]]:
    pool = get_pool()
    conn = pool.get_connection()
    try:
        if not conn.is_connected():
            conn.reconnect(attempts=2, delay=0)
    except Exception:
        conn.reconnect(attempts=2, delay=0)
    cur = conn.cursor(dictionary=dictionary, buffered=True)
    try:
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            cur.close()
        finally:
            conn.close()


def fetch_one(cur: Any, sql: str, params: tuple[Any, ...] = ()) -> Any | None:
    cur.execute(sql, params)
    return cur.fetchone()


def fetch_all(cur: Any, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
    cur.execute(sql, params)
    return list(cur.fetchall())


def exec_one(cur: Any, sql: str, params: tuple[Any, ...] = ()) -> int:
    cur.execute(sql, params)
    return int(getattr(cur, "lastrowid", 0) or 0)


# --- Auth ---
Role = Literal["OWNER", "TEACHER"]


@dataclass(frozen=True)
class CurrentUser:
    id: int
    role: Role
    owner_id: int | None
    teacher_id: int | None
    login: str


def _extract_token() -> str | None:
    auth = request.headers.get("Authorization", "").strip()
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def get_current_user() -> CurrentUser:
    tok = _extract_token()
    if not tok:
        abort(401, description="Missing Authorization Bearer token")
    try:
        user_id = int(tok)
    except ValueError:
        abort(401, description="Invalid token format")
    with db_cursor() as (_, cur):
        row = fetch_one(
            cur,
            "SELECT id, login, role, owner_id, teacher_id, is_active FROM auf_users WHERE id=%s",
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


# --- API responses ---
def _to_jsonable(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray)):
        return base64.b64encode(bytes(v)).decode("ascii")
    return str(v)


def _jsonify(data: Any, status: int = 200) -> Response:
    return Response(
        json.dumps(data, ensure_ascii=False, default=_to_jsonable),
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
