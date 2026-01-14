from __future__ import annotations

from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Literal, TypeVar

from flask import Request, abort, g, request

from backend.db import db_cursor, fetch_one

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


def owner_scoped_department_ids(owner_id: int) -> list[int]:
    with db_cursor() as (_, cur):
        cur.execute("SELECT department_id FROM department_owners WHERE owner_id=%s", (owner_id,))
        out = [int(r["department_id"]) for r in cur.fetchall()]
    return out

