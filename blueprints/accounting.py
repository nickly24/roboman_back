"""
Blueprint: Бухгалтерия — денежные листы, поступления, зарплаты, расходы, переводы.
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from flask import Blueprint, Response, abort, g, request

from shared import (
    db_cursor,
    exec_one,
    fetch_all,
    fetch_one,
    get_current_user,
    require_auth,
    require_role,
    _err,
    _ok,
)


def _owner_department_ids(owner_id: int) -> list[int]:
    with db_cursor() as (_, cur):
        rows = fetch_all(cur, "SELECT department_id FROM department_owners WHERE owner_id=%s", (owner_id,))
    return [int(r["department_id"]) for r in rows]


def _to_float(v: Any) -> float:
    if v is None:
        return 0.0
    if isinstance(v, Decimal):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _sheet_access(owner_id: int, department_id: int) -> bool:
    return department_id in _owner_department_ids(owner_id)


bp = Blueprint("accounting", __name__)


# ---------------------------------------------------------------------------
# Листы
# ---------------------------------------------------------------------------

@bp.get("/sheets")
@require_auth
@require_role("OWNER")
def sheets_list() -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")
    dep_ids = _owner_department_ids(u.owner_id)
    if not dep_ids:
        return _ok({"items": []})

    year = request.args.get("year")
    month = request.args.get("month")
    department_id = request.args.get("department_id")

    where: list[str] = ["s.department_id IN (" + ",".join(["%s"] * len(dep_ids)) + ")"]
    params: list[Any] = list(dep_ids)
    if year:
        where.append("s.year=%s")
        params.append(int(year))
    if month:
        where.append("s.month=%s")
        params.append(int(month))
    if department_id:
        did = int(department_id)
        if did not in dep_ids:
            abort(403, description="Access denied to this department")
        where.append("s.department_id=%s")
        params.append(did)

    with db_cursor() as (_, cur):
        rows = fetch_all(
            cur,
            """
            SELECT s.id, s.department_id, s.year, s.month, s.created_at, s.created_by_user_id,
                   d.name AS department_name
            FROM accounting_sheets s
            JOIN departments d ON d.id = s.department_id
            WHERE """ + " AND ".join(where) + """
            ORDER BY s.year DESC, s.month DESC, d.name
            LIMIT 200
            """,
            tuple(params),
        )
    return _ok({"items": rows or []})


@bp.post("/sheets")
@require_auth
@require_role("OWNER")
def sheets_create() -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")
    body = request.get_json(silent=True) or {}
    year = body.get("year")
    month = body.get("month")
    department_id = body.get("department_id")
    if year is None or month is None or department_id is None:
        abort(400, description="year, month, department_id are required")
    year_i = int(year)
    month_i = int(month)
    dep_id = int(department_id)
    if not _sheet_access(u.owner_id, dep_id):
        abort(403, description="Access denied to this department")
    if not (1 <= month_i <= 12):
        abort(400, description="month must be 1–12")
    if not (2020 <= year_i <= 2100):
        abort(400, description="year out of range")

    with db_cursor() as (_, cur):
        existing = fetch_one(cur, "SELECT id FROM accounting_sheets WHERE department_id=%s AND year=%s AND month=%s", (dep_id, year_i, month_i))
        if existing:
            return _err("Sheet for this department and period already exists", status=409)

        sheet_id = exec_one(
            cur,
            "INSERT INTO accounting_sheets (department_id, year, month, created_by_user_id) VALUES (%s,%s,%s,%s)",
            (dep_id, year_i, month_i, u.id),
        )
        row = fetch_one(cur, "SELECT s.*, d.name AS department_name FROM accounting_sheets s JOIN departments d ON d.id=s.department_id WHERE s.id=%s", (sheet_id,))
    return _ok(row)


@bp.get("/sheets/<int:sheet_id>")
@require_auth
@require_role("OWNER")
def sheets_get(sheet_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        sheet = fetch_one(cur, "SELECT s.*, d.name AS department_name FROM accounting_sheets s JOIN departments d ON d.id=s.department_id WHERE s.id=%s", (sheet_id,))
        if not sheet:
            abort(404, description="Sheet not found")
        if not _sheet_access(u.owner_id, int(sheet["department_id"])):
            abort(403, description="Access denied")

        # Владельцы и преподаватели отдела
        dep_id = int(sheet["department_id"])
        owners = fetch_all(cur, "SELECT o.id, o.full_name FROM owners o JOIN department_owners do ON do.owner_id=o.id WHERE do.department_id=%s ORDER BY o.full_name", (dep_id,))
        teachers = fetch_all(
            cur,
            """
            SELECT DISTINCT t.id, t.full_name
            FROM teachers t
            JOIN branch_teachers bt ON bt.teacher_id = t.id
            JOIN branches b ON b.id = bt.branch_id
            WHERE b.department_id = %s
            ORDER BY t.full_name
            """,
            (dep_id,),
        )
        branches = fetch_all(cur, "SELECT id, name FROM branches WHERE department_id=%s AND is_active=1 ORDER BY name", (dep_id,))

        # Записи
        incomes = fetch_all(cur, "SELECT i.*, b.name AS branch_name, o.full_name AS owner_name FROM accounting_incomes i JOIN branches b ON b.id=i.branch_id JOIN owners o ON o.id=i.owner_id WHERE i.sheet_id=%s ORDER BY i.id", (sheet_id,))
        salaries = fetch_all(cur, "SELECT s.*, o.full_name AS owner_name, t.full_name AS teacher_name FROM accounting_salaries s JOIN owners o ON o.id=s.owner_id JOIN teachers t ON t.id=s.teacher_id WHERE s.sheet_id=%s ORDER BY s.id", (sheet_id,))
        expenses = fetch_all(cur, "SELECT e.*, o.full_name AS owner_name FROM accounting_expenses e JOIN owners o ON o.id=e.owner_id WHERE e.sheet_id=%s ORDER BY e.id", (sheet_id,))
        transfers = fetch_all(
            cur,
            "SELECT t.*, o1.full_name AS from_owner_name, o2.full_name AS to_owner_name FROM accounting_transfers t JOIN owners o1 ON o1.id=t.from_owner_id JOIN owners o2 ON o2.id=t.to_owner_id WHERE t.sheet_id=%s ORDER BY t.id",
            (sheet_id,),
        )

    # Сводка
    summary = _compute_summary(incomes or [], salaries or [], expenses or [], transfers or [], owners or [])

    return _ok({
        "sheet": sheet,
        "owners": owners or [],
        "teachers": teachers or [],
        "branches": branches or [],
        "incomes": incomes or [],
        "salaries": salaries or [],
        "expenses": expenses or [],
        "transfers": transfers or [],
        "summary": summary,
    })


def _income_referral_amount(i: dict) -> float:
    """Сумма рефералки в рублях для поступления."""
    amt = _to_float(i["amount"])
    rp = _to_float(i.get("referral_percent"))
    if not rp or rp <= 0:
        return 0.0
    if i.get("referral_from_net"):
        return (amt - _to_float(i["tax_amount"])) * (rp / 100)
    return amt * (rp / 100)


def _income_net_amount(i: dict) -> float:
    """Чистая сумма поступления после вычета налога и рефералки."""
    amt = _to_float(i["amount"])
    tax = _to_float(i["tax_amount"])
    ref = _income_referral_amount(i)
    return amt - tax - ref


def _compute_summary(
    incomes: list[dict],
    salaries: list[dict],
    expenses: list[dict],
    transfers: list[dict],
    owners: list[dict],
) -> dict[str, Any]:
    total_revenue = sum(_to_float(i["amount"]) for i in incomes)
    total_tax = sum(_to_float(i["tax_amount"]) for i in incomes)
    total_referral = sum(_income_referral_amount(i) for i in incomes)
    total_costs = total_tax + total_referral
    total_salaries = sum(_to_float(s["amount"]) for s in salaries)
    total_expenses_other = sum(_to_float(e["amount"]) for e in expenses)
    total_expenses = total_salaries + total_expenses_other
    profit = total_revenue - total_costs - total_expenses

    owner_balances: list[dict] = []
    for o in owners:
        oid = int(o["id"])
        owner_incomes = [i for i in incomes if int(i["owner_id"]) == oid]
        inc_gross = sum(_to_float(i["amount"]) for i in owner_incomes)
        inc_net = sum(_income_net_amount(i) for i in owner_incomes)
        sal = sum(_to_float(s["amount"]) for s in salaries if int(s["owner_id"]) == oid)
        exp = sum(_to_float(e["amount"]) for e in expenses if int(e["owner_id"]) == oid)
        out_tr = sum(_to_float(t["amount"]) for t in transfers if int(t["from_owner_id"]) == oid)
        in_tr = sum(_to_float(t["amount"]) for t in transfers if int(t["to_owner_id"]) == oid)
        balance = inc_net - sal - exp - out_tr + in_tr
        owner_balances.append({
            "owner_id": oid,
            "owner_name": o["full_name"],
            "income": inc_gross,
            "income_net": inc_net,
            "salary_paid": sal,
            "expenses_paid": exp,
            "transfers_out": out_tr,
            "transfers_in": in_tr,
            "balance": balance,
        })

    total_balance = sum(ob["balance"] for ob in owner_balances)
    balances_equal = len(set(ob["balance"] for ob in owner_balances)) <= 1 if owner_balances else True
    discrepancy = 0.0
    if owner_balances and not balances_equal:
        avg = total_balance / len(owner_balances)
        discrepancy = sum(abs(ob["balance"] - avg) for ob in owner_balances) / 2

    return {
        "revenue": total_revenue,
        "costs": total_costs,
        "costs_tax": total_tax,
        "costs_referral": total_referral,
        "expenses": total_expenses,
        "expenses_salaries": total_salaries,
        "expenses_other": total_expenses_other,
        "profit": profit,
        "owner_balances": owner_balances,
        "total_balance": total_balance,
        "discrepancy": discrepancy,
        "balances_equal": balances_equal,
    }


@bp.delete("/sheets/<int:sheet_id>")
@require_auth
@require_role("OWNER")
def sheets_delete(sheet_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        sheet = fetch_one(cur, "SELECT department_id FROM accounting_sheets WHERE id=%s", (sheet_id,))
        if not sheet:
            abort(404, description="Sheet not found")
        if not _sheet_access(u.owner_id, int(sheet["department_id"])):
            abort(403, description="Access denied")
        cur.execute("DELETE FROM accounting_sheets WHERE id=%s", (sheet_id,))

    return _ok({"deleted": sheet_id})


# ---------------------------------------------------------------------------
# Поступления
# ---------------------------------------------------------------------------

@bp.post("/sheets/<int:sheet_id>/incomes")
@require_auth
@require_role("OWNER")
def incomes_create(sheet_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        sheet = fetch_one(cur, "SELECT department_id FROM accounting_sheets WHERE id=%s", (sheet_id,))
        if not sheet:
            abort(404, description="Sheet not found")
        if not _sheet_access(u.owner_id, int(sheet["department_id"])):
            abort(403, description="Access denied")

    body = request.get_json(silent=True) or {}
    branch_id = body.get("branch_id")
    owner_id = body.get("owner_id")
    amount = body.get("amount")
    if branch_id is None or branch_id == "":
        abort(400, description="Выберите филиал")
    if owner_id is None or owner_id == "":
        abort(400, description="Выберите владельца")
    if amount is None or amount == "":
        abort(400, description="Укажите сумму")
    try:
        amt_val = float(amount)
    except (TypeError, ValueError):
        abort(400, description="Сумма должна быть числом")
    try:
        branch_id_int = int(branch_id)
        owner_id_int = int(owner_id)
    except (TypeError, ValueError):
        abort(400, description="Неверный формат филиала или владельца")

    with db_cursor() as (_, cur):
        branch = fetch_one(cur, "SELECT id, department_id FROM branches WHERE id=%s", (branch_id_int,))
        if not branch:
            abort(400, description="Филиал не найден")
        if int(branch["department_id"]) != int(sheet["department_id"]):
            abort(400, description="Филиал должен принадлежать отделу листа")
        owner = fetch_one(cur, "SELECT owner_id FROM department_owners WHERE owner_id=%s AND department_id=%s", (owner_id_int, int(sheet["department_id"])))
        if not owner:
            abort(400, description="Владелец должен принадлежать отделу листа")

        amt = amt_val
        ref_pct = float(body.get("referral_percent") or 0) if body.get("referral_percent") is not None else None
        ref_from_net = 1 if (body.get("referral_from_net") or False) else 0
        ref_comment = (body.get("referral_comment") or "").strip() or None
        tax = float(body.get("tax_amount") or 0)

        income_id = exec_one(
            cur,
            "INSERT INTO accounting_incomes (sheet_id, branch_id, owner_id, amount, referral_percent, referral_from_net, referral_comment, tax_amount, created_by_user_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (sheet_id, branch_id_int, owner_id_int, amt, ref_pct, ref_from_net, ref_comment, tax, u.id),
        )
        row = fetch_one(cur, "SELECT i.*, b.name AS branch_name, o.full_name AS owner_name FROM accounting_incomes i JOIN branches b ON b.id=i.branch_id JOIN owners o ON o.id=i.owner_id WHERE i.id=%s", (income_id,))
    return _ok(row)


@bp.put("/incomes/<int:income_id>")
@require_auth
@require_role("OWNER")
def incomes_update(income_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT i.*, s.department_id FROM accounting_incomes i JOIN accounting_sheets s ON s.id=i.sheet_id WHERE i.id=%s", (income_id,))
        if not row:
            abort(404, description="Income not found")
        if not _sheet_access(u.owner_id, int(row["department_id"])):
            abort(403, description="Access denied")

    body = request.get_json(silent=True) or {}
    updates: list[str] = []
    params: list[Any] = []
    for key, col in [("amount", "amount"), ("branch_id", "branch_id"), ("owner_id", "owner_id"), ("tax_amount", "tax_amount"), ("referral_percent", "referral_percent"), ("referral_from_net", "referral_from_net"), ("referral_comment", "referral_comment")]:
        if key in body:
            val = body[key]
            if key == "referral_from_net":
                val = 1 if val else 0
            elif key == "referral_comment":
                val = (val or "").strip() or None
            updates.append(f"{col}=%s")
            params.append(val)
    if not updates:
        with db_cursor() as (_, cur):
            r = fetch_one(cur, "SELECT i.*, b.name AS branch_name, o.full_name AS owner_name FROM accounting_incomes i JOIN branches b ON b.id=i.branch_id JOIN owners o ON o.id=i.owner_id WHERE i.id=%s", (income_id,))
        return _ok(r)

    params.append(income_id)
    with db_cursor() as (_, cur):
        cur.execute("UPDATE accounting_incomes SET " + ", ".join(updates) + " WHERE id=%s", tuple(params))
        r = fetch_one(cur, "SELECT i.*, b.name AS branch_name, o.full_name AS owner_name FROM accounting_incomes i JOIN branches b ON b.id=i.branch_id JOIN owners o ON o.id=i.owner_id WHERE i.id=%s", (income_id,))
    return _ok(r)


@bp.delete("/incomes/<int:income_id>")
@require_auth
@require_role("OWNER")
def incomes_delete(income_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT i.sheet_id, s.department_id FROM accounting_incomes i JOIN accounting_sheets s ON s.id=i.sheet_id WHERE i.id=%s", (income_id,))
        if not row:
            abort(404, description="Income not found")
        if not _sheet_access(u.owner_id, int(row["department_id"])):
            abort(403, description="Access denied")
        cur.execute("DELETE FROM accounting_incomes WHERE id=%s", (income_id,))
    return _ok({"deleted": income_id})


# ---------------------------------------------------------------------------
# Зарплаты
# ---------------------------------------------------------------------------

@bp.post("/sheets/<int:sheet_id>/salaries")
@require_auth
@require_role("OWNER")
def salaries_create(sheet_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        sheet = fetch_one(cur, "SELECT department_id FROM accounting_sheets WHERE id=%s", (sheet_id,))
        if not sheet:
            abort(404, description="Sheet not found")
        if not _sheet_access(u.owner_id, int(sheet["department_id"])):
            abort(403, description="Access denied")

    body = request.get_json(silent=True) or {}
    owner_id = body.get("owner_id")
    teacher_id = body.get("teacher_id")
    amount = body.get("amount")
    period_type = body.get("period_type", "full")
    if owner_id is None or owner_id == "":
        abort(400, description="Выберите владельца")
    if teacher_id is None or teacher_id == "":
        abort(400, description="Выберите преподавателя")
    if amount is None or amount == "":
        abort(400, description="Укажите сумму")
    try:
        amt_val = float(amount)
    except (TypeError, ValueError):
        abort(400, description="Сумма должна быть числом")
    if period_type not in ("1_15", "16_end", "full"):
        abort(400, description="Укажите период")

    with db_cursor() as (_, cur):
        owner = fetch_one(cur, "SELECT owner_id FROM department_owners WHERE owner_id=%s AND department_id=%s", (int(owner_id), int(sheet["department_id"])))
        if not owner:
            abort(400, description="Владелец должен принадлежать отделу листа")
        teacher = fetch_one(cur, "SELECT t.id FROM teachers t JOIN branch_teachers bt ON bt.teacher_id=t.id JOIN branches b ON b.id=bt.branch_id WHERE t.id=%s AND b.department_id=%s", (int(teacher_id), int(sheet["department_id"])))
        if not teacher:
            abort(400, description="Преподаватель должен быть привязан к филиалу отдела листа")

        amt = amt_val
        salary_id = exec_one(
            cur,
            "INSERT INTO accounting_salaries (sheet_id, owner_id, teacher_id, amount, period_type, created_by_user_id) VALUES (%s,%s,%s,%s,%s,%s)",
            (sheet_id, int(owner_id), int(teacher_id), amt, period_type, u.id),
        )
        row = fetch_one(cur, "SELECT s.*, o.full_name AS owner_name, t.full_name AS teacher_name FROM accounting_salaries s JOIN owners o ON o.id=s.owner_id JOIN teachers t ON t.id=s.teacher_id WHERE s.id=%s", (salary_id,))
    return _ok(row)


@bp.put("/salaries/<int:salary_id>")
@require_auth
@require_role("OWNER")
def salaries_update(salary_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT s.*, sh.department_id FROM accounting_salaries s JOIN accounting_sheets sh ON sh.id=s.sheet_id WHERE s.id=%s", (salary_id,))
        if not row:
            abort(404, description="Salary not found")
        if not _sheet_access(u.owner_id, int(row["department_id"])):
            abort(403, description="Access denied")

    body = request.get_json(silent=True) or {}
    updates: list[str] = []
    params: list[Any] = []
    for key, col in [("amount", "amount"), ("owner_id", "owner_id"), ("teacher_id", "teacher_id"), ("period_type", "period_type")]:
        if key in body:
            val = body[key]
            if key == "period_type" and val not in ("1_15", "16_end", "full"):
                abort(400, description="period_type must be 1_15, 16_end, or full")
            updates.append(f"{col}=%s")
            params.append(val)
    if not updates:
        with db_cursor() as (_, cur):
            r = fetch_one(cur, "SELECT s.*, o.full_name AS owner_name, t.full_name AS teacher_name FROM accounting_salaries s JOIN owners o ON o.id=s.owner_id JOIN teachers t ON t.id=s.teacher_id WHERE s.id=%s", (salary_id,))
        return _ok(r)

    params.append(salary_id)
    with db_cursor() as (_, cur):
        cur.execute("UPDATE accounting_salaries SET " + ", ".join(updates) + " WHERE id=%s", tuple(params))
        r = fetch_one(cur, "SELECT s.*, o.full_name AS owner_name, t.full_name AS teacher_name FROM accounting_salaries s JOIN owners o ON o.id=s.owner_id JOIN teachers t ON t.id=s.teacher_id WHERE s.id=%s", (salary_id,))
    return _ok(r)


@bp.delete("/salaries/<int:salary_id>")
@require_auth
@require_role("OWNER")
def salaries_delete(salary_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT s.sheet_id, sh.department_id FROM accounting_salaries s JOIN accounting_sheets sh ON sh.id=s.sheet_id WHERE s.id=%s", (salary_id,))
        if not row:
            abort(404, description="Salary not found")
        if not _sheet_access(u.owner_id, int(row["department_id"])):
            abort(403, description="Access denied")
        cur.execute("DELETE FROM accounting_salaries WHERE id=%s", (salary_id,))
    return _ok({"deleted": salary_id})


# ---------------------------------------------------------------------------
# Прочие расходы
# ---------------------------------------------------------------------------

@bp.post("/sheets/<int:sheet_id>/expenses")
@require_auth
@require_role("OWNER")
def expenses_create(sheet_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        sheet = fetch_one(cur, "SELECT department_id FROM accounting_sheets WHERE id=%s", (sheet_id,))
        if not sheet:
            abort(404, description="Sheet not found")
        if not _sheet_access(u.owner_id, int(sheet["department_id"])):
            abort(403, description="Access denied")

    body = request.get_json(silent=True) or {}
    owner_id = body.get("owner_id")
    name = (body.get("name") or "").strip()
    amount = body.get("amount")
    if owner_id is None or owner_id == "":
        abort(400, description="Выберите владельца")
    if not name:
        abort(400, description="Укажите название расхода")
    if amount is None or amount == "":
        abort(400, description="Укажите сумму")
    try:
        amt_val = float(amount)
    except (TypeError, ValueError):
        abort(400, description="Сумма должна быть числом")

    with db_cursor() as (_, cur):
        owner = fetch_one(cur, "SELECT owner_id FROM department_owners WHERE owner_id=%s AND department_id=%s", (int(owner_id), int(sheet["department_id"])))
        if not owner:
            abort(400, description="Владелец должен принадлежать отделу листа")

        amt = amt_val
        exp_id = exec_one(
            cur,
            "INSERT INTO accounting_expenses (sheet_id, owner_id, name, amount, created_by_user_id) VALUES (%s,%s,%s,%s,%s)",
            (sheet_id, int(owner_id), name, amt, u.id),
        )
        row = fetch_one(cur, "SELECT e.*, o.full_name AS owner_name FROM accounting_expenses e JOIN owners o ON o.id=e.owner_id WHERE e.id=%s", (exp_id,))
    return _ok(row)


@bp.put("/expenses/<int:expense_id>")
@require_auth
@require_role("OWNER")
def expenses_update(expense_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT e.*, s.department_id FROM accounting_expenses e JOIN accounting_sheets s ON s.id=e.sheet_id WHERE e.id=%s", (expense_id,))
        if not row:
            abort(404, description="Expense not found")
        if not _sheet_access(u.owner_id, int(row["department_id"])):
            abort(403, description="Access denied")

    body = request.get_json(silent=True) or {}
    updates: list[str] = []
    params: list[Any] = []
    for key, col in [("name", "name"), ("amount", "amount"), ("owner_id", "owner_id")]:
        if key in body:
            val = body[key]
            if key == "name" and not (val or "").strip():
                abort(400, description="name cannot be empty")
            updates.append(f"{col}=%s")
            params.append((val or "").strip() if key == "name" else val)
    if not updates:
        with db_cursor() as (_, cur):
            r = fetch_one(cur, "SELECT e.*, o.full_name AS owner_name FROM accounting_expenses e JOIN owners o ON o.id=e.owner_id WHERE e.id=%s", (expense_id,))
        return _ok(r)

    params.append(expense_id)
    with db_cursor() as (_, cur):
        cur.execute("UPDATE accounting_expenses SET " + ", ".join(updates) + " WHERE id=%s", tuple(params))
        r = fetch_one(cur, "SELECT e.*, o.full_name AS owner_name FROM accounting_expenses e JOIN owners o ON o.id=e.owner_id WHERE e.id=%s", (expense_id,))
    return _ok(r)


@bp.delete("/expenses/<int:expense_id>")
@require_auth
@require_role("OWNER")
def expenses_delete(expense_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT e.sheet_id, s.department_id FROM accounting_expenses e JOIN accounting_sheets s ON s.id=e.sheet_id WHERE e.id=%s", (expense_id,))
        if not row:
            abort(404, description="Expense not found")
        if not _sheet_access(u.owner_id, int(row["department_id"])):
            abort(403, description="Access denied")
        cur.execute("DELETE FROM accounting_expenses WHERE id=%s", (expense_id,))
    return _ok({"deleted": expense_id})


# ---------------------------------------------------------------------------
# Переводы
# ---------------------------------------------------------------------------

@bp.post("/sheets/<int:sheet_id>/transfers")
@require_auth
@require_role("OWNER")
def transfers_create(sheet_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        sheet = fetch_one(cur, "SELECT department_id FROM accounting_sheets WHERE id=%s", (sheet_id,))
        if not sheet:
            abort(404, description="Sheet not found")
        if not _sheet_access(u.owner_id, int(sheet["department_id"])):
            abort(403, description="Access denied")

    body = request.get_json(silent=True) or {}
    from_owner_id = body.get("from_owner_id")
    to_owner_id = body.get("to_owner_id")
    amount = body.get("amount")
    if from_owner_id is None or from_owner_id == "":
        abort(400, description="Выберите владельца «От кого»")
    if to_owner_id is None or to_owner_id == "":
        abort(400, description="Выберите владельца «Кому»")
    if amount is None or amount == "":
        abort(400, description="Укажите сумму")
    try:
        from_id = int(from_owner_id)
        to_id = int(to_owner_id)
        amt_val = float(amount)
    except (TypeError, ValueError):
        abort(400, description="Неверный формат данных")
    if from_id == to_id:
        abort(400, description="Отправитель и получатель должны быть разными")

    dep_id = int(sheet["department_id"])
    with db_cursor() as (_, cur):
        for oid, label in [(from_id, "От кого"), (to_id, "Кому")]:
            owner = fetch_one(cur, "SELECT owner_id FROM department_owners WHERE owner_id=%s AND department_id=%s", (oid, dep_id))
            if not owner:
                abort(400, description=f"Владелец «{label}» должен принадлежать отделу листа")

        amt = amt_val
        if amt <= 0:
            abort(400, description="amount must be positive")

        transfer_id = exec_one(
            cur,
            "INSERT INTO accounting_transfers (sheet_id, from_owner_id, to_owner_id, amount, created_by_user_id) VALUES (%s,%s,%s,%s,%s)",
            (sheet_id, from_id, to_id, amt, u.id),
        )
        row = fetch_one(
            cur,
            "SELECT t.*, o1.full_name AS from_owner_name, o2.full_name AS to_owner_name FROM accounting_transfers t JOIN owners o1 ON o1.id=t.from_owner_id JOIN owners o2 ON o2.id=t.to_owner_id WHERE t.id=%s",
            (transfer_id,),
        )
    return _ok(row)


@bp.put("/transfers/<int:transfer_id>")
@require_auth
@require_role("OWNER")
def transfers_update(transfer_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT t.*, s.department_id FROM accounting_transfers t JOIN accounting_sheets s ON s.id=t.sheet_id WHERE t.id=%s", (transfer_id,))
        if not row:
            abort(404, description="Transfer not found")
        if not _sheet_access(u.owner_id, int(row["department_id"])):
            abort(403, description="Access denied")

    body = request.get_json(silent=True) or {}
    updates: list[str] = []
    params: list[Any] = []
    for key, col in [("from_owner_id", "from_owner_id"), ("to_owner_id", "to_owner_id"), ("amount", "amount")]:
        if key in body:
            val = body[key]
            if key == "amount" and float(val or 0) <= 0:
                abort(400, description="amount must be positive")
            updates.append(f"{col}=%s")
            params.append(val)
    if not updates:
        with db_cursor() as (_, cur):
            r = fetch_one(cur, "SELECT t.*, o1.full_name AS from_owner_name, o2.full_name AS to_owner_name FROM accounting_transfers t JOIN owners o1 ON o1.id=t.from_owner_id JOIN owners o2 ON o2.id=t.to_owner_id WHERE t.id=%s", (transfer_id,))
        return _ok(r)

    if "from_owner_id" in body or "to_owner_id" in body:
        from_id = int(body.get("from_owner_id", row["from_owner_id"]))
        to_id = int(body.get("to_owner_id", row["to_owner_id"]))
        if from_id == to_id:
            abort(400, description="from_owner_id and to_owner_id must be different")

    params.append(transfer_id)
    with db_cursor() as (_, cur):
        cur.execute("UPDATE accounting_transfers SET " + ", ".join(updates) + " WHERE id=%s", tuple(params))
        r = fetch_one(cur, "SELECT t.*, o1.full_name AS from_owner_name, o2.full_name AS to_owner_name FROM accounting_transfers t JOIN owners o1 ON o1.id=t.from_owner_id JOIN owners o2 ON o2.id=t.to_owner_id WHERE t.id=%s", (transfer_id,))
    return _ok(r)


@bp.delete("/transfers/<int:transfer_id>")
@require_auth
@require_role("OWNER")
def transfers_delete(transfer_id: int) -> Response:
    u = getattr(g, "current_user") or get_current_user()
    if not u.owner_id:
        abort(403, description="Owner required")

    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT t.sheet_id, s.department_id FROM accounting_transfers t JOIN accounting_sheets s ON s.id=t.sheet_id WHERE t.id=%s", (transfer_id,))
        if not row:
            abort(404, description="Transfer not found")
        if not _sheet_access(u.owner_id, int(row["department_id"])):
            abort(403, description="Access denied")
        cur.execute("DELETE FROM accounting_transfers WHERE id=%s", (transfer_id,))
    return _ok({"deleted": transfer_id})
