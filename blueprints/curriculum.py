"""Учебные планы, комментарии и прохождение планов филиалами."""
from __future__ import annotations

from io import BytesIO
from typing import Any

from flask import Blueprint, Response, abort, g, request, send_file

from shared import db_cursor, exec_one, fetch_all, fetch_one, get_current_user, require_auth, require_role, _ok


bp = Blueprint("curriculum", __name__)
MAX_IMAGE_BYTES = 5 * 1024 * 1024
CLOSING_MODES = ("PLAN", "REPEAT", "OFF_PLAN_REPLACE")


def _user() -> Any:
    return getattr(g, "current_user", None) or get_current_user()


def _branch_access(cur: Any, branch_id: int, *, owner_only: bool = False) -> dict[str, Any]:
    u = _user()
    if u.role == "OWNER":
        row = fetch_one(
            cur,
            """
            SELECT b.id, b.name
            FROM branches b
            JOIN department_owners do2 ON do2.department_id=b.department_id
            WHERE b.id=%s AND do2.owner_id=%s
            """,
            (branch_id, u.owner_id),
        )
    elif not owner_only:
        row = fetch_one(
            cur,
            """
            SELECT b.id, b.name
            FROM branches b
            JOIN branch_teachers bt ON bt.branch_id=b.id
            WHERE b.id=%s AND bt.teacher_id=%s
            """,
            (branch_id, u.teacher_id),
        )
    else:
        row = None
    if not row:
        abort(404, description="Branch not found or access denied")
    return row


def _lesson_used(cur: Any, lesson_id: int) -> bool:
    return bool(fetch_one(cur, "SELECT 1 FROM lessons WHERE curriculum_lesson_id=%s LIMIT 1", (lesson_id,)))


def _plan_used(cur: Any, plan_id: int) -> bool:
    return bool(
        fetch_one(
            cur,
            """
            SELECT 1
            FROM lessons l
            JOIN curriculum_lessons cl ON cl.id=l.curriculum_lesson_id
            JOIN curriculum_modules cm ON cm.id=cl.module_id
            WHERE cm.plan_id=%s LIMIT 1
            """,
            (plan_id,),
        )
    )


def _plan_sequence(cur: Any, plan_id: int) -> list[dict[str, Any]]:
    return fetch_all(
        cur,
        """
        SELECT cl.id, cl.module_id, cm.name AS module_name, cm.sort_order AS module_sort_order,
               cl.name, cl.internal_description, cl.external_description, cl.format_id,
               lf.name AS format_name, cl.instruction_id, i.name AS instruction_name,
               cl.sort_order, cl.created_at, cl.updated_at,
               EXISTS(SELECT 1 FROM lessons x WHERE x.curriculum_lesson_id=cl.id) AS is_used,
               (SELECT COUNT(*) FROM curriculum_lesson_images img WHERE img.lesson_id=cl.id) AS image_count,
               (SELECT COUNT(*) FROM curriculum_lesson_comments c WHERE c.lesson_id=cl.id) AS lesson_comment_count,
               (SELECT COUNT(*) FROM instruction_comments ic WHERE ic.instruction_id=cl.instruction_id) AS instruction_comment_count
        FROM curriculum_lessons cl
        JOIN curriculum_modules cm ON cm.id=cl.module_id
        JOIN lesson_formats lf ON lf.id=cl.format_id
        LEFT JOIN instructions i ON i.id=cl.instruction_id
        WHERE cm.plan_id=%s
        ORDER BY cm.sort_order, cm.id, cl.sort_order, cl.id
        """,
        (plan_id,),
    )


def _active_run(cur: Any, branch_id: int) -> dict[str, Any] | None:
    return fetch_one(
        cur,
        """
        SELECT r.*, p.name AS plan_name, p.description AS plan_description
        FROM branch_curriculum_runs r
        JOIN curriculum_plans p ON p.id=r.plan_id
        WHERE r.branch_id=%s AND r.is_active=1
        ORDER BY r.id DESC LIMIT 1
        """,
        (branch_id,),
    )


def get_run_progress(cur: Any, run: dict[str, Any]) -> dict[str, Any]:
    sequence = _plan_sequence(cur, int(run["plan_id"]))
    image_rows = fetch_all(
        cur,
        """
        SELECT img.id,img.lesson_id,img.filename,img.mime,img.sort_order
        FROM curriculum_lesson_images img
        JOIN curriculum_lessons cl ON cl.id=img.lesson_id
        JOIN curriculum_modules cm ON cm.id=cl.module_id
        WHERE cm.plan_id=%s ORDER BY img.lesson_id,img.sort_order,img.id
        """,
        (int(run["plan_id"]),),
    )
    images_by_lesson: dict[int, list[dict[str, Any]]] = {}
    for image in image_rows:
        images_by_lesson.setdefault(int(image["lesson_id"]), []).append(image)
    for lesson in sequence:
        lesson["images"] = images_by_lesson.get(int(lesson["id"]), [])
    rows = fetch_all(
        cur,
        """
        SELECT DISTINCT curriculum_lesson_id
        FROM lessons
        WHERE curriculum_run_id=%s
          AND curriculum_lesson_id IS NOT NULL
          AND curriculum_mode IN ('PLAN','REPEAT','OFF_PLAN_REPLACE')
        """,
        (int(run["id"]),),
    )
    closed_ids = {int(row["curriculum_lesson_id"]) for row in rows}
    current = next((row for row in sequence if int(row["id"]) not in closed_ids), None)
    current_index = sequence.index(current) if current is not None else len(sequence)
    previous = [row for row in sequence[:current_index] if int(row["id"]) in closed_ids]
    last = previous[-1] if previous else None
    return {
        "enabled": True,
        "run": run,
        "plan_id": run["plan_id"],
        "plan_name": run["plan_name"],
        "total_lessons": len(sequence),
        "closed_lessons": len(closed_ids),
        "current_lesson": current,
        "last_lesson": last,
        "previous_lessons": previous,
        "is_completed": current is None,
    }


def get_branch_progress(cur: Any, branch_id: int) -> dict[str, Any]:
    run = _active_run(cur, branch_id)
    if not run:
        return {
            "enabled": False,
            "run": None,
            "plan_id": None,
            "plan_name": None,
            "total_lessons": 0,
            "closed_lessons": 0,
            "current_lesson": None,
            "last_lesson": None,
            "previous_lessons": [],
            "is_completed": False,
        }
    return get_run_progress(cur, run)


def validate_lesson_curriculum(
    cur: Any,
    branch_id: int,
    mode: str | None,
    requested_lesson_id: Any,
    requested_instruction_id: Any,
) -> dict[str, Any]:
    progress = get_branch_progress(cur, branch_id)
    if not progress["enabled"]:
        if mode:
            abort(400, description="Branch has no active curriculum plan")
        return {"run_id": None, "lesson_id": None, "mode": None, "instruction_id": requested_instruction_id}

    normalized = str(mode or "PLAN").upper()
    if normalized not in {"PLAN", "REPEAT", "OFF_PLAN_REPLACE", "OFF_PLAN_PAUSE"}:
        abort(400, description="Invalid curriculum_mode")
    current = progress["current_lesson"]
    if normalized in {"PLAN", "OFF_PLAN_REPLACE"} and current is None:
        abort(400, description="Curriculum plan is completed")

    if normalized == "PLAN":
        if requested_lesson_id not in (None, "") and int(requested_lesson_id) != int(current["id"]):
            abort(409, description="Current curriculum lesson has changed")
        return {
            "run_id": int(progress["run"]["id"]),
            "lesson_id": int(current["id"]),
            "mode": normalized,
            "instruction_id": current.get("instruction_id"),
        }
    if normalized == "REPEAT":
        if requested_lesson_id in (None, ""):
            abort(400, description="curriculum_lesson_id is required for repeat")
        previous = {int(row["id"]): row for row in progress["previous_lessons"]}
        selected = previous.get(int(requested_lesson_id))
        if not selected:
            abort(400, description="Only a previously completed lesson can be repeated")
        return {
            "run_id": int(progress["run"]["id"]),
            "lesson_id": int(selected["id"]),
            "mode": normalized,
            "instruction_id": selected.get("instruction_id"),
        }
    if normalized == "OFF_PLAN_REPLACE":
        return {
            "run_id": int(progress["run"]["id"]),
            "lesson_id": int(current["id"]),
            "mode": normalized,
            "instruction_id": requested_instruction_id,
        }
    return {
        "run_id": int(progress["run"]["id"]),
        "lesson_id": None,
        "mode": normalized,
        "instruction_id": requested_instruction_id,
    }


@bp.get("/lesson-formats")
@require_auth
def lesson_formats_list() -> Response:
    include_inactive = request.args.get("include_inactive") in {"1", "true", "True"}
    where = "" if include_inactive and _user().role == "OWNER" else "WHERE is_active=1"
    with db_cursor() as (_, cur):
        rows = fetch_all(cur, f"SELECT * FROM lesson_formats {where} ORDER BY sort_order, name, id")
    return _ok({"items": rows})


@bp.post("/lesson-formats")
@require_auth
@require_role("OWNER")
def lesson_formats_create() -> Response:
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    if not name:
        abort(400, description="name is required")
    with db_cursor() as (_, cur):
        fid = exec_one(cur, "INSERT INTO lesson_formats(name,description,sort_order) VALUES (%s,%s,%s)", (name, body.get("description"), int(body.get("sort_order") or 0)))
        row = fetch_one(cur, "SELECT * FROM lesson_formats WHERE id=%s", (fid,))
    return _ok(row)


@bp.put("/lesson-formats/<int:format_id>")
@require_auth
@require_role("OWNER")
def lesson_formats_update(format_id: int) -> Response:
    body = request.get_json(silent=True) or {}
    fields: list[str] = []
    params: list[Any] = []
    for key in ("name", "description", "sort_order", "is_active"):
        if key in body:
            fields.append(f"{key}=%s")
            params.append(1 if key == "is_active" and bool(body[key]) else body[key])
    if not fields:
        abort(400, description="No fields to update")
    with db_cursor() as (_, cur):
        cur.execute(f"UPDATE lesson_formats SET {', '.join(fields)} WHERE id=%s", tuple(params + [format_id]))
        row = fetch_one(cur, "SELECT * FROM lesson_formats WHERE id=%s", (format_id,))
    if not row:
        abort(404)
    return _ok(row)


@bp.delete("/lesson-formats/<int:format_id>")
@require_auth
@require_role("OWNER")
def lesson_formats_delete(format_id: int) -> Response:
    with db_cursor() as (_, cur):
        used = fetch_one(cur, "SELECT 1 FROM curriculum_lessons WHERE format_id=%s LIMIT 1", (format_id,))
        if used:
            cur.execute("UPDATE lesson_formats SET is_active=0 WHERE id=%s", (format_id,))
            return _ok({"archived": True})
        cur.execute("DELETE FROM lesson_formats WHERE id=%s", (format_id,))
    return _ok({"deleted": True})


@bp.get("/curriculum-plans")
@require_auth
def plans_list() -> Response:
    with db_cursor() as (_, cur):
        rows = fetch_all(
            cur,
            """
            SELECT p.*,
                   COUNT(DISTINCT m.id) AS module_count,
                   COUNT(DISTINCT cl.id) AS lesson_count,
                   EXISTS(
                     SELECT 1 FROM lessons x
                     JOIN curriculum_lessons xl ON xl.id=x.curriculum_lesson_id
                     JOIN curriculum_modules xm ON xm.id=xl.module_id
                     WHERE xm.plan_id=p.id
                   ) AS is_used
            FROM curriculum_plans p
            LEFT JOIN curriculum_modules m ON m.plan_id=p.id
            LEFT JOIN curriculum_lessons cl ON cl.module_id=m.id
            GROUP BY p.id ORDER BY p.name, p.id
            """,
        )
    return _ok({"items": rows})


@bp.post("/curriculum-plans")
@require_auth
@require_role("OWNER")
def plans_create() -> Response:
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    if not name:
        abort(400, description="name is required")
    with db_cursor() as (_, cur):
        pid = exec_one(cur, "INSERT INTO curriculum_plans(name,description) VALUES (%s,%s)", (name, body.get("description")))
    return plan_get(pid)


@bp.get("/curriculum-plans/<int:plan_id>")
@require_auth
def plan_get(plan_id: int) -> Response:
    with db_cursor() as (_, cur):
        plan = fetch_one(cur, "SELECT * FROM curriculum_plans WHERE id=%s", (plan_id,))
        if not plan:
            abort(404)
        modules = fetch_all(
            cur,
            """
            SELECT m.*,
                   (SELECT COUNT(*) FROM curriculum_lessons cl WHERE cl.module_id=m.id) AS lesson_count
            FROM curriculum_modules m WHERE m.plan_id=%s ORDER BY m.sort_order,m.id
            """,
            (plan_id,),
        )
        lessons = _plan_sequence(cur, plan_id)
        images = fetch_all(
            cur,
            """
            SELECT img.id,img.lesson_id,img.filename,img.mime,img.sort_order,img.created_at
            FROM curriculum_lesson_images img
            JOIN curriculum_lessons cl ON cl.id=img.lesson_id
            JOIN curriculum_modules cm ON cm.id=cl.module_id
            WHERE cm.plan_id=%s ORDER BY img.lesson_id,img.sort_order,img.id
            """,
            (plan_id,),
        )
        by_module: dict[int, list[dict[str, Any]]] = {}
        by_lesson_images: dict[int, list[dict[str, Any]]] = {}
        for image in images:
            by_lesson_images.setdefault(int(image["lesson_id"]), []).append(image)
        for lesson in lessons:
            lesson["images"] = by_lesson_images.get(int(lesson["id"]), [])
            by_module.setdefault(int(lesson["module_id"]), []).append(lesson)
        for module in modules:
            module["lessons"] = by_module.get(int(module["id"]), [])
        plan["modules"] = modules
        plan["module_count"] = len(modules)
        plan["lesson_count"] = len(lessons)
        plan["is_used"] = _plan_used(cur, plan_id)
    return _ok(plan)


@bp.put("/curriculum-plans/<int:plan_id>")
@require_auth
@require_role("OWNER")
def plans_update(plan_id: int) -> Response:
    body = request.get_json(silent=True) or {}
    fields: list[str] = []
    params: list[Any] = []
    for key in ("name", "description"):
        if key in body:
            fields.append(f"{key}=%s")
            params.append(str(body[key]).strip() if key == "name" else body[key])
    if not fields:
        abort(400, description="No fields to update")
    with db_cursor() as (_, cur):
        cur.execute(f"UPDATE curriculum_plans SET {', '.join(fields)} WHERE id=%s", tuple(params + [plan_id]))
    return plan_get(plan_id)


@bp.delete("/curriculum-plans/<int:plan_id>")
@require_auth
@require_role("OWNER")
def plans_delete(plan_id: int) -> Response:
    with db_cursor() as (_, cur):
        if _plan_used(cur, plan_id) or fetch_one(cur, "SELECT 1 FROM branch_curriculum_runs WHERE plan_id=%s LIMIT 1", (plan_id,)):
            abort(409, description="Used curriculum plan cannot be deleted")
        cur.execute("DELETE FROM curriculum_plans WHERE id=%s", (plan_id,))
    return _ok({"deleted": True})


@bp.post("/curriculum-plans/<int:plan_id>/modules")
@require_auth
@require_role("OWNER")
def modules_create(plan_id: int) -> Response:
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    if not name:
        abort(400, description="name is required")
    with db_cursor() as (_, cur):
        if not fetch_one(cur, "SELECT 1 FROM curriculum_plans WHERE id=%s", (plan_id,)):
            abort(404)
        order_row = fetch_one(cur, "SELECT COALESCE(MAX(sort_order),0)+1 AS n FROM curriculum_modules WHERE plan_id=%s", (plan_id,))
        mid = exec_one(cur, "INSERT INTO curriculum_modules(plan_id,name,description,sort_order) VALUES (%s,%s,%s,%s)", (plan_id, name, body.get("description"), int(order_row["n"])))
        row = fetch_one(cur, "SELECT * FROM curriculum_modules WHERE id=%s", (mid,))
    return _ok(row)


@bp.put("/curriculum-modules/<int:module_id>")
@require_auth
@require_role("OWNER")
def modules_update(module_id: int) -> Response:
    body = request.get_json(silent=True) or {}
    fields: list[str] = []
    params: list[Any] = []
    for key in ("name", "description"):
        if key in body:
            fields.append(f"{key}=%s")
            params.append(str(body[key]).strip() if key == "name" else body[key])
    if not fields:
        abort(400, description="No fields to update")
    with db_cursor() as (_, cur):
        cur.execute(f"UPDATE curriculum_modules SET {', '.join(fields)} WHERE id=%s", tuple(params + [module_id]))
        row = fetch_one(cur, "SELECT * FROM curriculum_modules WHERE id=%s", (module_id,))
    if not row:
        abort(404)
    return _ok(row)


@bp.delete("/curriculum-modules/<int:module_id>")
@require_auth
@require_role("OWNER")
def modules_delete(module_id: int) -> Response:
    with db_cursor() as (_, cur):
        if fetch_one(cur, "SELECT 1 FROM lessons l JOIN curriculum_lessons cl ON cl.id=l.curriculum_lesson_id WHERE cl.module_id=%s LIMIT 1", (module_id,)):
            abort(409, description="Module contains used lessons")
        cur.execute("DELETE FROM curriculum_modules WHERE id=%s", (module_id,))
    return _ok({"deleted": True})


@bp.put("/curriculum-plans/<int:plan_id>/modules/reorder")
@require_auth
@require_role("OWNER")
def modules_reorder(plan_id: int) -> Response:
    ids = [int(value) for value in (request.get_json(silent=True) or {}).get("module_ids", [])]
    with db_cursor() as (_, cur):
        current = fetch_all(cur, "SELECT id FROM curriculum_modules WHERE plan_id=%s ORDER BY sort_order,id", (plan_id,))
        current_ids = [int(row["id"]) for row in current]
        if sorted(ids) != sorted(current_ids):
            abort(400, description="module_ids must contain every module exactly once")
        used_rows = fetch_all(cur, "SELECT DISTINCT cl.module_id FROM lessons l JOIN curriculum_lessons cl ON cl.id=l.curriculum_lesson_id JOIN curriculum_modules cm ON cm.id=cl.module_id WHERE cm.plan_id=%s", (plan_id,))
        used = {int(row["module_id"]) for row in used_rows}
        for module_id in used:
            if current_ids.index(module_id) != ids.index(module_id):
                abort(409, description="Modules containing used lessons cannot be moved")
        for index, module_id in enumerate(ids, 1):
            cur.execute("UPDATE curriculum_modules SET sort_order=%s WHERE id=%s", (index, module_id))
    return _ok({"module_ids": ids})


@bp.post("/curriculum-modules/<int:module_id>/lessons")
@require_auth
@require_role("OWNER")
def curriculum_lessons_create(module_id: int) -> Response:
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()
    format_id = body.get("format_id")
    if not name or format_id in (None, ""):
        abort(400, description="name and format_id are required")
    with db_cursor() as (_, cur):
        if not fetch_one(cur, "SELECT 1 FROM curriculum_modules WHERE id=%s", (module_id,)):
            abort(404)
        order_row = fetch_one(cur, "SELECT COALESCE(MAX(sort_order),0)+1 AS n FROM curriculum_lessons WHERE module_id=%s", (module_id,))
        lid = exec_one(
            cur,
            """
            INSERT INTO curriculum_lessons(module_id,name,internal_description,external_description,format_id,instruction_id,sort_order)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            """,
            (module_id, name, body.get("internal_description"), body.get("external_description"), int(format_id), int(body["instruction_id"]) if body.get("instruction_id") not in (None, "") else None, int(order_row["n"])),
        )
        row = fetch_one(cur, "SELECT * FROM curriculum_lessons WHERE id=%s", (lid,))
    return _ok(row)


@bp.put("/curriculum-lessons/<int:lesson_id>")
@require_auth
@require_role("OWNER")
def curriculum_lessons_update(lesson_id: int) -> Response:
    body = request.get_json(silent=True) or {}
    with db_cursor() as (_, cur):
        existing = fetch_one(cur, "SELECT * FROM curriculum_lessons WHERE id=%s", (lesson_id,))
        if not existing:
            abort(404)
        if _lesson_used(cur, lesson_id):
            abort(409, description="Lesson is already used and cannot be edited")
        fields: list[str] = []
        params: list[Any] = []
        for key in ("name", "internal_description", "external_description", "format_id", "instruction_id", "module_id"):
            if key in body:
                fields.append(f"{key}=%s")
                value = body[key]
                if key in {"format_id", "module_id"}:
                    value = int(value)
                elif key == "instruction_id":
                    value = int(value) if value not in (None, "") else None
                elif key == "name":
                    value = str(value).strip()
                params.append(value)
        new_module_id = int(body["module_id"]) if body.get("module_id") not in (None, "") else int(existing["module_id"])
        if new_module_id != int(existing["module_id"]):
            order_row = fetch_one(cur, "SELECT COALESCE(MAX(sort_order),0)+1 AS n FROM curriculum_lessons WHERE module_id=%s", (new_module_id,))
            fields.append("sort_order=%s")
            params.append(int(order_row["n"]))
        if not fields:
            abort(400, description="No fields to update")
        cur.execute(f"UPDATE curriculum_lessons SET {', '.join(fields)} WHERE id=%s", tuple(params + [lesson_id]))
        if new_module_id != int(existing["module_id"]):
            source_rows = fetch_all(cur, "SELECT id FROM curriculum_lessons WHERE module_id=%s ORDER BY sort_order,id", (existing["module_id"],))
            for index, source in enumerate(source_rows, 1):
                cur.execute("UPDATE curriculum_lessons SET sort_order=%s WHERE id=%s", (index, source["id"]))
        row = fetch_one(cur, "SELECT * FROM curriculum_lessons WHERE id=%s", (lesson_id,))
    return _ok(row)


@bp.delete("/curriculum-lessons/<int:lesson_id>")
@require_auth
@require_role("OWNER")
def curriculum_lessons_delete(lesson_id: int) -> Response:
    with db_cursor() as (_, cur):
        if _lesson_used(cur, lesson_id):
            abort(409, description="Used lesson cannot be deleted")
        cur.execute("DELETE FROM curriculum_lessons WHERE id=%s", (lesson_id,))
    return _ok({"deleted": True})


@bp.put("/curriculum-modules/<int:module_id>/lessons/reorder")
@require_auth
@require_role("OWNER")
def curriculum_lessons_reorder(module_id: int) -> Response:
    ids = [int(value) for value in (request.get_json(silent=True) or {}).get("lesson_ids", [])]
    with db_cursor() as (_, cur):
        rows = fetch_all(cur, "SELECT id FROM curriculum_lessons WHERE module_id=%s ORDER BY sort_order,id", (module_id,))
        current = [int(row["id"]) for row in rows]
        if sorted(ids) != sorted(current):
            abort(400, description="lesson_ids must contain every lesson exactly once")
        for lesson_id in current:
            if _lesson_used(cur, lesson_id) and current.index(lesson_id) != ids.index(lesson_id):
                abort(409, description="Used lessons cannot be moved")
        for index, lesson_id in enumerate(ids, 1):
            cur.execute("UPDATE curriculum_lessons SET sort_order=%s WHERE id=%s", (index, lesson_id))
    return _ok({"lesson_ids": ids})


@bp.post("/curriculum-lessons/<int:lesson_id>/images")
@require_auth
@require_role("OWNER")
def lesson_images_create(lesson_id: int) -> Response:
    image = request.files.get("image") or request.files.get("file")
    if not image:
        abort(400, description="image file is required")
    data = image.read()
    if not data:
        abort(400, description="Empty image")
    if len(data) > MAX_IMAGE_BYTES:
        abort(413, description="Image is too large")
    if not str(image.mimetype or "").startswith("image/"):
        abort(400, description="Only image files are allowed")
    with db_cursor() as (_, cur):
        if _lesson_used(cur, lesson_id):
            abort(409, description="Used lesson cannot be edited")
        order_row = fetch_one(cur, "SELECT COALESCE(MAX(sort_order),0)+1 AS n FROM curriculum_lesson_images WHERE lesson_id=%s", (lesson_id,))
        iid = exec_one(cur, "INSERT INTO curriculum_lesson_images(lesson_id,filename,mime,image_blob,sort_order) VALUES (%s,%s,%s,%s,%s)", (lesson_id, image.filename, image.mimetype, data, int(order_row["n"])))
        row = fetch_one(cur, "SELECT id,lesson_id,filename,mime,sort_order,created_at FROM curriculum_lesson_images WHERE id=%s", (iid,))
    return _ok(row)


@bp.get("/curriculum-lesson-images/<int:image_id>")
@require_auth
def lesson_images_get(image_id: int) -> Response:
    with db_cursor(dictionary=False) as (_, cur):
        cur.execute("SELECT image_blob,mime,filename FROM curriculum_lesson_images WHERE id=%s", (image_id,))
        row = cur.fetchone()
    if not row:
        abort(404)
    return send_file(BytesIO(row[0]), mimetype=row[1] or "image/jpeg", download_name=row[2] or f"lesson_{image_id}.jpg", max_age=0)


@bp.delete("/curriculum-lesson-images/<int:image_id>")
@require_auth
@require_role("OWNER")
def lesson_images_delete(image_id: int) -> Response:
    with db_cursor() as (_, cur):
        row = fetch_one(cur, "SELECT lesson_id FROM curriculum_lesson_images WHERE id=%s", (image_id,))
        if not row:
            abort(404)
        if _lesson_used(cur, int(row["lesson_id"])):
            abort(409, description="Used lesson cannot be edited")
        cur.execute("DELETE FROM curriculum_lesson_images WHERE id=%s", (image_id,))
    return _ok({"deleted": True})


def _comments_list(table: str, parent_field: str, parent_id: int) -> Response:
    with db_cursor() as (_, cur):
        rows = fetch_all(cur, f"SELECT c.*,u.login AS author_name,u.role AS author_role FROM {table} c JOIN auf_users u ON u.id=c.author_user_id WHERE c.{parent_field}=%s ORDER BY c.created_at,c.id", (parent_id,))
    return _ok({"items": rows})


def _comment_create(table: str, parent_field: str, parent_table: str, parent_id: int) -> Response:
    text = str((request.get_json(silent=True) or {}).get("text") or "").strip()
    if not text:
        abort(400, description="text is required")
    with db_cursor() as (_, cur):
        if not fetch_one(cur, f"SELECT 1 FROM {parent_table} WHERE id=%s", (parent_id,)):
            abort(404)
        cid = exec_one(cur, f"INSERT INTO {table}({parent_field},author_user_id,text) VALUES (%s,%s,%s)", (parent_id, _user().id, text))
        row = fetch_one(cur, f"SELECT c.*,u.login AS author_name,u.role AS author_role FROM {table} c JOIN auf_users u ON u.id=c.author_user_id WHERE c.id=%s", (cid,))
    return _ok(row)


@bp.get("/curriculum-lessons/<int:lesson_id>/comments")
@require_auth
def lesson_comments_list(lesson_id: int) -> Response:
    return _comments_list("curriculum_lesson_comments", "lesson_id", lesson_id)


@bp.post("/curriculum-lessons/<int:lesson_id>/comments")
@require_auth
def lesson_comments_create(lesson_id: int) -> Response:
    return _comment_create("curriculum_lesson_comments", "lesson_id", "curriculum_lessons", lesson_id)


@bp.get("/instructions/<int:instruction_id>/comments")
@require_auth
def instruction_comments_list(instruction_id: int) -> Response:
    return _comments_list("instruction_comments", "instruction_id", instruction_id)


@bp.post("/instructions/<int:instruction_id>/comments")
@require_auth
def instruction_comments_create(instruction_id: int) -> Response:
    return _comment_create("instruction_comments", "instruction_id", "instructions", instruction_id)


@bp.get("/branches/<int:branch_id>/curriculum")
@require_auth
def branch_curriculum_get(branch_id: int) -> Response:
    with db_cursor() as (_, cur):
        _branch_access(cur, branch_id)
        progress = get_branch_progress(cur, branch_id)
    return _ok(progress)


@bp.put("/branches/<int:branch_id>/curriculum")
@require_auth
@require_role("OWNER")
def branch_curriculum_update(branch_id: int) -> Response:
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled"))
    plan_id = body.get("plan_id")
    with db_cursor() as (_, cur):
        _branch_access(cur, branch_id, owner_only=True)
        active = _active_run(cur, branch_id)
        if not enabled:
            if active:
                cur.execute("UPDATE branch_curriculum_runs SET is_active=0,active_branch_id=NULL,ended_at=NOW() WHERE id=%s", (active["id"],))
            return _ok(get_branch_progress(cur, branch_id))
        if plan_id in (None, ""):
            abort(400, description="plan_id is required")
        plan_id = int(plan_id)
        if not fetch_one(cur, "SELECT 1 FROM curriculum_plans WHERE id=%s", (plan_id,)):
            abort(400, description="Unknown curriculum plan")
        if active and int(active["plan_id"]) == plan_id:
            return _ok(get_run_progress(cur, active))
        if active:
            cur.execute("UPDATE branch_curriculum_runs SET is_active=0,active_branch_id=NULL,ended_at=NOW() WHERE id=%s", (active["id"],))
        rid = exec_one(cur, "INSERT INTO branch_curriculum_runs(branch_id,plan_id,is_active,active_branch_id,created_by_user_id) VALUES (%s,%s,1,%s,%s)", (branch_id, plan_id, branch_id, _user().id))
        run = fetch_one(cur, "SELECT r.*,p.name AS plan_name,p.description AS plan_description FROM branch_curriculum_runs r JOIN curriculum_plans p ON p.id=r.plan_id WHERE r.id=%s", (rid,))
        progress = get_run_progress(cur, run)
    return _ok(progress)
