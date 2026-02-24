"""
CRM «Поиск» — ИИ-поиск детских садов через gpt-4o-mini-search-preview (web search).
Без 2GIS. Модель ищет в интернете, мы парсим, проверяем на робототехнику, сохраняем.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from typing import Any, Callable, Iterator

import requests
from flask import Flask, Response, abort, g, request, stream_with_context

from shared import db_cursor, exec_one, fetch_all, fetch_one, get_current_user

SEARCH_MODEL = "gpt-4o-mini-search-preview"
CHECK_MODEL = "gpt-4o-mini"

_search_stop_flags: dict[int, bool] = {}
_search_stop_lock = threading.Lock()


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


def _tool_fetch_webpage(url: str) -> str:
    if not url or not url.startswith(("http://", "https://")):
        return ""
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 (compatible; RoboMan/1.0)"})
        r.raise_for_status()
        html = r.text
        text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()[:15000]
        return text
    except Exception:
        return ""


def _is_state_or_school(name: str) -> bool:
    if not name or not isinstance(name, str):
        return False
    n = name.lower().strip()
    if re.search(r"№\s*\d+|№\d+", n):
        return True
    if re.search(r"детский\s+сад\s+№|доу\s+№|д\s*/\s*с\s+№", n):
        return True
    if any(kw in n for kw in ("школа", "school", "гимназия", "лицей", "интернат")):
        return True
    return False


def _extract_phone_from_text(text: str) -> str | None:
    if not text:
        return None
    m = re.search(r"[\+]?[78][\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}", text)
    if m:
        return re.sub(r"[\s\-\(\)]", "", m.group(0))
    m = re.search(r"[\+]?[78]\d{10}", text)
    return m.group(0) if m else None


def _make_external_id(name: str, url: str) -> str:
    s = f"{name}|{url}"
    return hashlib.md5(s.encode()).hexdigest()


def _tool_save_prospect(
    name: str,
    address: str | None,
    phone: str | None,
    website: str | None,
    source_url: str | None,
    source: str,
    external_id: str | None,
    user_id: int,
) -> dict[str, Any]:
    with db_cursor() as (_, cur):
        if external_id and source:
            exists = fetch_one(cur, "SELECT 1 FROM crm_prospect_kindergartens WHERE source=%s AND external_id=%s", (source, external_id))
            if exists:
                return {"ok": False, "duplicate": True}
        map_url = source_url or website or ""
        pid = exec_one(
            cur,
            """INSERT INTO crm_prospect_kindergartens
               (name, address, phone, website, map_2gis_url, source, external_id, created_by_user_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (name[:255], (address or "")[:512], (phone or "")[:128], (website or "")[:512],
             map_url[:512], source[:64], (external_id or "")[:128], user_id),
        )
        row = fetch_one(cur, "SELECT id, name, address, phone, website, map_2gis_url FROM crm_prospect_kindergartens WHERE id=%s", (pid,))
        if row:
            for k in list(row.keys()):
                if hasattr(row[k], "isoformat"):
                    row[k] = row[k].isoformat()
        return {"ok": True, "id": pid, "row": row}


def _parse_kindergartens_from_response(text: str) -> list[dict[str, Any]]:
    """Извлечь JSON-массив садиков из ответа модели."""
    out = []
    m = re.search(r"\[[\s\S]*?\]", text)
    if m:
        try:
            arr = json.loads(m.group(0))
            for it in arr if isinstance(arr, list) else []:
                if isinstance(it, dict) and it.get("name"):
                    out.append({
                        "name": str(it.get("name", "")).strip(),
                        "address": str(it.get("address", "")).strip() or None,
                        "phone": str(it.get("phone", "")).strip() or None,
                        "website": str(it.get("website", "")).strip() or str(it.get("url", "")).strip() or None,
                        "source_url": str(it.get("source_url", "")).strip() or str(it.get("url", "")).strip() or None,
                    })
        except json.JSONDecodeError:
            pass
    return out


PHASES_ORDER = ["init", "search", "search_done", "parse", "dedup", "filter_done", "check", "done", "no_results", "nothing_new"]


def _run_search_agent(user_id: int, stop_check: Callable[[], bool]) -> Iterator[dict[str, Any]]:
    api_key = _get_aitunnel_api_key()
    if not api_key:
        yield {"type": "error", "message": "AITUNNEL API key не настроен"}
        return

    def _step(phase: str, message: str, detail: str = ""):
        idx = PHASES_ORDER.index(phase) if phase in PHASES_ORDER else -1
        return {"type": "step", "phase": phase, "phase_index": idx, "message": message, "detail": detail}

    with db_cursor() as (_, cur):
        existing_rows = fetch_all(
            cur,
            "SELECT name, website, map_2gis_url FROM crm_prospect_kindergartens WHERE source=%s ORDER BY id DESC LIMIT 300",
            ("web_search",),
        )
    existing_names = set()
    existing_urls = set()
    for r in existing_rows or []:
        name = (r.get("name") or "").strip()
        if name:
            existing_names.add(name.lower())
        for key in ("website", "map_2gis_url"):
            u = (r.get(key) or "").strip()
            if u and u.startswith(("http://", "https://")):
                existing_urls.add(u.lower().rstrip("/"))

    exclude_block = ""
    if existing_names or existing_urls:
        parts = []
        if existing_names:
            names_list = sorted(existing_names)[:120]
            parts.append("Названия (не предлагай их снова): " + ", ".join(f'"{n}"' for n in names_list))
        if existing_urls:
            urls_list = sorted(existing_urls)[:50]
            parts.append("Сайты (не предлагай эти организации снова): " + ", ".join(urls_list))
        exclude_block = "\n\nУЖЕ ЕСТЬ В БАЗЕ — НЕ ПРЕДЛАГАЙ ИХ. Ищи именно ДРУГИЕ частные детские сады:\n" + "\n".join(parts)

    init_detail = "Подключение к gpt-4o-mini-search-preview через AITUNNEL."
    if existing_names or existing_urls:
        init_detail += f" В промпт добавлено {len(existing_names)} названий и {len(existing_urls)} сайтов — модель будет искать другие садики."
    yield _step("init", "Инициализация поиска", init_detail)

    prompt = """Ты ищешь частные детские сады в Москве через поиск в интернете.

ЗАДАЧА: Найди 15–25 ЧАСТНЫХ детских садов в городе Москва (только город, не область).
ВАЖНО: Предлагай только те садики, которых ещё НЕТ в списке «УЖЕ ЕСТЬ В БАЗЕ» ниже — при каждом запуске нужны НОВЫЕ организации.""" + exclude_block + """

ИСКЛЮЧИ:
- Государственные садики (названия с №, типа "Детский сад № 123")
- Школы, гимназии, лицеи
- Детские центры, которые не садики

ФОРМАТ ОТВЕТА: Верни ТОЛЬКО валидный JSON-массив. Никакого текста до и после.
Пример:
[
  {"name": "Название", "address": "Адрес", "phone": "+7...", "website": "https://...", "source_url": "URL откуда взял"},
  ...
]

source_url — ссылка на страницу, откуда ты взял информацию.
Для каждого садика найди: название, адрес (если есть), телефон, сайт.
Если телефона или сайта нет — оставь пустую строку.
Все садики должны быть в Москве."""

    yield _step("search", "Запрос к ИИ с веб-поиском", "Модель ищет новые садики (исключая уже сохранённые)" if exclude_block else "Модель gpt-4o-mini-search-preview ищет частные детские сады Москвы")

    full_text = ""
    try:
        r = requests.post(
            "https://api.aitunnel.ru/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": SEARCH_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 8000,
                "stream": True,
            },
            timeout=120,
            stream=True,
        )
        r.raise_for_status()
        for line in r.iter_lines():
            if stop_check():
                yield {"type": "stopped", "suitable": 0, "medium": 0, "unsuitable": 0}
                return
            if line and line.startswith(b"data: ") and line != b"data: [DONE]":
                try:
                    data = json.loads(line[6:].decode())
                    delta = (data.get("choices") or [{}])[0].get("delta", {})
                    chunk = delta.get("content", "")
                    if chunk:
                        full_text += chunk
                        yield {"type": "stream_token", "chunk": chunk}
                except (json.JSONDecodeError, KeyError):
                    pass
    except requests.RequestException as e:
        yield {"type": "error", "message": f"Ошибка API: {e}"}
        return

    yield _step("search_done", "Ответ модели получен", f"Получено {len(full_text)} символов от gpt-4o-mini-search-preview")

    orgs_raw = _parse_kindergartens_from_response(full_text)
    yield _step("parse", "Парсинг JSON-ответа", f"Распознано {len(orgs_raw)} организаций из ответа модели")

    if not orgs_raw:
        yield _step("no_results", "Не удалось извлечь список садиков", "Модель не вернула валидный JSON. Попробуйте запустить поиск снова.")
        yield {"type": "done", "suitable": 0, "medium": 0, "unsuitable": 0}
        return

    with db_cursor() as (_, cur):
        rows = fetch_all(cur, "SELECT external_id FROM crm_prospect_kindergartens WHERE source=%s AND external_id IS NOT NULL", ("web_search",))
    existing_ids = {str(r.get("external_id", "")).strip() for r in rows if r.get("external_id")}
    yield _step("dedup", "Проверка дубликатов", f"В базе уже {len(existing_ids)} записей из web_search")

    orgs = []
    skipped_state = 0
    skipped_dup = 0
    for org in orgs_raw:
        if _is_state_or_school(org.get("name", "")):
            skipped_state += 1
            yield {"type": "log", "level": "skip", "message": f"Пропуск (гос./школа): {org.get('name', '')}"}
            continue
        ext_id = _make_external_id(org.get("name", ""), org.get("source_url") or org.get("website") or "")
        if ext_id in existing_ids:
            skipped_dup += 1
            yield {"type": "log", "level": "skip", "message": f"Пропуск (дубликат): {org.get('name', '')}"}
            continue
        org["external_id"] = ext_id
        orgs.append(org)

    yield _step("filter_done", "Фильтрация завершена", f"К проверке на робототехнику: {len(orgs)} садиков (пропущено гос.: {skipped_state}, дубликатов: {skipped_dup})")

    if not orgs:
        yield _step("nothing_new", "Нет новых садиков", "Все найденные уже в базе или отфильтрованы")
        yield {"type": "done", "suitable": 0, "medium": 0, "unsuitable": 0}
        return

    saved = 0
    cnt_medium = 0
    cnt_unsuitable = 0
    source = "web_search"

    yield {"type": "log", "level": "info", "message": f"Начинаем проверку {len(orgs)} садиков на робототехнику и LEGO"}
    for i, org in enumerate(orgs):
        if stop_check():
            yield {"type": "stopped", "suitable": saved, "medium": cnt_medium, "unsuitable": cnt_unsuitable}
            return

        yield _step("check", f"Проверка {i+1}/{len(orgs)}: {org.get('name', '')[:50]}", "Загрузка сайта → проверка на робототехнику/LEGO")

        page_text = ""
        url = org.get("website") or org.get("source_url")
        if url:
            yield {"type": "log", "level": "fetch", "message": f"Загрузка: {url[:60]}..."}
            page_text = _tool_fetch_webpage(url)[:8000]
        if not org.get("phone") and page_text:
            extracted = _extract_phone_from_text(page_text)
            if extracted:
                org["phone"] = extracted

        check_prompt = f"""Проверь детский сад. Есть ли робототехника, Lego, LEGO Education, программирование?
Название: {org.get('name', '')}
Адрес: {org.get('address', '')}
Текст с сайта:
{page_text[:4000] if page_text else 'Нет данных'}
Ответь ТОЛЬКО: ДА или НЕТ. ДА = есть робототехника/Lego. НЕТ = точно нет."""

        try:
            rc = requests.post(
                "https://api.aitunnel.ru/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": CHECK_MODEL, "messages": [{"role": "user", "content": check_prompt}], "max_tokens": 10},
                timeout=25,
            )
            rc.raise_for_status()
            ans = ((rc.json().get("choices") or [{}])[0].get("message") or {}).get("content") or ""
            has_robotics = "нет" not in ans.lower().strip() or "да" in ans.lower().strip() or len(ans.strip()) < 2
        except Exception:
            has_robotics = True

        has_contact = bool((org.get("phone") or "").strip() or (org.get("website") or "").strip())

        if has_robotics:
            cnt_unsuitable += 1
            yield {"type": "unsuitable", "name": org.get("name", ""), "reason": "робототехника/LEGO", "count": cnt_unsuitable}
        elif not has_contact:
            cnt_medium += 1
            res = _tool_save_prospect(
                name=org.get("name", ""),
                address=org.get("address"),
                phone=org.get("phone"),
                website=org.get("website"),
                source_url=org.get("source_url"),
                source=source,
                external_id=org.get("external_id"),
                user_id=user_id,
            )
            if res.get("ok") and not res.get("duplicate"):
                saved += 1
                row = res.get("row") or org
                row["id"] = res.get("id")
                yield {"type": "log", "level": "saved", "message": f"Сохранён (без контакта): {org.get('name', '')}"}
                yield {"type": "medium", "data": row, "count": cnt_medium}
                existing_ids.add(org.get("external_id", ""))
            else:
                yield {"type": "medium", "name": org.get("name", ""), "reason": "нет контакта", "count": cnt_medium}
        else:
            res = _tool_save_prospect(
                name=org.get("name", ""),
                address=org.get("address"),
                phone=org.get("phone"),
                website=org.get("website"),
                source_url=org.get("source_url"),
                source=source,
                external_id=org.get("external_id"),
                user_id=user_id,
            )
            if res.get("ok") and not res.get("duplicate"):
                saved += 1
                row = res.get("row") or org
                row["id"] = res.get("id")
                yield {"type": "log", "level": "saved", "message": f"Сохранён: {org.get('name', '')}"}
                yield {"type": "suitable", "data": row}
                existing_ids.add(org.get("external_id", ""))

    yield _step("done", "Поиск завершён", f"Подходящих: {saved}, без контакта: {cnt_medium}, неподходящих: {cnt_unsuitable}")
    yield {"type": "done", "suitable": saved, "medium": cnt_medium, "unsuitable": cnt_unsuitable}


def register_routes(app: Flask, api_base: str) -> None:
    @app.get(f"{api_base}/crm/search-prospects")
    @_require_crm_access
    def crm_search_prospects_list():
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                """SELECT id, name, address, phone, website, map_2gis_url, source, status, notes, created_at,
                          lead_status_id, is_archived, archived_at, archive_comment, converted_to_lead_at, branch_id
                   FROM crm_prospect_kindergartens ORDER BY created_at DESC LIMIT 500""",
            )
            for r in rows:
                if r.get("created_at"):
                    r["created_at"] = r["created_at"].isoformat()
                if r.get("archived_at"):
                    r["archived_at"] = r["archived_at"].isoformat()
                if r.get("converted_to_lead_at"):
                    r["converted_to_lead_at"] = r["converted_to_lead_at"].isoformat()
        return Response(json.dumps({"ok": True, "items": rows}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.patch(f"{api_base}/crm/search-prospects/<int:prospect_id>")
    @_require_crm_access
    def crm_search_prospects_update(prospect_id: int):
        u = getattr(g, "current_user", None) or get_current_user()
        body = request.get_json(silent=True) or {}
        updates = []
        params: list[Any] = []
        limits = {"name": 255, "address": 512, "phone": 128, "website": 512, "notes": 2000}
        for key in ("name", "address", "phone", "website", "notes"):
            if key in body:
                updates.append(f"{key}=%s")
                params.append(str(body.get(key) or "")[: limits[key]])
        new_lead_status_id = body.get("lead_status_id")
        if new_lead_status_id is not None:
            try:
                new_lead_status_id = int(new_lead_status_id)
            except (TypeError, ValueError):
                abort(400, description="lead_status_id must be integer")
            updates.append("lead_status_id=%s")
            params.append(new_lead_status_id)
        if not updates:
            abort(400, description="Укажите хотя бы одно поле")
        with db_cursor() as (_, cur):
            row_old = fetch_one(cur, "SELECT lead_status_id, converted_to_lead_at FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if not row_old:
                abort(404)
            if new_lead_status_id is not None:
                from_status_id = row_old.get("lead_status_id")
                if row_old.get("converted_to_lead_at") is None:
                    updates.append("converted_to_lead_at=CURRENT_TIMESTAMP")
                cur.execute(
                    "INSERT INTO crm_prospect_status_history (prospect_id, from_status_id, to_status_id, user_id) VALUES (%s,%s,%s,%s)",
                    (prospect_id, from_status_id, new_lead_status_id, u.id),
                )
            params.append(prospect_id)
            cur.execute(f"UPDATE crm_prospect_kindergartens SET {', '.join(updates)} WHERE id=%s", tuple(params))
            row = fetch_one(cur, "SELECT id, name, address, phone, website, map_2gis_url, notes, status, created_at, lead_status_id, is_archived, archived_at, archive_comment, converted_to_lead_at, branch_id FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if row:
                for dt in ("created_at", "archived_at", "converted_to_lead_at"):
                    if row.get(dt) and hasattr(row[dt], "isoformat"):
                        row[dt] = row[dt].isoformat()
        return Response(json.dumps({"ok": True, "data": row}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.delete(f"{api_base}/crm/search-prospects/<int:prospect_id>")
    @_require_crm_access
    def crm_search_prospects_delete(prospect_id: int):
        with db_cursor() as (_, cur):
            if not fetch_one(cur, "SELECT 1 FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,)):
                abort(404)
            cur.execute("DELETE FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
        return Response(json.dumps({"ok": True}), content_type="application/json; charset=utf-8")

    # --- Лиды: статусы (таблица crm_lead_statuses), канбан, архив, история, комментарии ---
    @app.get(f"{api_base}/crm/lead-statuses")
    @_require_crm_access
    def crm_lead_statuses_list():
        with db_cursor() as (_, cur):
            rows = fetch_all(cur, "SELECT id, name, sort_order, is_system FROM crm_lead_statuses ORDER BY sort_order, id")
        return Response(json.dumps({"ok": True, "items": rows}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.post(f"{api_base}/crm/lead-statuses")
    @_require_crm_access
    def crm_lead_status_create():
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        if not name:
            abort(400, description="name is required")
        sort_order = body.get("sort_order")
        if sort_order is None:
            sort_order = 50
        sort_order = int(sort_order)
        with db_cursor() as (_, cur):
            sid = exec_one(cur, "INSERT INTO crm_lead_statuses (name, sort_order, is_system) VALUES (%s,%s,0)", (name[:128], sort_order))
            row = fetch_one(cur, "SELECT id, name, sort_order, is_system FROM crm_lead_statuses WHERE id=%s", (sid,))
        return Response(json.dumps({"ok": True, "data": row}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.patch(f"{api_base}/crm/lead-statuses/<int:status_id>")
    @_require_crm_access
    def crm_lead_status_update(status_id: int):
        body = request.get_json(silent=True) or {}
        with db_cursor() as (_, cur):
            row = fetch_one(cur, "SELECT id, name, sort_order, is_system FROM crm_lead_statuses WHERE id=%s", (status_id,))
            if not row:
                abort(404)
            updates = []
            params: list[Any] = []
            if "name" in body:
                name = (body.get("name") or "").strip()
                if not name:
                    abort(400, description="name cannot be empty")
                updates.append("name=%s")
                params.append(name[:128])
            if "sort_order" in body:
                updates.append("sort_order=%s")
                params.append(int(body.get("sort_order")))
            if not updates:
                abort(400, description="No fields to update")
            params.append(status_id)
            cur.execute(f"UPDATE crm_lead_statuses SET {', '.join(updates)} WHERE id=%s", tuple(params))
            row = fetch_one(cur, "SELECT id, name, sort_order, is_system FROM crm_lead_statuses WHERE id=%s", (status_id,))
        return Response(json.dumps({"ok": True, "data": row}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.delete(f"{api_base}/crm/lead-statuses/<int:status_id>")
    @_require_crm_access
    def crm_lead_status_delete(status_id: int):
        with db_cursor() as (_, cur):
            row = fetch_one(cur, "SELECT id, is_system FROM crm_lead_statuses WHERE id=%s", (status_id,))
            if not row:
                abort(404)
            if row.get("is_system") == 1:
                abort(400, description="Системный статус нельзя удалить (Отказ, Взят в работу, Сотрудничество, Архив)")
            n = fetch_one(cur, "SELECT COUNT(*) AS n FROM crm_prospect_kindergartens WHERE lead_status_id=%s", (status_id,))
            if n and int(n.get("n") or 0) > 0:
                abort(400, description="Есть лиды с этим статусом; сначала переназначьте их")
            cur.execute("DELETE FROM crm_lead_statuses WHERE id=%s", (status_id,))
        return Response(json.dumps({"ok": True}), content_type="application/json; charset=utf-8")

    @app.get(f"{api_base}/crm/leads")
    @_require_crm_access
    def crm_leads_list():
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                """SELECT id, name, address, phone, website, map_2gis_url, notes, lead_status_id, converted_to_lead_at, branch_id
                   FROM crm_prospect_kindergartens
                   WHERE lead_status_id IS NOT NULL AND (is_archived = 0 OR is_archived IS NULL)
                   ORDER BY converted_to_lead_at DESC, id DESC LIMIT 500""",
            )
            for r in rows:
                if r.get("converted_to_lead_at") and hasattr(r["converted_to_lead_at"], "isoformat"):
                    r["converted_to_lead_at"] = r["converted_to_lead_at"].isoformat()
        return Response(json.dumps({"ok": True, "items": rows}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.get(f"{api_base}/crm/leads/archive")
    @_require_crm_access
    def crm_leads_archive_list():
        with db_cursor() as (_, cur):
            rows = fetch_all(
                cur,
                """SELECT id, name, address, phone, website, notes, lead_status_id, archived_at, archive_comment
                   FROM crm_prospect_kindergartens
                   WHERE is_archived = 1
                   ORDER BY archived_at DESC LIMIT 500""",
            )
            for r in rows:
                if r.get("archived_at") and hasattr(r["archived_at"], "isoformat"):
                    r["archived_at"] = r["archived_at"].isoformat()
        return Response(json.dumps({"ok": True, "items": rows}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.post(f"{api_base}/crm/search-prospects/<int:prospect_id>/to-lead")
    @_require_crm_access
    def crm_prospect_to_lead(prospect_id: int):
        u = getattr(g, "current_user", None) or get_current_user()
        with db_cursor() as (_, cur):
            default_status = fetch_one(cur, "SELECT id FROM crm_lead_statuses WHERE name='Взят в работу' AND is_system=1 LIMIT 1")
            if not default_status:
                abort(500, description="Статус «Взят в работу» не найден в crm_lead_statuses")
            default_status_id = int(default_status["id"])
            row = fetch_one(cur, "SELECT id, lead_status_id FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if not row:
                abort(404)
            if row.get("lead_status_id") is not None:
                abort(400, description="Уже перенесён в лиды")
            cur.execute(
                "INSERT INTO crm_prospect_status_history (prospect_id, from_status_id, to_status_id, user_id) VALUES (%s,NULL,%s,%s)",
                (prospect_id, default_status_id, u.id),
            )
            cur.execute(
                "UPDATE crm_prospect_kindergartens SET lead_status_id=%s, converted_to_lead_at=CURRENT_TIMESTAMP WHERE id=%s",
                (default_status_id, prospect_id),
            )
            row = fetch_one(cur, "SELECT id, name, address, phone, website, map_2gis_url, notes, lead_status_id, converted_to_lead_at, branch_id FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if row and row.get("converted_to_lead_at"):
                row["converted_to_lead_at"] = row["converted_to_lead_at"].isoformat()
        return Response(json.dumps({"ok": True, "data": row}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.post(f"{api_base}/crm/leads/<int:prospect_id>/archive")
    @_require_crm_access
    def crm_lead_archive(prospect_id: int):
        body = request.get_json(silent=True) or {}
        comment = (body.get("comment") or "").strip()[:2000]
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT 1 FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if not ok:
                abort(404)
            cur.execute(
                "UPDATE crm_prospect_kindergartens SET is_archived=1, archived_at=CURRENT_TIMESTAMP, archive_comment=%s WHERE id=%s",
                (comment, prospect_id),
            )
        return Response(json.dumps({"ok": True}), content_type="application/json; charset=utf-8")

    @app.post(f"{api_base}/crm/leads/<int:prospect_id>/restore")
    @_require_crm_access
    def crm_lead_restore(prospect_id: int):
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT 1 FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if not ok:
                abort(404)
            cur.execute(
                "UPDATE crm_prospect_kindergartens SET is_archived=0, archived_at=NULL, archive_comment=NULL WHERE id=%s",
                (prospect_id,),
            )
        return Response(json.dumps({"ok": True}), content_type="application/json; charset=utf-8")

    @app.get(f"{api_base}/crm/search-prospects/<int:prospect_id>/history")
    @_require_crm_access
    def crm_prospect_history(prospect_id: int):
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT 1 FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if not ok:
                abort(404)
            rows = fetch_all(
                cur,
                """SELECT h.id, h.from_status_id, h.to_status_id, h.created_at, u.login AS user_login,
                          fs.name AS from_status_name, ts.name AS to_status_name
                   FROM crm_prospect_status_history h
                   LEFT JOIN auf_users u ON u.id = h.user_id
                   LEFT JOIN crm_lead_statuses fs ON fs.id = h.from_status_id
                   LEFT JOIN crm_lead_statuses ts ON ts.id = h.to_status_id
                   WHERE h.prospect_id = %s ORDER BY h.created_at ASC""",
                (prospect_id,),
            )
            for r in rows:
                if r.get("created_at") and hasattr(r["created_at"], "isoformat"):
                    r["created_at"] = r["created_at"].isoformat()
        return Response(json.dumps({"ok": True, "items": rows}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.get(f"{api_base}/crm/search-prospects/<int:prospect_id>/comments")
    @_require_crm_access
    def crm_prospect_comments_list(prospect_id: int):
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT 1 FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if not ok:
                abort(404)
            rows = fetch_all(
                cur,
                """SELECT c.id, c.user_id, c.message, c.created_at, u.login AS user_login
                   FROM crm_prospect_comments c
                   JOIN auf_users u ON u.id = c.user_id
                   WHERE c.prospect_id = %s ORDER BY c.created_at ASC""",
                (prospect_id,),
            )
            for r in rows:
                if r.get("created_at") and hasattr(r["created_at"], "isoformat"):
                    r["created_at"] = r["created_at"].isoformat()
        return Response(json.dumps({"ok": True, "items": rows}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.post(f"{api_base}/crm/search-prospects/<int:prospect_id>/comments")
    @_require_crm_access
    def crm_prospect_comment_add(prospect_id: int):
        u = getattr(g, "current_user", None) or get_current_user()
        body = request.get_json(silent=True) or {}
        message = (body.get("message") or "").strip()
        if not message:
            abort(400, description="message is required")
        if len(message) > 10000:
            abort(400, description="message too long")
        with db_cursor() as (_, cur):
            ok = fetch_one(cur, "SELECT 1 FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if not ok:
                abort(404)
            exec_one(cur, "INSERT INTO crm_prospect_comments (prospect_id, user_id, message) VALUES (%s,%s,%s)", (prospect_id, u.id, message))
            row = fetch_one(cur, "SELECT id, user_id, message, created_at FROM crm_prospect_comments WHERE prospect_id=%s ORDER BY id DESC LIMIT 1", (prospect_id,))
            if row and row.get("created_at"):
                row["created_at"] = row["created_at"].isoformat()
            row["user_login"] = u.login if getattr(u, "login", None) else None
        return Response(json.dumps({"ok": True, "data": row}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.post(f"{api_base}/crm/leads/<int:prospect_id>/create-branch")
    @_require_crm_access
    def crm_lead_create_branch(prospect_id: int):
        u = getattr(g, "current_user", None) or get_current_user()
        owner_id = getattr(u, "owner_id", None)
        if not owner_id:
            abort(403, description="Only owner can create branch")
        body = request.get_json(silent=True) or {}
        department_id = body.get("department_id")
        price = body.get("price_per_child")
        if department_id is None or price is None:
            abort(400, description="department_id and price_per_child are required")
        department_id = int(department_id)
        price = float(price)
        with db_cursor() as (_, cur):
            coop = fetch_one(cur, "SELECT id FROM crm_lead_statuses WHERE name='Сотрудничество' AND is_system=1 LIMIT 1")
            if not coop:
                abort(500, description="Статус «Сотрудничество» не найден")
            prospect = fetch_one(cur, "SELECT id, name, address, phone, website, lead_status_id, branch_id FROM crm_prospect_kindergartens WHERE id=%s", (prospect_id,))
            if not prospect:
                abort(404)
            if prospect.get("lead_status_id") != int(coop["id"]):
                abort(400, description="Создать филиал можно только из лида со статусом «Сотрудничество»")
            if prospect.get("branch_id"):
                abort(400, description="Филиал уже создан для этого лида")
            ok = fetch_one(cur, "SELECT 1 FROM department_owners WHERE department_id=%s AND owner_id=%s", (department_id, owner_id))
            if not ok:
                abort(403, description="No access to department")
            name = (body.get("name") or (prospect.get("name") or "")).strip() or "Филиал"
            address = (body.get("address") or (prospect.get("address") or "")).strip() or "—"
            metro = (body.get("metro") or "").strip() or None
            teacher_base_rate = body.get("teacher_base_rate")
            if teacher_base_rate is None:
                teacher_base_rate = 1200
            teacher_base_rate = int(teacher_base_rate)
            bid = exec_one(
                cur,
                "INSERT INTO branches (department_id, name, address, metro, price_per_child, is_active, teacher_base_rate) VALUES (%s,%s,%s,%s,%s,1,%s)",
                (department_id, name[:255], address[:512], metro, price, teacher_base_rate),
            )
            cur.execute("UPDATE crm_prospect_kindergartens SET branch_id=%s WHERE id=%s", (bid, prospect_id))
            try:
                exec_one(cur, "INSERT INTO crm_branches (branch_id) VALUES (%s)", (bid,))
            except Exception:
                pass
            row = fetch_one(cur, "SELECT * FROM branches WHERE id=%s", (bid,))
        return Response(json.dumps({"ok": True, "data": row}, ensure_ascii=False), content_type="application/json; charset=utf-8")

    @app.post(f"{api_base}/crm/search-prospects/stop")
    @_require_crm_access
    def crm_search_prospects_stop():
        u = getattr(g, "current_user", None) or get_current_user()
        with _search_stop_lock:
            _search_stop_flags[u.id] = True
        return Response(json.dumps({"ok": True}), content_type="application/json; charset=utf-8")

    @app.get(f"{api_base}/crm/search-prospects/stream")
    @_require_crm_access
    def crm_search_prospects_stream():
        u = getattr(g, "current_user", None) or get_current_user()
        with _search_stop_lock:
            _search_stop_flags[u.id] = False

        def stream_gen():
            for ev in _run_search_agent(u.id, lambda: _search_stop_flags.get(u.id, False)):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"

        return Response(
            stream_with_context(stream_gen()),
            mimetype="text/event-stream; charset=utf-8",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
