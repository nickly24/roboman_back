#!/usr/bin/env python3
"""
Парсинг частных детских садов с msk.spravker.ru и занесение в crm_prospect_kindergartens.

Зависимости: pip install beautifulsoup4 (requests уже в requirements).
Переменные окружения БД: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME (как у backend).

Запуск из каталога backend:
  PYTHONPATH=. python scripts/parse_spravker_kindergartens.py
Или из корня проекта:
  cd backend && PYTHONPATH=. python scripts/parse_spravker_kindergartens.py
"""
from __future__ import annotations

import base64
import hashlib
import re
import sys
import time
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# Подключаем shared (БД) из backend
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shared import db_cursor, exec_one, fetch_one

BASE_URL = "https://msk.spravker.ru"
LIST_URL = f"{BASE_URL}/chastnye-detskie-sady/"
SOURCE = "spravker"


def is_state_or_school(name: str) -> bool:
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


def make_external_id(name: str, url: str) -> str:
    return hashlib.md5(f"{name}|{url}".encode()).hexdigest()


def parse_page(html: str) -> list[dict]:
    """Из одной HTML-страницы вытаскивает список карточек: name, address, phone, website, source_url."""
    soup = BeautifulSoup(html, "html.parser")
    items = []
    for block in soup.select("div.widgets-list__item div.org-widget"):
        title_el = block.select_one("a.org-widget-header__title-link")
        if not title_el:
            continue
        name = (title_el.get_text() or "").strip()
        href = title_el.get("href") or ""
        source_url = (BASE_URL + href) if href.startswith("/") else href

        location_el = block.select_one("span.org-widget-header__meta--location")
        address = (location_el.get_text() or "").strip() if location_el else None

        phone = None
        website = None
        for dl in block.select("div.org-widget__spec dl.spec"):
            label_el = dl.select_one("dt.spec__index span.spec__index-inner")
            value_el = dl.select_one("dd.spec__value")
            if not label_el or not value_el:
                continue
            label = (label_el.get_text() or "").strip()
            if "телефон" in label.lower():
                phone = (value_el.get_text() or "").strip() or None
            elif "сайт" in label.lower():
                pseudo = value_el.select_one("span.js-pseudo-link[data-url]")
                if pseudo and pseudo.get("data-url"):
                    try:
                        website = base64.b64decode(pseudo["data-url"]).decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                if not website and value_el.get_text():
                    website = (value_el.get_text() or "").strip() or None

        if not name:
            continue
        items.append({
            "name": name[:255],
            "address": (address or "")[:512] or None,
            "phone": (phone or "")[:128] or None,
            "website": (website or "")[:512] or None,
            "source_url": source_url[:512] if source_url else None,
        })
    return items


def save_prospect(row: dict) -> tuple[bool, str]:
    """Вставляет запись в БД. Возвращает (ok, 'saved'|'duplicate'|'skip')."""
    name = row["name"]
    if is_state_or_school(name):
        return False, "skip"
    source_url = row.get("source_url") or row.get("website") or ""
    external_id = make_external_id(name, source_url)
    with db_cursor() as (_, cur):
        if fetch_one(cur, "SELECT 1 FROM crm_prospect_kindergartens WHERE source=%s AND external_id=%s", (SOURCE, external_id)):
            return False, "duplicate"
        map_url = source_url or row.get("website") or ""
        exec_one(
            cur,
            """INSERT INTO crm_prospect_kindergartens
               (name, address, phone, website, map_2gis_url, source, external_id, created_by_user_id)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                name,
                row.get("address") or "",
                row.get("phone") or "",
                row.get("website") or "",
                map_url,
                SOURCE,
                external_id,
                None,  # created_by_user_id -> NULL, чтобы не ловить FK-ошибку
            ),
        )
    return True, "saved"


def main():
    max_pages = 5
    saved = 0
    duplicates = 0
    skipped = 0
    errors = 0

    print("Парсинг Spravker: частные детские сады Москвы")
    print("Источник:", LIST_URL)
    print("Страниц (макс.):", max_pages)
    print("---")

    for page in range(1, max_pages + 1):
        url = f"{LIST_URL}?page={page}" if page > 1 else LIST_URL
        try:
            r = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0 (compatible; RoboMan/1.0)"})
            r.raise_for_status()
        except Exception as e:
            print(f"Страница {page}: ошибка запроса — {e}")
            errors += 1
            break

        rows = parse_page(r.text)
        if not rows:
            print(f"Страница {page}: карточек не найдено, стоп.")
            break

        for row in rows:
            try:
                ok, status = save_prospect(row)
                if status == "saved":
                    saved += 1
                    print(f"  + {row['name'][:50]}")
                elif status == "duplicate":
                    duplicates += 1
                else:
                    skipped += 1
            except Exception as e:
                errors += 1
                print(f"  ! {row.get('name', '')[:40]} — {e}")

        print(f"Страница {page}: обработано {len(rows)} карточек (всего сохранено: {saved}, дубли: {duplicates}, пропуск: {skipped})")
        time.sleep(0.5)

    print("---")
    print("Готово. Сохранено:", saved, "Дубликатов:", duplicates, "Пропущено (гос/школа):", skipped, "Ошибок:", errors)


if __name__ == "__main__":
    main()
