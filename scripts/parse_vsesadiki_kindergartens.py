#!/usr/bin/env python3
"""
Парсинг детских садов с https://www.vsesadiki.ru/ и занесение в crm_prospect_kindergartens
с детальными логами.

Зависимости: pip install beautifulsoup4 (requests уже в requirements).
Переменные окружения БД: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME (как у backend).

Запуск из каталога backend:
  PYTHONPATH=. python scripts/parse_vsesadiki_kindergartens.py

По умолчанию стартуем с главной страницы сайта и пытаемся найти ссылки на
страницы с детскими садами, а уже оттуда — ссылки на конкретные садики.
Верстка сайта может меняться, поэтому селекторы могут потребовать
минимальной ручной подстройки после первого запуска.
"""
from __future__ import annotations

import hashlib
import re
import sys
import time
from collections import deque
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Подключаем shared (БД) из backend
sys.path.insert(0, str(__file__).rsplit("/backend/", 1)[0] + "/backend")
from shared import db_cursor, exec_one, fetch_one  # type: ignore


BASE_URL = "https://www.vsesadiki.ru/"
SOURCE = "vsesadiki"

# Ограничения, чтобы случайно не устроить DDoS
MAX_PAGES_TO_VISIT = 200
MAX_ORGS_TO_SAVE = 2000
REQUEST_TIMEOUT = 15
SLEEP_BETWEEN_REQUESTS = 0.5


@dataclass
class Stats:
    visited_pages: int = 0
    org_candidates: int = 0
    saved: int = 0
    duplicates: int = 0
    skipped: int = 0
    errors: int = 0


def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")


def is_same_domain(url: str, base: str = BASE_URL) -> bool:
    try:
        d1 = urlparse(url).netloc or urlparse(base).netloc
        d2 = urlparse(base).netloc
        return d1 == d2 or d1.endswith("." + d2)
    except Exception:
        return False


def is_state_or_school(name: str) -> bool:
    """Фильтрация гос. садов/школ (та же логика, что и в spravker-скрипте)."""
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


def extract_org_links_from_page(html: str, page_url: str) -> list[str]:
    """
    Пытаемся вытащить ссылки на конкретные садики.

    Стратегия «по умолчанию»:
    - ищем <a>, в тексте которых фигурирует «детский сад», «садик» и т.п.
    - фильтруем по домену и уникальности.

    При необходимости можно сузить селекторы под реальную вёрстку карточек.
    """
    soup = BeautifulSoup(html, "html.parser")
    links: list[str] = []
    seen: set[str] = set()

    for a in soup.find_all("a", href=True):
        text = (a.get_text() or "").strip()
        if not text:
            continue
        low = text.lower()
        if not any(kw in low for kw in ("детский сад", "детсад", "садик")):
            continue
        href = a["href"]
        full = urljoin(page_url, href)
        if not is_same_domain(full):
            continue
        # Отсекаем совсем служебные/якорные ссылки
        if full in seen:
            continue
        seen.add(full)
        links.append(full)

    return links


def parse_org_page(html: str, url: str) -> dict | None:
    """
    Из страницы конкретного садика достаём name / address / phone / website.

    Селекторы сделаны максимально нейтрально на основе типовой вёрстки каталогов:
    - name: <h1> или <h1 class*=\"title\">
    - address: элементы с классами, содержащими \"addr\" или текстом «Адрес»
    - phone: ссылки tel:, либо элементы с текстом «Телефон»
    - website: ссылки с http/https вне домена vsesadiki.ru

    При необходимости можно подправить под фактическую разметку.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Название
    name_el = soup.find("h1")
    if not name_el:
        name_el = soup.find("h1", class_=re.compile("title", re.I))
    name = (name_el.get_text() or "").strip() if name_el else ""
    if not name:
        return None

    # Адрес
    address = None
    # 1) элементы с классом, содержащим addr
    addr_el = soup.find(attrs={"class": re.compile("addr", re.I)})
    if addr_el:
        address = (addr_el.get_text() or "").strip()
    if not address:
        # 2) по label'у «Адрес»
        for lbl in soup.find_all(text=re.compile("Адрес", re.I)):
            parent = lbl.parent
            if not parent:
                continue
            # берём соседний текст/элемент
            sib = parent.find_next_sibling()
            if sib:
                address = (sib.get_text() or "").strip()
                if address:
                    break

    # Телефон
    phone = None
    # 1) ссылки tel:
    tel_link = soup.find("a", href=re.compile("^tel:", re.I))
    if tel_link and tel_link.get("href"):
        phone = re.sub(r"^tel:", "", tel_link["href"]).strip()
    if not phone:
        # 2) по label'у «Телефон»
        for lbl in soup.find_all(text=re.compile("Телефон", re.I)):
            parent = lbl.parent
            if not parent:
                continue
            sib = parent.find_next_sibling()
            if sib:
                txt = (sib.get_text() or "").strip()
                if txt:
                    phone = txt
                    break

    # Сайт: ищем внешние ссылки (не vsesadiki.ru)
    website = None
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href.startswith("http"):
            continue
        if "vsesadiki.ru" in urlparse(href).netloc:
            continue
        website = href
        break

    return {
        "name": name[:255],
        "address": (address or "")[:512] or None,
        "phone": (phone or "")[:128] or None,
        "website": (website or "")[:512] or None,
        "source_url": url[:512],
    }


def save_prospect(row: dict) -> tuple[bool, str]:
    """Вставляет запись в БД. Возвращает (ok, 'saved'|'duplicate'|'skip')."""
    name = row["name"]
    if is_state_or_school(name):
        return False, "skip"
    source_url = row.get("source_url") or row.get("website") or ""
    external_id = make_external_id(name, source_url)
    with db_cursor() as (_, cur):
        if fetch_one(
            cur,
            "SELECT 1 FROM crm_prospect_kindergartens WHERE source=%s AND external_id=%s",
            (SOURCE, external_id),
        ):
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


def fetch(url: str) -> str | None:
    try:
        log(f"HTTP GET {url}")
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RoboMan/1.0; +https://www.vsesadiki.ru/)"},
        )
        r.raise_for_status()
        return r.text
    except Exception as e:
        log(f"  ! Ошибка запроса {url}: {e}")
        return None


def crawl(start_urls: Iterable[str]) -> Stats:
    stats = Stats()
    visited: set[str] = set()
    org_urls: set[str] = set()
    q: deque[str] = deque()

    for u in start_urls:
        full = urljoin(BASE_URL, u)
        q.append(full)

    log("Старт обхода vsesadiki.ru")
    log(f"Начальные URL: {list(q)}")
    log(f"Лимиты: страниц={MAX_PAGES_TO_VISIT}, организаций={MAX_ORGS_TO_SAVE}")
    log("---")

    while q and stats.visited_pages < MAX_PAGES_TO_VISIT and len(org_urls) < MAX_ORGS_TO_SAVE:
        url = q.popleft()
        if url in visited:
            continue
        visited.add(url)
        stats.visited_pages += 1

        html = fetch(url)
        if html is None:
            stats.errors += 1
            continue

        # 1) с текущей страницы собираем ссылки на садики
        org_links = extract_org_links_from_page(html, url)
        new_org = 0
        for ou in org_links:
            if ou not in org_urls:
                org_urls.add(ou)
                new_org += 1
        stats.org_candidates += new_org
        log(f"Страница {stats.visited_pages}: найдено ссылок на сады: {len(org_links)} (новых: {new_org}, всего уникальных садов: {len(org_urls)})")

        # 2) добавляем в очередь ещё страницы того же домена (ограниченно)
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full = urljoin(url, href)
            if not is_same_domain(full):
                continue
            # небольшое ограничение по глубине: не ходим по якорям и параметрам фильтров
            if "#" in full:
                continue
            if full not in visited:
                q.append(full)

        time.sleep(SLEEP_BETWEEN_REQUESTS)

    log("---")
    log(f"Обход страниц завершён. Всего посещено страниц: {stats.visited_pages}, всего уникальных URL садов: {len(org_urls)}")

    # Теперь обходим сами страницы садов и сохраняем в БД
    for i, org_url in enumerate(sorted(org_urls), start=1):
        if stats.saved >= MAX_ORGS_TO_SAVE:
            log("Достигнут лимит по количеству организаций, остановка сохранения.")
            break
        html = fetch(org_url)
        if html is None:
            stats.errors += 1
            continue
        row = parse_org_page(html, org_url)
        if not row:
            stats.skipped += 1
            log(f"[{i}/{len(org_urls)}] Пропуск: не удалось распарсить страницу сада {org_url}")
            continue
        try:
            ok, status = save_prospect(row)
            if status == "saved":
                stats.saved += 1
                log(f"[{i}/{len(org_urls)}] + Сохранён: {row['name'][:80]}")
            elif status == "duplicate":
                stats.duplicates += 1
                log(f"[{i}/{len(org_urls)}] = Дубликат: {row['name'][:80]}")
            else:
                stats.skipped += 1
                log(f"[{i}/{len(org_urls)}] ~ Пропущен по фильтру: {row['name'][:80]}")
        except Exception as e:
            stats.errors += 1
            log(f"[{i}/{len(org_urls)}] ! Ошибка при сохранении {row.get('name', '')[:80]}: {e}")

        time.sleep(SLEEP_BETWEEN_REQUESTS)

    return stats


def main() -> None:
    # Можно передать стартовые URL аргументами командной строки, иначе берём главную
    start_urls = sys.argv[1:] or [BASE_URL]
    log("Парсер vsesadiki.ru запущен")
    stats = crawl(start_urls)
    log("---")
    log(
        "ИТОГО: сохранено={saved}, дубликатов={dup}, пропущено={skipped}, "
        "ошибок={errors}, посещено_страниц={pages}, кандидатов_садов={cands}".format(
            saved=stats.saved,
            dup=stats.duplicates,
            skipped=stats.skipped,
            errors=stats.errors,
            pages=stats.visited_pages,
            cands=stats.org_candidates,
        )
    )


if __name__ == "__main__":
    main()

