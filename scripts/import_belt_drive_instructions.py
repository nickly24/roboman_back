#!/usr/bin/env python3
"""
Импорт инструкций по блоку «Ремённая передача» в таблицу instructions.

Что делает скрипт:
- читает описание из about.txt в папке блока;
- находит/создаёт раздел (instruction_sections) с именем «Ремённая передача»;
- проходит по всем PDF-файлам в этой папке;
- для каждого PDF:
  - берёт имя файла (без .pdf) как название инструкции;
  - формирует описание: текст из about.txt + упоминание конкретной модели;
  - рендерит первую страницу PDF в JPEG (превью);
  - создаёт или обновляет запись в таблице instructions:
    - pdf_blob / pdf_filename / pdf_mime
    - photo_blob / photo_filename / photo_mime

Зависимости:
  pip install pymupdf

Переменные окружения БД:
  DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
  (те же, что и для основного backend).

Запуск (из каталога backend):
  PYTHONPATH=. python scripts/import_belt_drive_instructions.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional
import argparse

import fitz  # type: ignore  # PyMuPDF

# Подключаем shared (БД) из backend, как в других скриптах
sys.path.insert(0, str(__file__).rsplit("/backend/", 1)[0] + "/backend")
from shared import db_cursor, exec_one, fetch_one  # type: ignore


def log(msg: str) -> None:
    print(msg, flush=True)


def read_about_text(about_file: Path) -> str:
    if not about_file.exists():
        log(f"[WARN] Файл описания не найден: {about_file}")
        return ""
    text = about_file.read_text(encoding="utf-8", errors="ignore").strip()
    return text


def ensure_section(section_name: str, description: str) -> int:
    """Находим или создаём запись в instruction_sections и возвращаем id."""
    with db_cursor() as (_, cur):
        row = fetch_one(
            cur,
            "SELECT id FROM instruction_sections WHERE name=%s",
            (section_name,),
        )
        if row and "id" in row:
            section_id = int(row["id"])
            log(f"[INFO] Раздел уже существует: id={section_id}, name={section_name!r}")
            return section_id

        section_id = exec_one(
            cur,
            "INSERT INTO instruction_sections(name, description) VALUES (%s,%s)",
            (section_name, description or None),
        )
        log(f"[INFO] Создан новый раздел: id={section_id}, name={section_name!r}")
        return int(section_id)


def render_first_page_preview(pdf_path: Path) -> bytes:
    """Рендер первой страницы PDF в JPEG-байты."""
    doc = fitz.open(pdf_path.as_posix())
    if doc.page_count == 0:
        raise RuntimeError(f"PDF без страниц: {pdf_path}")
    page = doc.load_page(0)
    # dpi можно подправить при необходимости (качество/размер)
    pix = page.get_pixmap(dpi=150)
    img_bytes = pix.tobytes("jpeg")
    doc.close()
    return img_bytes


def load_pdf_bytes(pdf_path: Path) -> bytes:
    return pdf_path.read_bytes()


def make_instruction_name_from_filename(pdf_path: Path) -> str:
    name = pdf_path.stem
    # Убираем лишние пробелы
    return name.strip()


def make_instruction_description(base_about: str, model_name: str) -> str:
    base_about = (base_about or "").strip()
    extra = f"Модель: {model_name}"
    if base_about:
        return f"{base_about}\n\n{extra}"
    return extra


def upsert_instruction(
    section_id: int,
    name: str,
    description: str,
    pdf_filename: str,
    pdf_bytes: bytes,
    photo_filename: str,
    photo_bytes: bytes,
    pdf_mime: str = "application/pdf",
    photo_mime: str = "image/jpeg",
) -> int:
    """
    Если инструкция с таким (section_id, name) уже есть — обновляем,
    иначе создаём новую. Возвращаем id инструкции.
    """
    with db_cursor() as (_, cur):
        existing = fetch_one(
            cur,
            "SELECT id FROM instructions WHERE section_id=%s AND name=%s",
            (section_id, name),
        )
        if existing and "id" in existing:
            instr_id = int(existing["id"])
            log(f"[INFO] Обновляем существующую инструкцию id={instr_id}, name={name!r}")
            cur.execute(
                """
                UPDATE instructions
                SET
                  description=%s,
                  photo_filename=%s,
                  photo_mime=%s,
                  photo_blob=%s,
                  pdf_filename=%s,
                  pdf_mime=%s,
                  pdf_blob=%s
                WHERE id=%s
                """,
                (
                    description or None,
                    photo_filename,
                    photo_mime,
                    photo_bytes,
                    pdf_filename,
                    pdf_mime,
                    pdf_bytes,
                    instr_id,
                ),
            )
            return instr_id

        log(f"[INFO] Создаём новую инструкцию name={name!r}")
        instr_id = exec_one(
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
                section_id,
                name,
                description or None,
                photo_filename,
                photo_mime,
                photo_bytes,
                pdf_filename,
                pdf_mime,
                pdf_bytes,
            ),
        )
        return int(instr_id)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Импорт PDF-инструкций из папки блока в таблицу instructions"
    )
    parser.add_argument(
        "--block-dir",
        type=str,
        default="/Users/nickly/Documents/сет нью/2 БЛОК. Ремённая передача",
        help="Путь к папке с блоком (где лежат about.txt и PDF-файлы)",
    )
    parser.add_argument(
        "--section-name",
        type=str,
        default=None,
        help="Имя раздела в instruction_sections. "
        "Если не указано — берём первую строку из about.txt, "
        "а если её нет, то имя папки.",
    )
    args = parser.parse_args()

    block_dir = Path(args.block_dir).expanduser()
    about_file = block_dir / "about.txt"

    if not block_dir.exists():
        log(f"[ERROR] Папка блока не найдена: {block_dir}")
        sys.exit(1)

    about_text = read_about_text(about_file)

    # Определяем имя раздела
    section_name: str
    if args.section_name:
        section_name = args.section_name
    else:
        first_line = (about_text.splitlines() or [""])[0].strip() if about_text else ""
        if first_line:
            section_name = first_line
        else:
            section_name = block_dir.name.strip()

    log(f"[INFO] Папка блока: {block_dir}")
    log(f"[INFO] Раздел: {section_name!r}")

    section_id = ensure_section(section_name, about_text)

    pdf_files = sorted(block_dir.glob("*.pdf"))
    if not pdf_files:
        log(f"[WARN] В папке {block_dir} не найдено PDF-файлов")
        return

    total_files = len(pdf_files)
    log(f"[INFO] Найдено {total_files} PDF-файлов в {block_dir}")

    processed = 0
    errors = 0

    for idx, pdf_path in enumerate(pdf_files, start=1):
        try:
            percent = int(idx * 100 / total_files)
            log(f"[INFO] ({idx}/{total_files}, {percent}%) Обработка файла: {pdf_path.name}")
            name = make_instruction_name_from_filename(pdf_path)
            description = make_instruction_description(about_text, name)

            pdf_bytes = load_pdf_bytes(pdf_path)
            photo_bytes = render_first_page_preview(pdf_path)

            photo_filename = f"{pdf_path.stem}.jpg"

            instr_id = upsert_instruction(
                section_id=section_id,
                name=name,
                description=description,
                pdf_filename=pdf_path.name,
                pdf_bytes=pdf_bytes,
                photo_filename=photo_filename,
                photo_bytes=photo_bytes,
            )

            log(f"[OK] Инструкция id={instr_id} успешно сохранена/обновлена")
            processed += 1
        except Exception as e:
            errors += 1
            log(f"[ERROR] Ошибка при обработке {pdf_path.name}: {e!r}")

    log(f"[DONE] Обработано успешно: {processed}, с ошибками: {errors} (всего файлов: {total_files})")


if __name__ == "__main__":
    main()

