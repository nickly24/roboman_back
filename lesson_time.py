"""Lesson starts_at is a literal local datetime, with no UTC conversion."""

import re
from datetime import datetime


def parse_lesson_time(value: object) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?", value
    ):
        raise ValueError(
            "Дата и время занятия должны быть без часового пояса "
            "(ГГГГ-ММ-ДДTЧЧ:ММ). Обновите страницу и укажите время заново."
        )
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("Укажите корректные дату и время занятия.") from None
