from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

import mysql.connector  # type: ignore
from mysql.connector import pooling  # type: ignore

from backend import config


@dataclass(frozen=True)
class DbConfig:
    host: str
    user: str
    password: str
    database: str
    port: int = 3306


def load_db_config() -> DbConfig:
    return DbConfig(
        host=config.DB_HOST,
        user=config.DB_USER,
        password=config.DB_PASSWORD or "",
        database=config.DB_NAME,
        port=int(config.DB_PORT),
    )


_POOL: pooling.MySQLConnectionPool | None = None


def get_pool() -> pooling.MySQLConnectionPool:
    global _POOL
    if _POOL is None:
        cfg = load_db_config()
        _POOL = pooling.MySQLConnectionPool(
            pool_name="roboman_pool",
            pool_size=int(getattr(config, "DB_POOL_SIZE", 10)),
            host=cfg.host,
            user=cfg.user,
            password=cfg.password,
            database=cfg.database,
            port=cfg.port,
            autocommit=False,
        )
    return _POOL


@contextmanager
def db_cursor(*, dictionary: bool = True) -> Iterator[tuple[Any, Any]]:
    """
    Context manager returning (conn, cur).
    Commits on success, rollbacks on error.
    """
    pool = get_pool()
    conn = pool.get_connection()
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


def exec_many(cur: Any, sql: str, params_list: list[tuple[Any, ...]]) -> int:
    cur.executemany(sql, params_list)
    return int(getattr(cur, "rowcount", 0) or 0)

