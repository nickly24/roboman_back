"""Test lesson/help migration in a new disposable database on a local MySQL socket.

No application configuration, production credentials or remote hosts are used.
Example: python scripts/verify_lesson_help_mysql.py --socket /tmp/mysql-qa.sock
"""
from __future__ import annotations

import argparse
from decimal import Decimal
from pathlib import Path
import sys
import uuid

import mysql.connector

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.apply_migrations import _statements


MIGRATION = Path(__file__).resolve().parents[1] / "migrations/20260922_001_lesson_help_and_skip.sql"

# Only the dependency columns used by lesson constraints/triggers are needed here.
# The lessons definition retains the existing types, checks and FK actions.
BASELINE_SQL = """
CREATE TABLE settings (
  `key` VARCHAR(64) PRIMARY KEY, value_int BIGINT NULL, value_bool TINYINT(1) NULL,
  description VARCHAR(255) NULL
);
CREATE TABLE branches (
  id BIGINT UNSIGNED PRIMARY KEY,
  price_per_child DECIMAL(10,2) NOT NULL,
  teacher_base_rate INT NULL
);
CREATE TABLE teachers (
  id BIGINT UNSIGNED PRIMARY KEY,
  status ENUM('working','vacation','fired') NOT NULL DEFAULT 'working'
);
CREATE TABLE branch_teachers (
  branch_id BIGINT UNSIGNED NOT NULL, teacher_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (branch_id, teacher_id)
);
CREATE TABLE auf_users (id BIGINT UNSIGNED PRIMARY KEY);
CREATE TABLE instructions (id BIGINT UNSIGNED PRIMARY KEY);
CREATE TABLE curriculum_lessons (id BIGINT UNSIGNED PRIMARY KEY);
CREATE TABLE branch_curriculum_runs (id BIGINT UNSIGNED PRIMARY KEY);
CREATE TABLE lessons (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  branch_id BIGINT UNSIGNED NOT NULL,
  teacher_id BIGINT UNSIGNED NOT NULL,
  starts_at DATETIME NOT NULL,
  paid_children INT UNSIGNED NOT NULL DEFAULT 0,
  trial_children INT UNSIGNED NOT NULL DEFAULT 0,
  is_creative TINYINT(1) NOT NULL DEFAULT 0,
  instruction_id BIGINT UNSIGNED NULL,
  curriculum_run_id BIGINT UNSIGNED NULL,
  curriculum_lesson_id BIGINT UNSIGNED NULL,
  curriculum_mode ENUM('PLAN','REPEAT','OFF_PLAN_REPLACE','OFF_PLAN_PAUSE') NULL,
  price_snapshot DECIMAL(10,2) NOT NULL,
  created_by_user_id BIGINT UNSIGNED NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  is_salary_free TINYINT(1) NOT NULL DEFAULT 0,
  is_fixed_salary_2000 TINYINT(1) NOT NULL DEFAULT 0,
  KEY idx_lessons_curriculum_progress (curriculum_run_id, curriculum_lesson_id, curriculum_mode),
  CONSTRAINT fk_lessons_branch FOREIGN KEY (branch_id)
    REFERENCES branches (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_lessons_teacher FOREIGN KEY (teacher_id)
    REFERENCES teachers (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_lessons_created_by FOREIGN KEY (created_by_user_id)
    REFERENCES auf_users (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_lessons_instruction FOREIGN KEY (instruction_id)
    REFERENCES instructions (id) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT fk_lessons_curriculum_run FOREIGN KEY (curriculum_run_id)
    REFERENCES branch_curriculum_runs (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_lessons_curriculum_lesson FOREIGN KEY (curriculum_lesson_id)
    REFERENCES curriculum_lessons (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT chk_lessons_counts CHECK (paid_children >= 0 AND trial_children >= 0),
  CONSTRAINT chk_lessons_not_empty CHECK (paid_children + trial_children > 0),
  CONSTRAINT chk_lessons_price_nonneg CHECK (price_snapshot >= 0)
);
"""


def run(socket: str, user: str, password: str) -> None:
    schema = "roboman_lesson_qa_" + uuid.uuid4().hex
    connection = mysql.connector.connect(
        unix_socket=str(Path(socket).resolve()), user=user, password=password,
        autocommit=True, connection_timeout=10,
    )
    cursor = connection.cursor(dictionary=True, buffered=True)
    checks = 0

    def check(condition, message):
        nonlocal checks
        if not condition:
            raise AssertionError(message)
        checks += 1

    def reject(sql, values=(), message=None):
        nonlocal checks
        try:
            cursor.execute(sql, values)
        except mysql.connector.Error as error:
            check(error.errno in (1644, 3819, 1451, 1452, 1265, 1264, 1048), str(error))
            if message:
                check(message in str(error), str(error))
        else:
            raise AssertionError("Invalid data was accepted: " + sql)

    def insert(overrides=None, invalid=False, error=None, help_record=False):
        data = dict(branch_id=1, teacher_id=1, starts_at="2026-09-22 10:00:00",
                    paid_children=8, trial_children=2, is_creative=1,
                    price_snapshot=300, created_by_user_id=1)
        if help_record:
            data.update(lesson_type="HELP", paid_children=0, trial_children=0,
                        is_creative=0, price_snapshot=0, help_rate_snapshot=Decimal("625.50"))
        data.update(overrides or {})
        sql = "INSERT INTO lessons (" + ",".join(data) + ") VALUES (" + ",".join(["%s"] * len(data)) + ")"
        if invalid:
            reject(sql, tuple(data.values()), error)
            return None
        cursor.execute(sql, tuple(data.values()))
        return cursor.lastrowid

    def row(lesson_id):
        cursor.execute("SELECT * FROM v_lessons_calc WHERE id=%s", (lesson_id,))
        return cursor.fetchone()

    try:
        cursor.execute(f"CREATE DATABASE `{schema}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        cursor.execute(f"USE `{schema}`")
        for statement in _statements(BASELINE_SQL):
            cursor.execute(statement)
        cursor.executemany("INSERT INTO branches VALUES (%s,%s,%s)", [(1, 300, None), (2, 450, 1200)])
        cursor.executemany("INSERT INTO teachers VALUES (%s,%s)",
                           [(1, "working"), (2, "working"), (3, "fired"), (4, "vacation")])
        cursor.executemany("INSERT INTO branch_teachers VALUES (%s,%s)", [(1, 1), (2, 1), (1, 3), (1, 4)])
        cursor.execute("INSERT INTO auf_users VALUES (1)")
        cursor.execute("INSERT INTO instructions VALUES (1)")
        cursor.execute("INSERT INTO curriculum_lessons VALUES (1),(2),(3)")
        cursor.execute("INSERT INTO branch_curriculum_runs VALUES (1)")
        cursor.executemany("INSERT INTO settings (`key`, value_int) VALUES (%s,%s)",
                           [("teacher_base_rate", 1000), ("teacher_threshold_children", 6),
                            ("teacher_bonus_per_child", 100)])
        # Existing lesson rows must survive migration unchanged, including payroll.
        legacy_ids = [insert(), insert({"branch_id": 2}),
                      insert({"is_fixed_salary_2000": 1}),
                      insert({"is_fixed_salary_2000": 1, "is_salary_free": 1})]
        for statement in _statements(MIGRATION.read_text(encoding="utf-8")):
            cursor.execute(statement)
        for lesson_id, salary in zip(legacy_ids, (1400, 1600, 2000, 0)):
            value = row(lesson_id)
            check(value["lesson_type"] == "LESSON" and value["help_rate_snapshot"] is None,
                  "Existing lesson type/snapshot changed")
            check(value["teacher_salary"] == salary and value["revenue"] == 2400,
                  "Existing salary/revenue formula changed")
        cursor.execute("SELECT value_int FROM settings WHERE `key`='teacher_help_rate'")
        check(cursor.fetchone()["value_int"] is None, "Unconfigured help rate must be NULL")

        help_id = insert(help_record=True)
        help_value = row(help_id)
        check(help_value["teacher_salary"] == Decimal("625.50") and help_value["revenue"] == 0
              and help_value["total_children"] == 0, "Help payment/revenue/children incorrect")
        free_help = insert({"is_salary_free": 1}, help_record=True)
        check(row(free_help)["teacher_salary"] == 0, "Salary-free help must remain unpaid")
        zero_help = insert({"help_rate_snapshot": 0}, help_record=True)
        check(row(zero_help)["teacher_salary"] == 0, "Explicit zero help payment must be supported")
        cursor.execute("UPDATE settings SET value_int=950 WHERE `key`='teacher_help_rate'")
        check(row(help_id)["teacher_salary"] == Decimal("625.50"), "Setting change rewrote old help payment")
        new_help = insert({"help_rate_snapshot": 950}, help_record=True)
        check(row(new_help)["teacher_salary"] == 950, "New help snapshot ignored")
        cursor.execute("UPDATE lessons SET starts_at='2026-09-23 11:00:00', branch_id=2 WHERE id=%s", (help_id,))
        check(row(help_id)["teacher_salary"] == Decimal("625.50"), "Help edit rewrote historical snapshot")
        cursor.execute("UPDATE lessons SET help_rate_snapshot=help_rate_snapshot WHERE id=%s", (help_id,))
        reject("UPDATE lessons SET help_rate_snapshot=999 WHERE id=%s", (help_id,), "snapshot cannot be changed")
        reject("UPDATE lessons SET help_rate_snapshot=NULL WHERE id=%s", (help_id,), "snapshot cannot be changed")
        reject("UPDATE lessons SET lesson_type='LESSON' WHERE id=%s", (help_id,), "type cannot be changed")
        reject("UPDATE lessons SET lesson_type='HELP' WHERE id=%s", (legacy_ids[0],), "type cannot be changed")
        for invalid in [
            {"paid_children": 1}, {"trial_children": 1}, {"is_creative": 1},
            {"instruction_id": 1}, {"curriculum_run_id": 1}, {"curriculum_lesson_id": 1},
            {"skipped_curriculum_lesson_id": 1}, {"curriculum_mode": "PLAN"},
            {"price_snapshot": 1}, {"is_fixed_salary_2000": 1},
            {"help_rate_snapshot": None}, {"help_rate_snapshot": -1},
        ]:
            insert(invalid, invalid=True, help_record=True)
        for assignment in ("paid_children=1", "instruction_id=1", "curriculum_run_id=1",
                           "curriculum_lesson_id=1", "skipped_curriculum_lesson_id=1",
                           "curriculum_mode='PLAN'", "price_snapshot=1", "is_fixed_salary_2000=1"):
            reject("UPDATE lessons SET " + assignment + " WHERE id=%s", (help_id,))

        # Ordinary lessons retain every prior business/DB restriction.
        insert({"paid_children": 0, "trial_children": 0}, invalid=True)
        insert({"help_rate_snapshot": 1}, invalid=True)
        insert({"is_creative": 0}, invalid=True, error="must have instruction_id")
        insert({"instruction_id": 1}, invalid=True, error="cannot have instruction_id")
        auto_price = insert({"is_creative": 0, "instruction_id": 1, "price_snapshot": None})
        check(row(auto_price)["price_snapshot"] == 300, "Lesson price no longer defaults from branch")
        for help_record in (False, True):
            insert({"teacher_id": 2}, invalid=True, error="not assigned", help_record=help_record)
            insert({"teacher_id": 3}, invalid=True, error="Fired teacher", help_record=help_record)
            insert({"teacher_id": 4}, invalid=True, error="Vacation teacher", help_record=help_record)
        reject("UPDATE lessons SET teacher_id=2 WHERE id=%s", (help_id,), "not assigned")
        cursor.execute("INSERT INTO settings (`key`,value_bool) VALUES ('allow_vacation_teacher_for_lessons',1)")
        vacation_help = insert({"teacher_id": 4}, help_record=True)
        check(row(vacation_help)["teacher_salary"] == Decimal("625.50"), "Allowed vacation help rejected")
        cursor.execute("UPDATE settings SET value_bool=0 WHERE `key`='allow_vacation_teacher_for_lessons'")
        reject("UPDATE lessons SET starts_at='2026-09-24 10:00:00' WHERE id=%s", (vacation_help,), "Vacation teacher")
        cursor.execute("UPDATE teachers SET status='fired' WHERE id=4")
        reject("UPDATE lessons SET starts_at='2026-09-24 10:00:00' WHERE id=%s", (vacation_help,), "Fired teacher")

        skip = dict(curriculum_run_id=1, curriculum_lesson_id=2,
                    skipped_curriculum_lesson_id=1, curriculum_mode="SKIP_TO_NEXT")
        skip_id = insert(skip)
        check(row(skip_id)["skipped_curriculum_lesson_id"] == 1
              and row(skip_id)["curriculum_lesson_id"] == 2, "Skip did not preserve both lesson IDs")
        for change in [{"skipped_curriculum_lesson_id": None}, {"curriculum_lesson_id": None},
                       {"curriculum_run_id": None}, {"curriculum_lesson_id": 1},
                       {"curriculum_mode": None}, {"curriculum_mode": "PLAN"},
                       {"skipped_curriculum_lesson_id": 999}]:
            insert({**skip, **change}, invalid=True)
        reject("UPDATE lessons SET curriculum_mode=NULL WHERE id=%s", (skip_id,), "requires SKIP_TO_NEXT")
        reject("UPDATE lessons SET skipped_curriculum_lesson_id=curriculum_lesson_id WHERE id=%s", (skip_id,),
               "two different curriculum lessons")
        reject("DELETE FROM curriculum_lessons WHERE id=1")
        cursor.execute("DELETE FROM lessons WHERE id=%s", (skip_id,))
        cursor.execute("DELETE FROM curriculum_lessons WHERE id=1")
        check(cursor.rowcount == 1, "Deleted skip still retains its skipped lesson FK")

        cursor.execute("SELECT SUM(teacher_salary) AS salary, SUM(revenue) AS revenue FROM v_lessons_calc")
        totals = cursor.fetchone()
        check(totals["salary"] == Decimal("8601.00") and totals["revenue"] == Decimal("12000.00"),
              f"Mixed lesson/help aggregation failed: {totals}")
        print(f"Passed {checks} real MySQL migration, trigger, constraint and payroll checks.")
    finally:
        cursor.execute(f"DROP DATABASE IF EXISTS `{schema}`")
        cursor.close()
        connection.close()
        print("Disposable QA schema removed; application databases were not used.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, help="Unix socket of an isolated local MySQL 8 server")
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default="", help="Password of the local QA server only")
    arguments = parser.parse_args()
    run(arguments.socket, arguments.user, arguments.password)
