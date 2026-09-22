# Help records and skipping a curriculum lesson

`20260922_001_lesson_help_and_skip.sql` requires MySQL 8.0.16 or newer and the existing curriculum migrations. Apply it before starting the updated backend/frontend. Existing lesson rows receive `lesson_type = 'LESSON'`; their salary and revenue formula remains unchanged.

## Deployment

1. Back up the database, including tables, views and triggers. Save `SHOW CREATE TABLE lessons`, `SHOW CREATE VIEW v_lessons_calc` and both `trg_lessons_validate_*` definitions.
2. Pause application writes while applying the migration: MySQL DDL commits automatically, and replacing the validation triggers is not an atomic transaction.
3. Run the migration runner with **all five database variables set explicitly** to the intended deployment database. The existing runner has production defaults; do not use those defaults for testing.

   ```sh
   DB_HOST=<deployment-host> DB_PORT=3306 DB_USER=<migration-user> \
   DB_PASSWORD=<password> DB_NAME=<database> python scripts/apply_migrations.py
   ```

4. Start the updated application and set the help payment in the administrator settings. Until this setting is saved, creating help returns HTTP 409. An explicit payment of zero is valid.

The runner records the migration checksum in `schema_migrations`. Do not edit an already applied migration. If DDL fails partway through, inspect the actual schema and restore the backup or complete the remaining steps before rerunning the application; a transaction rollback cannot undo completed MySQL DDL.

## Data and calculations

- `lessons.lesson_type` distinguishes `LESSON` and `HELP`. Type changes on existing records are rejected.
- A help record uses its own teacher, kindergarten and date. It has no link to another performed lesson, instruction or curriculum. Its children, creative flag, child price and fixed-2000 flag are zero.
- `settings.teacher_help_rate` stores an integer payment; its initial value is `NULL`. The API copies the current setting into `help_rate_snapshot` when creating help. The snapshot cannot be changed, so a settings change only affects new help records.
- `v_lessons_calc` evaluates salary in this order: salary-free → zero; help → saved help payment; fixed-2000 lesson → 2000; ordinary lesson → the previous base-plus-children formula. Help revenue and children are zero. Existing consumers of this view therefore include help payment in salaries and costs.
- `SKIP_TO_NEXT` stores the skipped step in `skipped_curriculum_lesson_id` and the performed next step in `curriculum_lesson_id`, within the same curriculum run. Application progress calculation closes both steps. The foreign key protects the skipped lesson from deletion while the record exists.

The updated `chk_lessons_not_empty` permits zero children only for help. Other help invariants use a CHECK and both lesson validation triggers. MySQL disallows CHECK references to these curriculum/instruction fields because their foreign keys have cascading actions, so their validation is intentionally in the triggers. Existing assignment, teacher-status, creative/instruction and automatic lesson-price rules are retained.

## Isolated MySQL verification

Start an independent local MySQL 8 server with its own data directory and Unix socket, then run:

```sh
python scripts/verify_lesson_help_mysql.py --socket /path/to/isolated/mysql.sock
```

The verifier does not import the application database configuration and does not accept a remote host. It creates a randomly named `roboman_lesson_qa_*` schema, installs a synthetic pre-migration schema and rows, applies this migration, checks legacy salaries, help constraints/snapshots, teacher restrictions, skip references and mixed payroll aggregates, then drops that schema even on failure. It needs local QA credentials with permission to create/drop a database; defaults are `root` with an empty password, overridable with `--user` and `--password`.

This verifier deliberately does not call `apply_migrations.py` as a program: it reuses only the SQL statement parser, avoiding the runner's deployment defaults.

For HTTP integration checks against a local copy of the complete application schema with this migration applied, run:

```sh
python scripts/verify_lesson_api_mysql.py --host 127.0.0.1 --port 13317 --database roboman_lesson_qa_full
```

This second verifier creates synthetic fixtures inside a transaction and always rolls them back. It checks authorization, help creation and historical rates, curriculum progression, salaries, dashboards, reports, exports, portal invoices and accounting payments. It rejects remote hosts and database names without the `_qa` suffix/prefix component. The regular test suite is `python -m unittest discover -s tests` and uses isolated SQLite databases or mocks.
