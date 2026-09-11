CREATE TABLE IF NOT EXISTS calendar_series (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 branch_id BIGINT UNSIGNED NOT NULL,
 legacy_schedule_id BIGINT UNSIGNED NULL,
 request_key VARCHAR(64) NULL,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE KEY uq_calendar_legacy (legacy_schedule_id),
 UNIQUE KEY uq_calendar_request (request_key),
 CONSTRAINT fk_calendar_branch FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS calendar_versions (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 series_id BIGINT UNSIGNED NOT NULL,
 effective_week DATE NOT NULL,
 weekday TINYINT UNSIGNED NOT NULL,
 starts_at TIME NOT NULL,
 duration_minutes INT UNSIGNED NOT NULL,
 teacher_id BIGINT UNSIGNED NULL,
 teacher_name VARCHAR(255) NULL,
 is_active TINYINT NOT NULL DEFAULT 1,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 KEY idx_calendar_version_week(series_id,effective_week),
 CONSTRAINT fk_calendar_version_series FOREIGN KEY(series_id) REFERENCES calendar_series(id) ON DELETE RESTRICT,
 CONSTRAINT chk_calendar_day CHECK(weekday BETWEEN 1 AND 7),
 CONSTRAINT chk_calendar_duration CHECK(duration_minutes BETWEEN 1 AND 600)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS calendar_occurrences (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 series_id BIGINT UNSIGNED NOT NULL,
 week_start DATE NOT NULL,
 version_id BIGINT UNSIGNED NOT NULL,
 scheduled_starts_at DATETIME NOT NULL,
 starts_at DATETIME NOT NULL,
 duration_minutes INT UNSIGNED NOT NULL,
 planned_teacher_id BIGINT UNSIGNED NULL,
 planned_teacher_name VARCHAR(255) NULL,
 confirmed_teacher_id BIGINT UNSIGNED NULL,
 confirmed_teacher_name VARCHAR(255) NULL,
 is_override TINYINT NOT NULL DEFAULT 0,
 is_cancelled TINYINT NOT NULL DEFAULT 0,
 needs_replacement TINYINT NOT NULL DEFAULT 0,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 response_epoch INT UNSIGNED NOT NULL DEFAULT 1,
 note VARCHAR(1000) NOT NULL DEFAULT '',
 UNIQUE KEY uq_calendar_occurrence(series_id,week_start),
 KEY idx_calendar_actual_date(starts_at),
 CONSTRAINT fk_calendar_occurrence_series FOREIGN KEY(series_id) REFERENCES calendar_series(id) ON DELETE RESTRICT,
 CONSTRAINT fk_calendar_occurrence_version FOREIGN KEY(version_id) REFERENCES calendar_versions(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS calendar_responses (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 occurrence_id BIGINT UNSIGNED NOT NULL,
 teacher_id BIGINT UNSIGNED NOT NULL,
 teacher_name VARCHAR(255) NOT NULL,
 answer VARCHAR(16) NOT NULL,
 reason VARCHAR(1000) NOT NULL DEFAULT '',
 response_epoch INT UNSIGNED NOT NULL,
 created_at DATETIME NOT NULL,
 KEY idx_calendar_response(occurrence_id,response_epoch,id),
 CONSTRAINT fk_calendar_response_occurrence FOREIGN KEY(occurrence_id) REFERENCES calendar_occurrences(id) ON DELETE RESTRICT,
 CONSTRAINT chk_calendar_answer CHECK(answer IN ('confirmed','declined'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS calendar_audit (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 series_id BIGINT UNSIGNED NOT NULL,
 occurrence_id BIGINT UNSIGNED NULL,
 actor_user_id BIGINT UNSIGNED NULL,
 actor_name VARCHAR(255) NOT NULL,
 action VARCHAR(40) NOT NULL,
 details_json JSON NOT NULL,
 created_at DATETIME NOT NULL,
 KEY idx_calendar_audit(series_id,id),
 CONSTRAINT fk_calendar_audit_series FOREIGN KEY(series_id) REFERENCES calendar_series(id) ON DELETE RESTRICT,
 CONSTRAINT fk_calendar_audit_occurrence FOREIGN KEY(occurrence_id) REFERENCES calendar_occurrences(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO calendar_series(branch_id,legacy_schedule_id)
 SELECT s.branch_id,s.id FROM schedules s
 WHERE NOT EXISTS(SELECT 1 FROM calendar_series c WHERE c.legacy_schedule_id=s.id);
INSERT INTO calendar_versions(series_id,effective_week,weekday,starts_at,duration_minutes,teacher_id,teacher_name)
 SELECT c.id,DATE_SUB(DATE(UTC_TIMESTAMP()+INTERVAL 3 HOUR),INTERVAL WEEKDAY(UTC_TIMESTAMP()+INTERVAL 3 HOUR) DAY),s.weekday,s.starts_at,s.duration_minutes,s.teacher_id,t.full_name
 FROM schedules s JOIN calendar_series c ON c.legacy_schedule_id=s.id LEFT JOIN teachers t ON t.id=s.teacher_id
 WHERE NOT EXISTS(SELECT 1 FROM calendar_versions v WHERE v.series_id=c.id);
