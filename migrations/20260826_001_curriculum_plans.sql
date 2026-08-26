CREATE TABLE lesson_formats (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_lesson_formats_name (name),
  KEY idx_lesson_formats_active_order (is_active, sort_order, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE curriculum_plans (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_curriculum_plans_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE curriculum_modules (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  plan_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_curriculum_modules_plan_order (plan_id, sort_order, id),
  CONSTRAINT fk_curriculum_modules_plan FOREIGN KEY (plan_id)
    REFERENCES curriculum_plans (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE curriculum_lessons (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  module_id BIGINT UNSIGNED NOT NULL,
  name VARCHAR(255) NOT NULL,
  internal_description TEXT NULL,
  external_description TEXT NULL,
  format_id BIGINT UNSIGNED NOT NULL,
  instruction_id BIGINT UNSIGNED NULL,
  sort_order INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_curriculum_lessons_module_order (module_id, sort_order, id),
  KEY idx_curriculum_lessons_format (format_id),
  KEY idx_curriculum_lessons_instruction (instruction_id),
  CONSTRAINT fk_curriculum_lessons_module FOREIGN KEY (module_id)
    REFERENCES curriculum_modules (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_curriculum_lessons_format FOREIGN KEY (format_id)
    REFERENCES lesson_formats (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_curriculum_lessons_instruction FOREIGN KEY (instruction_id)
    REFERENCES instructions (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE curriculum_lesson_images (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  lesson_id BIGINT UNSIGNED NOT NULL,
  filename VARCHAR(255) NULL,
  mime VARCHAR(128) NOT NULL,
  image_blob LONGBLOB NOT NULL,
  sort_order INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_curriculum_lesson_images_order (lesson_id, sort_order, id),
  CONSTRAINT fk_curriculum_lesson_images_lesson FOREIGN KEY (lesson_id)
    REFERENCES curriculum_lessons (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE curriculum_lesson_comments (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  lesson_id BIGINT UNSIGNED NOT NULL,
  author_user_id BIGINT UNSIGNED NOT NULL,
  text TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_curriculum_lesson_comments_lesson (lesson_id, created_at, id),
  KEY idx_curriculum_lesson_comments_author (author_user_id),
  CONSTRAINT fk_curriculum_lesson_comments_lesson FOREIGN KEY (lesson_id)
    REFERENCES curriculum_lessons (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_curriculum_lesson_comments_author FOREIGN KEY (author_user_id)
    REFERENCES auf_users (id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE instruction_comments (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  instruction_id BIGINT UNSIGNED NOT NULL,
  author_user_id BIGINT UNSIGNED NOT NULL,
  text TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_instruction_comments_instruction (instruction_id, created_at, id),
  KEY idx_instruction_comments_author (author_user_id),
  CONSTRAINT fk_instruction_comments_instruction FOREIGN KEY (instruction_id)
    REFERENCES instructions (id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_instruction_comments_author FOREIGN KEY (author_user_id)
    REFERENCES auf_users (id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE branch_curriculum_runs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  branch_id BIGINT UNSIGNED NOT NULL,
  plan_id BIGINT UNSIGNED NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  active_branch_id BIGINT UNSIGNED NULL,
  started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ended_at TIMESTAMP NULL DEFAULT NULL,
  created_by_user_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_branch_curriculum_active (active_branch_id),
  KEY idx_branch_curriculum_runs_branch (branch_id, started_at, id),
  KEY idx_branch_curriculum_runs_plan (plan_id),
  KEY idx_branch_curriculum_runs_created_by (created_by_user_id),
  CONSTRAINT fk_branch_curriculum_runs_branch FOREIGN KEY (branch_id)
    REFERENCES branches (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_branch_curriculum_runs_plan FOREIGN KEY (plan_id)
    REFERENCES curriculum_plans (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT fk_branch_curriculum_runs_created_by FOREIGN KEY (created_by_user_id)
    REFERENCES auf_users (id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE lessons
  DROP FOREIGN KEY fk_lessons_instruction;

ALTER TABLE lessons
  ADD CONSTRAINT fk_lessons_instruction FOREIGN KEY (instruction_id)
    REFERENCES instructions (id) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE lessons
  ADD COLUMN curriculum_run_id BIGINT UNSIGNED NULL AFTER instruction_id,
  ADD COLUMN curriculum_lesson_id BIGINT UNSIGNED NULL AFTER curriculum_run_id,
  ADD COLUMN curriculum_mode ENUM(
    'PLAN',
    'REPEAT',
    'OFF_PLAN_REPLACE',
    'OFF_PLAN_PAUSE'
  ) NULL AFTER curriculum_lesson_id,
  ADD KEY idx_lessons_curriculum_run (curriculum_run_id),
  ADD KEY idx_lessons_curriculum_lesson (curriculum_lesson_id),
  ADD KEY idx_lessons_curriculum_progress (curriculum_run_id, curriculum_lesson_id, curriculum_mode),
  ADD CONSTRAINT fk_lessons_curriculum_run FOREIGN KEY (curriculum_run_id)
    REFERENCES branch_curriculum_runs (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT fk_lessons_curriculum_lesson FOREIGN KEY (curriculum_lesson_id)
    REFERENCES curriculum_lessons (id) ON DELETE RESTRICT ON UPDATE CASCADE;
