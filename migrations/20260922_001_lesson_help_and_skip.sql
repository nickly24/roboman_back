-- Apply before deploying the lesson/help API. MySQL 8.0.16+ is required for CHECKs.
-- NULL means an administrator has not configured help payment yet; zero is valid.
INSERT INTO settings (`key`, value_int, description)
VALUES ('teacher_help_rate', NULL, 'Fixed payment for help at a lesson, saved when help is recorded')
ON DUPLICATE KEY UPDATE `key` = VALUES(`key`);

ALTER TABLE lessons
  ADD COLUMN lesson_type ENUM('LESSON', 'HELP') NOT NULL DEFAULT 'LESSON' AFTER starts_at,
  ADD COLUMN help_rate_snapshot DECIMAL(10,2) NULL AFTER price_snapshot,
  ADD COLUMN skipped_curriculum_lesson_id BIGINT UNSIGNED NULL AFTER curriculum_lesson_id,
  MODIFY COLUMN curriculum_mode ENUM(
    'PLAN', 'REPEAT', 'OFF_PLAN_REPLACE', 'OFF_PLAN_PAUSE', 'SKIP_TO_NEXT'
  ) NULL,
  ADD KEY idx_lessons_skipped_curriculum_lesson (skipped_curriculum_lesson_id),
  ADD CONSTRAINT fk_lessons_skipped_curriculum_lesson FOREIGN KEY (skipped_curriculum_lesson_id)
    REFERENCES curriculum_lessons (id) ON DELETE RESTRICT ON UPDATE CASCADE,
  DROP CHECK chk_lessons_not_empty,
  ADD CONSTRAINT chk_lessons_not_empty CHECK (
    lesson_type = 'HELP' OR paid_children + trial_children > 0
  ),
  ADD CONSTRAINT chk_lessons_help_fields CHECK (
    (lesson_type = 'LESSON' AND help_rate_snapshot IS NULL)
    OR
    (lesson_type = 'HELP'
      AND paid_children = 0 AND trial_children = 0 AND is_creative = 0
      AND curriculum_mode IS NULL AND price_snapshot = 0 AND is_fixed_salary_2000 = 0
      AND help_rate_snapshot IS NOT NULL AND help_rate_snapshot >= 0)
  );

DELIMITER $$
DROP TRIGGER IF EXISTS trg_lessons_validate_ins$$
CREATE TRIGGER trg_lessons_validate_ins BEFORE INSERT ON lessons FOR EACH ROW
BEGIN
  DECLARE v_status VARCHAR(16);
  DECLARE v_allow_vac TINYINT(1);

  IF NEW.lesson_type = 'LESSON' THEN
    -- Preserve the existing creative XOR instruction requirement for lessons.
    IF NEW.is_creative = 1 THEN
      IF NEW.instruction_id IS NOT NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Creative lesson cannot have instruction_id';
      END IF;
    ELSE
      IF NEW.instruction_id IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Non-creative lesson must have instruction_id';
      END IF;
    END IF;

    IF NEW.price_snapshot IS NULL THEN
      SET NEW.price_snapshot = (SELECT b.price_per_child FROM branches b WHERE b.id = NEW.branch_id);
    END IF;
  ELSE
    -- MySQL forbids CHECKs on these columns because their FKs use referential actions.
    IF NEW.instruction_id IS NOT NULL OR NEW.curriculum_run_id IS NOT NULL
      OR NEW.curriculum_lesson_id IS NOT NULL OR NEW.skipped_curriculum_lesson_id IS NOT NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Help cannot reference instructions or curriculum lessons';
    END IF;
  END IF;

  IF NEW.curriculum_mode = 'SKIP_TO_NEXT' THEN
    IF NEW.skipped_curriculum_lesson_id IS NULL OR NEW.curriculum_run_id IS NULL
      OR NEW.curriculum_lesson_id IS NULL OR NEW.skipped_curriculum_lesson_id = NEW.curriculum_lesson_id THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Skip requires a curriculum run and two different curriculum lessons';
    END IF;
  ELSEIF NEW.skipped_curriculum_lesson_id IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Skipped curriculum lesson requires SKIP_TO_NEXT mode';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM branch_teachers bt
    WHERE bt.branch_id = NEW.branch_id AND bt.teacher_id = NEW.teacher_id
  ) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Teacher is not assigned to this branch';
  END IF;

  SELECT t.status INTO v_status FROM teachers t WHERE t.id = NEW.teacher_id;
  IF v_status = 'fired' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Fired teacher cannot be scheduled for lessons';
  END IF;
  SET v_allow_vac = COALESCE((SELECT value_bool FROM settings WHERE `key` = 'allow_vacation_teacher_for_lessons'), 0);
  IF v_status = 'vacation' AND v_allow_vac = 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Vacation teacher cannot be scheduled for lessons';
  END IF;
END$$

DROP TRIGGER IF EXISTS trg_lessons_validate_upd$$
CREATE TRIGGER trg_lessons_validate_upd BEFORE UPDATE ON lessons FOR EACH ROW
BEGIN
  DECLARE v_status VARCHAR(16);
  DECLARE v_allow_vac TINYINT(1);

  IF NEW.lesson_type <> OLD.lesson_type THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Lesson type cannot be changed';
  END IF;
  IF NOT (NEW.help_rate_snapshot <=> OLD.help_rate_snapshot) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Help payment snapshot cannot be changed';
  END IF;

  IF NEW.lesson_type = 'LESSON' THEN
    IF NEW.is_creative = 1 THEN
      IF NEW.instruction_id IS NOT NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Creative lesson cannot have instruction_id';
      END IF;
    ELSE
      IF NEW.instruction_id IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Non-creative lesson must have instruction_id';
      END IF;
    END IF;
  ELSE
    IF NEW.instruction_id IS NOT NULL OR NEW.curriculum_run_id IS NOT NULL
      OR NEW.curriculum_lesson_id IS NOT NULL OR NEW.skipped_curriculum_lesson_id IS NOT NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Help cannot reference instructions or curriculum lessons';
    END IF;
  END IF;

  IF NEW.curriculum_mode = 'SKIP_TO_NEXT' THEN
    IF NEW.skipped_curriculum_lesson_id IS NULL OR NEW.curriculum_run_id IS NULL
      OR NEW.curriculum_lesson_id IS NULL OR NEW.skipped_curriculum_lesson_id = NEW.curriculum_lesson_id THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Skip requires a curriculum run and two different curriculum lessons';
    END IF;
  ELSEIF NEW.skipped_curriculum_lesson_id IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Skipped curriculum lesson requires SKIP_TO_NEXT mode';
  END IF;

  IF NEW.branch_id <> OLD.branch_id OR NEW.teacher_id <> OLD.teacher_id THEN
    IF NOT EXISTS (
      SELECT 1 FROM branch_teachers bt
      WHERE bt.branch_id = NEW.branch_id AND bt.teacher_id = NEW.teacher_id
    ) THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Teacher is not assigned to this branch';
    END IF;
  END IF;

  SELECT t.status INTO v_status FROM teachers t WHERE t.id = NEW.teacher_id;
  IF v_status = 'fired' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Fired teacher cannot be scheduled for lessons';
  END IF;
  SET v_allow_vac = COALESCE((SELECT value_bool FROM settings WHERE `key` = 'allow_vacation_teacher_for_lessons'), 0);
  IF v_status = 'vacation' AND v_allow_vac = 0 THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Vacation teacher cannot be scheduled for lessons';
  END IF;
END$$
DELIMITER ;

-- Keep the existing lesson formula and salary-free precedence. Help has no revenue.
CREATE OR REPLACE VIEW v_lessons_calc AS
SELECT
  l.id, l.branch_id, l.teacher_id, l.starts_at,
  l.paid_children, l.trial_children,
  (l.paid_children + l.trial_children) AS total_children,
  l.is_creative, l.instruction_id, l.is_salary_free, l.is_fixed_salary_2000,
  l.price_snapshot,
  (l.paid_children * l.price_snapshot) AS revenue,
  CASE
    WHEN l.is_salary_free = 1 THEN 0
    WHEN l.lesson_type = 'HELP' THEN l.help_rate_snapshot
    WHEN l.is_fixed_salary_2000 = 1 THEN 2000
    ELSE (
      COALESCE(b.teacher_base_rate, (SELECT value_int FROM settings WHERE `key` = 'teacher_base_rate'))
      + GREATEST(0,
          CAST((l.paid_children + l.trial_children) AS SIGNED)
          - CAST((SELECT value_int FROM settings WHERE `key` = 'teacher_threshold_children') AS SIGNED)
        ) * (SELECT value_int FROM settings WHERE `key` = 'teacher_bonus_per_child')
    )
  END AS teacher_salary,
  l.created_by_user_id, l.created_at, l.updated_at,
  l.lesson_type, l.help_rate_snapshot, l.curriculum_run_id,
  l.curriculum_lesson_id, l.curriculum_mode, l.skipped_curriculum_lesson_id
FROM lessons l
JOIN branches b ON b.id = l.branch_id;
