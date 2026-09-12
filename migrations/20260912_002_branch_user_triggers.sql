DELIMITER $$
DROP TRIGGER IF EXISTS trg_auf_users_validate_ins$$
CREATE TRIGGER trg_auf_users_validate_ins BEFORE INSERT ON auf_users FOR EACH ROW
BEGIN
  IF NEW.role = 'OWNER' THEN
    IF NEW.owner_id IS NULL OR NEW.teacher_id IS NOT NULL OR NEW.branch_id IS NOT NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'OWNER user must reference owner_id only';
    END IF;
  ELSEIF NEW.role = 'TEACHER' THEN
    IF NEW.teacher_id IS NULL OR NEW.owner_id IS NOT NULL OR NEW.branch_id IS NOT NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'TEACHER user must reference teacher_id only';
    END IF;
  ELSEIF NEW.role = 'BRANCH' THEN
    IF NEW.branch_id IS NULL OR NEW.owner_id IS NOT NULL OR NEW.teacher_id IS NOT NULL OR NEW.crm_access <> 0 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'BRANCH user must reference branch_id only and cannot access CRM';
    END IF;
  ELSE
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Unknown user role';
  END IF;
END$$

DROP TRIGGER IF EXISTS trg_auf_users_validate_upd$$
CREATE TRIGGER trg_auf_users_validate_upd BEFORE UPDATE ON auf_users FOR EACH ROW
BEGIN
  IF NEW.role = 'OWNER' THEN
    IF NEW.owner_id IS NULL OR NEW.teacher_id IS NOT NULL OR NEW.branch_id IS NOT NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'OWNER user must reference owner_id only';
    END IF;
  ELSEIF NEW.role = 'TEACHER' THEN
    IF NEW.teacher_id IS NULL OR NEW.owner_id IS NOT NULL OR NEW.branch_id IS NOT NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'TEACHER user must reference teacher_id only';
    END IF;
  ELSEIF NEW.role = 'BRANCH' THEN
    IF NEW.branch_id IS NULL OR NEW.owner_id IS NOT NULL OR NEW.teacher_id IS NOT NULL OR NEW.crm_access <> 0 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'BRANCH user must reference branch_id only and cannot access CRM';
    END IF;
  ELSE
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Unknown user role';
  END IF;
END$$
DELIMITER ;
