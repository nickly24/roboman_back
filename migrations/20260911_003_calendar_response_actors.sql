ALTER TABLE calendar_responses
 ADD COLUMN actor_user_id BIGINT UNSIGNED NULL,
 ADD COLUMN actor_name VARCHAR(255) NULL,
 ADD COLUMN actor_role VARCHAR(16) NOT NULL DEFAULT 'TEACHER',
 ADD CONSTRAINT chk_calendar_response_actor_role CHECK(actor_role IN ('OWNER','TEACHER'));

UPDATE calendar_responses SET actor_name=teacher_name WHERE actor_name IS NULL;
