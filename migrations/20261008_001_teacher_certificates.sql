-- Digital teacher profiles; existing teacher names/assignments remain the source of truth.
-- Apply only after backup and explicit deployment approval. Requires MySQL 8.0.16+.
CREATE TABLE teacher_certificates (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 teacher_id BIGINT UNSIGNED NOT NULL,
 number VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 public_token VARCHAR(43) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 status ENUM('draft','published','revoked') NOT NULL DEFAULT 'draft',
 university VARCHAR(250) NOT NULL DEFAULT '',
 study_program VARCHAR(250) NOT NULL DEFAULT '',
 description TEXT NOT NULL,
 photo_blob MEDIUMBLOB NULL,
 photo_mime VARCHAR(50) NULL,
 photo_filename VARCHAR(255) NULL,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 issued_at DATETIME NULL,
 revoked_at DATETIME NULL,
 created_by_user_id BIGINT UNSIGNED NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 UNIQUE KEY uq_teacher_certificate_teacher(teacher_id),
 UNIQUE KEY uq_teacher_certificate_number(number),
 UNIQUE KEY uq_teacher_certificate_token(public_token),
 KEY idx_teacher_certificates_status(status),
 CONSTRAINT fk_teacher_certificate_teacher FOREIGN KEY(teacher_id) REFERENCES teachers(id) ON DELETE RESTRICT,
 CONSTRAINT fk_teacher_certificate_creator FOREIGN KEY(created_by_user_id) REFERENCES auf_users(id) ON DELETE SET NULL,
 CONSTRAINT chk_teacher_certificate_revision CHECK(revision >= 1),
 CONSTRAINT chk_teacher_certificate_token CHECK(CHAR_LENGTH(public_token)=43),
 CONSTRAINT chk_teacher_certificate_text CHECK(CHAR_LENGTH(description) <= 3000),
 CONSTRAINT chk_teacher_certificate_photo CHECK(
   (photo_blob IS NULL AND photo_mime IS NULL AND photo_filename IS NULL) OR
   (photo_blob IS NOT NULL AND OCTET_LENGTH(photo_blob)>0 AND OCTET_LENGTH(photo_blob)<=5242880
    AND photo_mime IS NOT NULL AND photo_mime='image/jpeg' AND photo_filename IS NOT NULL)),
 CONSTRAINT chk_teacher_certificate_publication CHECK(
   status <> 'published' OR (issued_at IS NOT NULL AND photo_blob IS NOT NULL AND CHAR_LENGTH(TRIM(description))>0)),
 CONSTRAINT chk_teacher_certificate_revocation CHECK(status <> 'revoked' OR revoked_at IS NOT NULL)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
