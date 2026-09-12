ALTER TABLE auf_users
 MODIFY COLUMN role ENUM('OWNER','TEACHER','BRANCH') NOT NULL,
 ADD COLUMN branch_id BIGINT UNSIGNED NULL,
 ADD INDEX idx_auf_users_branch(branch_id),
 ADD CONSTRAINT fk_auf_users_branch FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE RESTRICT,
 ADD CONSTRAINT chk_branch_user_scope CHECK(role <> 'BRANCH' OR (branch_id IS NOT NULL AND crm_access=0));

CREATE TABLE auth_sessions (
 token_hash CHAR(64) NOT NULL PRIMARY KEY,
 user_id BIGINT UNSIGNED NOT NULL,
 expires_at DATETIME NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 KEY idx_auth_sessions_user(user_id),
 KEY idx_auth_sessions_expiry(expires_at),
 CONSTRAINT fk_auth_sessions_user FOREIGN KEY(user_id) REFERENCES auf_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE branch_retail_prices (
 branch_id BIGINT UNSIGNED NOT NULL,
 month CHAR(7) NOT NULL,
 retail_price_per_child DECIMAL(10,2) NOT NULL,
 updated_by_user_id BIGINT UNSIGNED NOT NULL,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 PRIMARY KEY(branch_id,month),
 CONSTRAINT fk_branch_retail_branch FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE RESTRICT,
 CONSTRAINT chk_branch_retail_price CHECK(retail_price_per_child >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE branch_invoices (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 number VARCHAR(40) NULL,
 branch_id BIGINT UNSIGNED NOT NULL,
 branch_name VARCHAR(255) NOT NULL,
 month CHAR(7) NOT NULL,
 title VARCHAR(255) NOT NULL,
 status ENUM('draft','issued','payment_reported','paid','cancelled') NOT NULL DEFAULT 'draft',
 active_month CHAR(7) GENERATED ALWAYS AS (CASE WHEN status='cancelled' THEN NULL ELSE month END) STORED,
 total_amount DECIMAL(14,2) NOT NULL DEFAULT 0,
 due_date DATE NULL,
 note TEXT NULL,
 seller_details TEXT NULL,
 buyer_details TEXT NULL,
 payment_details TEXT NULL,
 revision INT UNSIGNED NOT NULL DEFAULT 1,
 created_by_user_id BIGINT UNSIGNED NOT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
 issued_at DATETIME NULL,
 payment_reported_at DATETIME NULL,
 payment_date DATE NULL,
 payment_note TEXT NULL,
 paid_at DATETIME NULL,
 paid_by_user_id BIGINT UNSIGNED NULL,
 cancelled_at DATETIME NULL,
 UNIQUE KEY uq_branch_invoice_number(number),
 UNIQUE KEY uq_branch_invoice_active_month(branch_id,active_month),
 KEY idx_branch_invoices_month_status(month,status),
 CONSTRAINT fk_branch_invoices_branch FOREIGN KEY(branch_id) REFERENCES branches(id) ON DELETE RESTRICT,
 CONSTRAINT chk_branch_invoice_total CHECK(total_amount >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE branch_invoice_items (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 invoice_id BIGINT UNSIGNED NOT NULL,
 sort_order INT UNSIGNED NOT NULL,
 lesson_id BIGINT UNSIGNED NULL,
 description VARCHAR(1000) NOT NULL,
 lesson_date DATETIME NULL,
 teacher_name VARCHAR(255) NULL,
 quantity DECIMAL(10,2) NOT NULL,
 unit_price DECIMAL(10,2) NOT NULL,
 amount DECIMAL(14,2) NOT NULL,
 KEY idx_branch_invoice_items_invoice(invoice_id,sort_order),
 CONSTRAINT fk_branch_invoice_items_invoice FOREIGN KEY(invoice_id) REFERENCES branch_invoices(id) ON DELETE CASCADE,
 CONSTRAINT chk_branch_invoice_item_amounts CHECK(quantity >= 0 AND unit_price >= 0 AND amount >= 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE branch_invoice_events (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 invoice_id BIGINT UNSIGNED NOT NULL,
 actor_user_id BIGINT UNSIGNED NOT NULL,
 actor_name VARCHAR(255) NOT NULL,
 action VARCHAR(40) NOT NULL,
 note TEXT NULL,
 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
 KEY idx_branch_invoice_events_invoice(invoice_id,id),
 CONSTRAINT fk_branch_invoice_events_invoice FOREIGN KEY(invoice_id) REFERENCES branch_invoices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
