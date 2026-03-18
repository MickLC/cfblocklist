-- cfblocklist schema
-- Run this against your 'blocklist' database on Gandalf
-- Safe to run against existing data; uses IF NOT EXISTS / ADD COLUMN IF NOT EXISTS

CREATE DATABASE IF NOT EXISTS blocklist CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE blocklist;

-- ============================================================
-- Core IP/CIDR/hostname entry table
-- ============================================================
CREATE TABLE IF NOT EXISTS ip (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    entry_type  ENUM('ip','cidr','hostname') NOT NULL DEFAULT 'ip',
    address     VARCHAR(253) NOT NULL,          -- IP, CIDR base, or hostname/domain
    cidr        TINYINT UNSIGNED NULL,           -- NULL for hostnames
    locked      TINYINT(1) NOT NULL DEFAULT 0,  -- 1 = admin-locked, no self-delist
    active      TINYINT(1) NOT NULL DEFAULT 1,  -- 0 = delisted/inactive, still in DB
    added_date  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    added_by    INT UNSIGNED NULL,               -- FK to login.id
    modified_date DATETIME NULL ON UPDATE CURRENT_TIMESTAMP,
    modified_by INT UNSIGNED NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_address_cidr (address, cidr),
    KEY idx_entry_type (entry_type),
    KEY idx_locked (locked),
    KEY idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Evidence table (one or more evidence records per IP entry)
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    ip_id       INT UNSIGNED NOT NULL,
    evidence    MEDIUMTEXT NOT NULL,
    added_date  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    added_by    INT UNSIGNED NULL,
    PRIMARY KEY (id),
    KEY idx_ip_id (ip_id),
    CONSTRAINT fk_evidence_ip FOREIGN KEY (ip_id) REFERENCES ip(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Admin login table
-- ============================================================
CREATE TABLE IF NOT EXISTS login (
    id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
    name         VARCHAR(64) NOT NULL,
    password     VARCHAR(255) NOT NULL,   -- iterations:salt:hash (PBKDF2)
    access_level INT NOT NULL DEFAULT 1000,
    active       TINYINT(1) NOT NULL DEFAULT 1,
    last_login   DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Audit log
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
    admin_id    INT UNSIGNED NULL,
    action      VARCHAR(32) NOT NULL,    -- ADD, EDIT, DELETE, LOCK, UNLOCK, DELIST
    entry_type  VARCHAR(16) NULL,
    target      VARCHAR(253) NULL,       -- the address acted on
    detail      TEXT NULL,
    ip_addr     VARCHAR(45) NULL,        -- admin's browser IP
    log_date    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_log_date (log_date),
    KEY idx_action (action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Migrations: safely add new columns to existing tables
-- (No-op if already present)
-- ============================================================
SET @dbname = DATABASE();

-- ip.entry_type
SET @exist = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=@dbname AND TABLE_NAME='ip' AND COLUMN_NAME='entry_type');
SET @sql = IF(@exist=0,
    'ALTER TABLE ip ADD COLUMN entry_type ENUM(''ip'',''cidr'',''hostname'') NOT NULL DEFAULT ''ip'' AFTER id',
    'SELECT ''entry_type already exists''');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ip.locked
SET @exist = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=@dbname AND TABLE_NAME='ip' AND COLUMN_NAME='locked');
SET @sql = IF(@exist=0,
    'ALTER TABLE ip ADD COLUMN locked TINYINT(1) NOT NULL DEFAULT 0 AFTER cidr',
    'SELECT ''locked already exists''');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;


-- ip.active
SET @exist = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=@dbname AND TABLE_NAME='ip' AND COLUMN_NAME='active');
SET @sql = IF(@exist=0,
    'ALTER TABLE ip ADD COLUMN active TINYINT(1) NOT NULL DEFAULT 1 AFTER locked',
    'SELECT ''active already exists''');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ip.added_date
SET @exist = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=@dbname AND TABLE_NAME='ip' AND COLUMN_NAME='added_date');
SET @sql = IF(@exist=0,
    'ALTER TABLE ip ADD COLUMN added_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER locked',
    'SELECT ''added_date already exists''');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ip.added_by
SET @exist = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=@dbname AND TABLE_NAME='ip' AND COLUMN_NAME='added_by');
SET @sql = IF(@exist=0,
    'ALTER TABLE ip ADD COLUMN added_by INT UNSIGNED NULL AFTER added_date',
    'SELECT ''added_by already exists''');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ip.modified_date
SET @exist = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=@dbname AND TABLE_NAME='ip' AND COLUMN_NAME='modified_date');
SET @sql = IF(@exist=0,
    'ALTER TABLE ip ADD COLUMN modified_date DATETIME NULL ON UPDATE CURRENT_TIMESTAMP AFTER added_by',
    'SELECT ''modified_date already exists''');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ip.modified_by
SET @exist = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=@dbname AND TABLE_NAME='ip' AND COLUMN_NAME='modified_by');
SET @sql = IF(@exist=0,
    'ALTER TABLE ip ADD COLUMN modified_by INT UNSIGNED NULL AFTER modified_date',
    'SELECT ''modified_by already exists''');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Backfill entry_type for existing rows where cidr IS NOT NULL → 'cidr', else → 'ip'
UPDATE ip SET entry_type = CASE WHEN cidr IS NOT NULL AND cidr < 32 THEN 'cidr' ELSE 'ip' END
WHERE entry_type = 'ip';
