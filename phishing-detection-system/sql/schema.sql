-- ============================================================
-- PhishGuard - MySQL Schema
-- Database: phishguard
-- Run this script BEFORE starting the Spring Boot application.
-- ============================================================

CREATE DATABASE IF NOT EXISTS phishguard
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE phishguard;

-- ------------------------------------------------------------
-- Users table (application login / signup)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              BIGINT          NOT NULL AUTO_INCREMENT,
    username        VARCHAR(50)    NOT NULL,
    email           VARCHAR(120)   NOT NULL,
    password_hash   VARCHAR(255)   NOT NULL,
    role            VARCHAR(20)    NOT NULL DEFAULT 'USER',
    created_at      TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_users_username (username),
    UNIQUE KEY uk_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- Scan history table (one row per URL checked by a user)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_history (
    id              BIGINT          NOT NULL AUTO_INCREMENT,
    user_id         BIGINT          NOT NULL,
    url             TEXT           NOT NULL,
    verdict         VARCHAR(20)    NOT NULL,        -- 'PHISHING' or 'LEGITIMATE'
    confidence      DECIMAL(5,2)   NOT NULL,        -- 0.00 - 100.00
    features_json   TEXT,                           -- JSON breakdown of extracted features
    scanned_at      TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_scan_user (user_id),
    KEY idx_scan_verdict (verdict),
    CONSTRAINT fk_scan_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- Model metrics table (stores last training evaluation)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS model_metrics (
    id              BIGINT          NOT NULL AUTO_INCREMENT,
    accuracy        DECIMAL(5,2)   NOT NULL,
    precision_val   DECIMAL(5,2)   NOT NULL,
    recall          DECIMAL(5,2)   NOT NULL,
    f1_score        DECIMAL(5,2)   NOT NULL,
    confusion_matrix TEXT,
    trained_at      TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ------------------------------------------------------------
-- Optional seed: default admin account
-- Password hash below = bcrypt of 'admin123' (replace if needed)
-- ------------------------------------------------------------
INSERT INTO users (username, email, password_hash, role)
SELECT 'admin', 'admin@phishguard.example',
       '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'ADMIN'
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');
