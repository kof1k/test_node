-- Database: user_management_system
-- Version: 1.0.0
-- Description: Complete database schema for user management system with events

-- ============================================
-- DATABASE SETUP
-- ============================================

-- Create database
CREATE DATABASE IF NOT EXISTS user_management_system 
CHARACTER SET utf8mb4 
COLLATE utf8mb4_unicode_ci;

USE user_management_system;

-- ============================================
-- USERS TABLE
-- ============================================
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    avatar_url VARCHAR(255) DEFAULT '/images/default-avatar.png',
    bio TEXT,
    phone VARCHAR(20),
    date_of_birth DATE,
    role ENUM('user', 'admin', 'moderator') DEFAULT 'user',
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    reset_token VARCHAR(255),
    reset_token_expires DATETIME,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    two_factor_secret VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    locked_until DATETIME NULL,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_role (role),
    INDEX idx_is_active (is_active),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- ============================================
-- SESSIONS TABLE
-- ============================================
DROP TABLE IF EXISTS sessions;
CREATE TABLE sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    refresh_token VARCHAR(255) UNIQUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_refresh_token (refresh_token)
) ENGINE=InnoDB;

-- ============================================
-- USER LOGS TABLE
-- ============================================
DROP TABLE IF EXISTS user_logs;
CREATE TABLE user_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(50) NOT NULL,
    status ENUM('success', 'failed', 'warning') DEFAULT 'success',
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    details JSON,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_action (user_id, action),
    INDEX idx_created_at (created_at),
    INDEX idx_action (action),
    INDEX idx_status (status)
) ENGINE=InnoDB;

-- ============================================
-- API KEYS TABLE
-- ============================================
DROP TABLE IF EXISTS api_keys;
CREATE TABLE api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    key_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    permissions JSON,
    rate_limit INT DEFAULT 1000,
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_api_key (api_key),
    INDEX idx_user_id (user_id),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB;

-- ============================================
-- EVENTS TABLE
-- ============================================
DROP TABLE IF EXISTS events;
CREATE TABLE events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    slug VARCHAR(200) UNIQUE NOT NULL,
    description TEXT,
    short_description VARCHAR(500),
    event_type ENUM('online', 'offline', 'hybrid') DEFAULT 'offline',
    event_date DATETIME NOT NULL,
    end_date DATETIME,
    location VARCHAR(200),
    online_url VARCHAR(500),
    max_participants INT DEFAULT NULL,
    price DECIMAL(10, 2) DEFAULT 0.00,
    currency VARCHAR(3) DEFAULT 'USD',
    image_url VARCHAR(500),
    tags JSON,
    requirements JSON,
    created_by INT NOT NULL,
    status ENUM('draft', 'published', 'cancelled', 'completed') DEFAULT 'draft',
    is_featured BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_event_date (event_date),
    INDEX idx_created_by (created_by),
    INDEX idx_status (status),
    INDEX idx_slug (slug),
    INDEX idx_is_featured (is_featured)
) ENGINE=InnoDB;

-- ============================================
-- EVENT REGISTRATIONS TABLE
-- ============================================
DROP TABLE IF EXISTS event_registrations;
CREATE TABLE event_registrations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NOT NULL,
    user_id INT NOT NULL,
    registration_number VARCHAR(50) UNIQUE NOT NULL,
    status ENUM('pending', 'confirmed', 'cancelled', 'attended', 'no_show') DEFAULT 'pending',
    payment_status ENUM('pending', 'paid', 'refunded', 'failed') DEFAULT 'pending',
    payment_method VARCHAR(50),
    payment_id VARCHAR(100),
    amount_paid DECIMAL(10, 2),
    notes TEXT,
    check_in_time TIMESTAMP NULL,
    registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_registration (event_id, user_id),
    INDEX idx_event_id (event_id),
    INDEX idx_user_id (user_id),
    INDEX idx_status (status),
    INDEX idx_registration_number (registration_number)
) ENGINE=InnoDB;

-- ============================================
-- NOTIFICATIONS TABLE
-- ============================================
DROP TABLE IF EXISTS notifications;
CREATE TABLE notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type VARCHAR(50) NOT NULL,
    title VARCHAR(200),
    message TEXT,
    data JSON,
    is_read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_is_read (is_read),
    INDEX idx_type (type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- ============================================
-- RATE LIMITING TABLE
-- ============================================
DROP TABLE IF EXISTS rate_limits;
CREATE TABLE rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    requests INT DEFAULT 1,
    window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_limit (identifier, endpoint),
    INDEX idx_window_start (window_start)
) ENGINE=InnoDB;

-- ============================================
-- PASSWORD HISTORY TABLE
-- ============================================
DROP TABLE IF EXISTS password_history;
CREATE TABLE password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- ============================================
-- USER PREFERENCES TABLE
-- ============================================
DROP TABLE IF EXISTS user_preferences;
CREATE TABLE user_preferences (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL UNIQUE,
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    theme ENUM('light', 'dark', 'auto') DEFAULT 'auto',
    email_notifications BOOLEAN DEFAULT TRUE,
    push_notifications BOOLEAN DEFAULT FALSE,
    newsletter_subscription BOOLEAN DEFAULT FALSE,
    privacy_settings JSON,
    notification_settings JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB;

-- ============================================
-- AUDIT TRAIL TABLE
-- ============================================
DROP TABLE IF EXISTS audit_trail;
CREATE TABLE audit_trail (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    table_name VARCHAR(50) NOT NULL,
    record_id INT NOT NULL,
    action ENUM('INSERT', 'UPDATE', 'DELETE') NOT NULL,
    user_id INT,
    old_values JSON,
    new_values JSON,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_table_record (table_name, record_id),
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB;

-- ============================================
-- STORED PROCEDURES
-- ============================================

-- Procedure to clean expired sessions
DELIMITER //
CREATE PROCEDURE CleanExpiredSessions()
BEGIN
    DELETE FROM sessions WHERE expires_at < NOW();
    DELETE FROM rate_limits WHERE window_start < DATE_SUB(NOW(), INTERVAL 1 HOUR);
    DELETE FROM password_history WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 YEAR);
END //
DELIMITER ;

-- Procedure to get user statistics
DELIMITER //
CREATE PROCEDURE GetUserStatistics(IN user_id INT)
BEGIN
    SELECT 
        u.id,
        u.username,
        u.email,
        u.created_at,
        COUNT(DISTINCT er.id) as total_registrations,
        COUNT(DISTINCT e.id) as events_created,
        COUNT(DISTINCT ul.id) as total_activities
    FROM users u
    LEFT JOIN event_registrations er ON u.id = er.user_id
    LEFT JOIN events e ON u.id = e.created_by
    LEFT JOIN user_logs ul ON u.id = ul.user_id
    WHERE u.id = user_id
    GROUP BY u.id;
END //
DELIMITER ;

-- ============================================
-- TRIGGERS
-- ============================================

-- Trigger to log user updates
DELIMITER //
CREATE TRIGGER after_user_update
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    INSERT INTO audit_trail (table_name, record_id, action, user_id, old_values, new_values)
    VALUES ('users', NEW.id, 'UPDATE', NEW.id, 
            JSON_OBJECT('username', OLD.username, 'email', OLD.email),
            JSON_OBJECT('username', NEW.username, 'email', NEW.email));
END //
DELIMITER ;

-- ============================================
-- DEFAULT DATA
-- ============================================

-- Insert default admin user (password: Admin123!)
INSERT INTO users (username, email, password_hash, first_name, last_name, role, is_active, is_verified) VALUES
('admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5C2EiIkGPNAaC', 'System', 'Administrator', 'admin', TRUE, TRUE);

-- Insert sample events
INSERT INTO events (title, slug, description, event_type, event_date, location, max_participants, created_by, status) VALUES
('Welcome Workshop', 'welcome-workshop', 'Introduction to our platform', 'offline', DATE_ADD(NOW(), INTERVAL 7 DAY), 'Main Conference Room', 50, 1, 'published'),
('Online Webinar', 'online-webinar', 'Learn about new features', 'online', DATE_ADD(NOW(), INTERVAL 14 DAY), 'Zoom', 100, 1, 'published');

-- ============================================
-- VIEWS
-- ============================================

-- View for active events
CREATE OR REPLACE VIEW active_events AS
SELECT 
    e.*,
    u.username as creator_username,
    COUNT(DISTINCT er.user_id) as registered_count,
    (e.max_participants - COUNT(DISTINCT er.user_id)) as available_spots
FROM events e
LEFT JOIN users u ON e.created_by = u.id
LEFT JOIN event_registrations er ON e.id = er.event_id AND er.status = 'confirmed'
WHERE e.status = 'published' AND e.event_date >= NOW()
GROUP BY e.id;

-- View for user activity summary
CREATE OR REPLACE VIEW user_activity_summary AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.role,
    u.last_login,
    COUNT(DISTINCT ul.id) as total_logs,
    COUNT(DISTINCT s.session_id) as active_sessions
FROM users u
LEFT JOIN user_logs ul ON u.id = ul.user_id
LEFT JOIN sessions s ON u.id = s.user_id AND s.is_active = TRUE
GROUP BY u.id;

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================

-- Additional composite indexes for common queries
CREATE INDEX idx_user_logs_composite ON user_logs(user_id, action, created_at);
CREATE INDEX idx_events_composite ON events(status, event_date, created_by);
CREATE INDEX idx_registrations_composite ON event_registrations(event_id, status, user_id);

-- ============================================
-- GRANTS (adjust based on your setup)
-- ============================================

-- Create application user
-- CREATE USER IF NOT EXISTS 'webapp'@'localhost' IDENTIFIED BY 'SecurePassword123!';
-- GRANT ALL PRIVILEGES ON user_management_system.* TO 'webapp'@'localhost';
-- FLUSH PRIVILEGES;
