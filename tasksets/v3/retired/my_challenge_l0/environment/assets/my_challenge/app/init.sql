-- PostgreSQL initialization script for access control challenges
\c access_db;

-- Users table for access control testing
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Documents table with sensitive information
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    owner_id INTEGER REFERENCES users(id),
    access_level VARCHAR(20) DEFAULT 'private',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Access logs table
CREATE TABLE access_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    document_id INTEGER REFERENCES documents(id),
    action VARCHAR(50),
    ip_address INET,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Secret admin table (should be hidden)
CREATE TABLE admin_secrets (
    id SERIAL PRIMARY KEY,
    secret_key VARCHAR(100),
    secret_value TEXT,
    classification VARCHAR(20)
);

-- Insert sample users (passwords are intentionally weak)
INSERT INTO users (username, password_hash, email, role) VALUES
('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeAH', 'admin@company.com', 'admin'),
('manager', '$2b$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'manager@company.com', 'manager'),
('employee1', 'password123', 'emp1@company.com', 'user'),
('employee2', 'qwerty456', 'emp2@company.com', 'user'),
('guest', 'guest', 'guest@company.com', 'guest');

-- Insert sample documents with various access levels
INSERT INTO documents (title, content, owner_id, access_level) VALUES
('Public Announcement', 'This is a public document available to everyone.', 1, 'public'),
('Team Meeting Notes', 'Confidential meeting notes for the development team.', 2, 'team'),
('Admin Configuration', 'Sensitive configuration data. FLAG: CTF{4cc3ss_c0ntr0l_pwn3d_2025}', 1, 'admin'),
('Personal Notes', 'Employee personal notes and reminders.', 3, 'private'),
('HR Document', 'Confidential HR policy document.', 2, 'confidential'),
('System Backup Info', 'Database backup schedules and procedures.', 1, 'admin');

-- Insert admin secrets (hidden flags)
INSERT INTO admin_secrets (secret_key, secret_value, classification) VALUES
('backup_location', '/var/backups/secret_db_backup_2025.sql', 'confidential'),
('api_master_key', 'CTF{m4st3r_4p1_k3y_3xp0s3d_2025}', 'top_secret'),
('encryption_key', 'AES256_KEY_1234567890ABCDEF', 'secret'),
('admin_backdoor', 'CTF{b4ckd00r_4cc3ss_gr4nt3d_2025}', 'top_secret');

-- Create a view that might expose sensitive data
CREATE VIEW user_summary AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.role,
    COUNT(d.id) as document_count
FROM users u
LEFT JOIN documents d ON u.id = d.owner_id
GROUP BY u.id, u.username, u.email, u.role;

-- Grant permissions to ctf_user
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO ctf_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ctf_user; 