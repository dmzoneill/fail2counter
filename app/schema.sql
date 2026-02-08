-- fail2counter database schema (PostgreSQL)
-- All tables use CREATE TABLE IF NOT EXISTS for idempotent deployment

CREATE TABLE IF NOT EXISTS hosts (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    host_id INT NOT NULL,
    scan_time TIMESTAMP NOT NULL,
    scan_type VARCHAR(50),
    latency_seconds REAL,
    duration_seconds REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ports (
    id SERIAL PRIMARY KEY,
    scan_id INT NOT NULL,
    port_number INT NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp',
    state VARCHAR(20) DEFAULT 'open',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
    id SERIAL PRIMARY KEY,
    port_id INT NOT NULL,
    service_name VARCHAR(100),
    product VARCHAR(255),
    version VARCHAR(100),
    extra_info VARCHAR(255),
    is_ssl BOOLEAN DEFAULT FALSE,
    recognized BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS exploits (
    id SERIAL PRIMARY KEY,
    scan_id INT NOT NULL,
    host_id INT NOT NULL,
    module_path VARCHAR(500) NOT NULL,
    rhosts VARCHAR(45),
    rport INT,
    rc_file_path VARCHAR(500),
    status VARCHAR(20) DEFAULT 'suggested',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_exploits_host ON exploits(host_id);
CREATE INDEX IF NOT EXISTS idx_exploits_status ON exploits(status);

CREATE TABLE IF NOT EXISTS exploit_results (
    id SERIAL PRIMARY KEY,
    exploit_id INT NOT NULL,
    output_text TEXT,
    exit_code INT,
    duration_seconds REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (exploit_id) REFERENCES exploits(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    host_id INT NOT NULL,
    exploit_id INT,
    notification_type VARCHAR(20) DEFAULT 'email',
    status VARCHAR(20) DEFAULT 'pending',
    contact_info VARCHAR(500),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY (exploit_id) REFERENCES exploits(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status);
CREATE INDEX IF NOT EXISTS idx_notifications_host ON notifications(host_id);
