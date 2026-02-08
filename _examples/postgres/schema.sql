-- PostgreSQL schema for swg blocklist
-- Run this to set up the database table

CREATE TABLE IF NOT EXISTS blocklist (
    id SERIAL PRIMARY KEY,
    rule_type VARCHAR(10) NOT NULL CHECK (rule_type IN ('domain', 'url', 'regex')),
    pattern VARCHAR(500) NOT NULL,
    reason VARCHAR(255) DEFAULT 'blocked by policy',
    category VARCHAR(100),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for efficient querying of enabled rules
CREATE INDEX IF NOT EXISTS idx_blocklist_enabled ON blocklist(enabled) WHERE enabled = true;

-- Index for category filtering
CREATE INDEX IF NOT EXISTS idx_blocklist_category ON blocklist(category);

-- Sample data
INSERT INTO blocklist (rule_type, pattern, reason, category) VALUES
    ('domain', 'ads.example.com', 'advertising content', 'ads'),
    ('domain', '*.tracking.com', 'user tracking', 'analytics'),
    ('domain', 'malware.bad.com', 'known malware host', 'security'),
    ('url', 'https://phishing.example.com/login', 'phishing attempt', 'security'),
    ('url', 'http://spam.com/offers', 'spam content', 'spam'),
    ('regex', '.*\.doubleclick\.net.*', 'advertising tracker', 'ads'),
    ('regex', '.*analytics.*\.js$', 'analytics script', 'analytics');

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to auto-update updated_at
DROP TRIGGER IF EXISTS update_blocklist_updated_at ON blocklist;
CREATE TRIGGER update_blocklist_updated_at
    BEFORE UPDATE ON blocklist
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
