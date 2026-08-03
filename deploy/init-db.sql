-- MALINFO Database Initialization Script
-- Run this on first database setup to create extensions and initial data

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create indexes for better performance (will be created by SQLAlchemy but good to have explicitly)
-- These are created after tables exist

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for samples table (will be added after table creation)
-- CREATE TRIGGER update_samples_updated_at BEFORE UPDATE ON samples
-- FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create trigger for users table
-- CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
-- FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Default admin user (password should be changed immediately)
-- Password: Admin@123 (bcrypt hashed)
-- INSERT INTO users (id, username, email, full_name, hashed_password, role, is_active, is_verified, created_at, updated_at)
-- VALUES (uuid_generate_v4(), 'admin', 'admin@malinfo.example.gov', 'System Administrator', 
--         '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/RK.PZvO.S', 
--         'admin', true, true, NOW(), NOW())
-- ON CONFLICT (username) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO malinfo;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO malinfo;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO malinfo;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO malinfo;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO malinfo;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO malinfo;