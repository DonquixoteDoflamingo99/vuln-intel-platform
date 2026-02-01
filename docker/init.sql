-- Create schemas for layered architecture
CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS staging;
CREATE SCHEMA IF NOT EXISTS intermediate;
CREATE SCHEMA IF NOT EXISTS marts;

-- Grant permissions
GRANT ALL ON SCHEMA raw TO vuln_user;
GRANT ALL ON SCHEMA staging TO vuln_user;
GRANT ALL ON SCHEMA intermediate TO vuln_user;
GRANT ALL ON SCHEMA marts TO vuln_user;