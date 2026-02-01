"""
Create raw tables for each data source.
Run once to set up the database schema.
"""
from db_utils import execute_query


def create_raw_nvd_table():
    """Create raw table for NVD CVE data."""
    query = """
    CREATE TABLE IF NOT EXISTS raw.nvd_cves (
        cve_id VARCHAR(20) PRIMARY KEY,
        source_identifier VARCHAR(255),
        vuln_status VARCHAR(50),
        published_date TIMESTAMP,
        last_modified_date TIMESTAMP,
        description TEXT,
        cvss_v31_score DECIMAL(3,1),
        cvss_v31_severity VARCHAR(20),
        cvss_v31_vector TEXT,
        cwe_id VARCHAR(20),
        raw_json JSONB,
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    execute_query(query)
    print("Created raw.nvd_cves table")


def create_raw_osv_table():
    """Create raw table for OSV vulnerability data."""
    query = """
    CREATE TABLE IF NOT EXISTS raw.osv_vulnerabilities (
        osv_id VARCHAR(50) PRIMARY KEY,
        cve_id VARCHAR(20),
        summary TEXT,
        details TEXT,
        published_date TIMESTAMP,
        modified_date TIMESTAMP,
        severity VARCHAR(20),
        raw_json JSONB,
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    execute_query(query)
    print("Created raw.osv_vulnerabilities table")


def create_raw_osv_affected_table():
    """Create raw table for OSV affected packages."""
    query = """
    CREATE TABLE IF NOT EXISTS raw.osv_affected_packages (
        id SERIAL PRIMARY KEY,
        osv_id VARCHAR(50),
        package_name VARCHAR(255),
        ecosystem VARCHAR(50),
        version_introduced VARCHAR(50),
        version_fixed VARCHAR(50),
        affected_versions TEXT[],
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    execute_query(query)
    print("Created raw.osv_affected_packages table")


def create_raw_redhat_table():
    """Create raw table for Red Hat advisory data."""
    query = """
    CREATE TABLE IF NOT EXISTS raw.redhat_cves (
        cve_id VARCHAR(20) PRIMARY KEY,
        severity VARCHAR(20),
        public_date TIMESTAMP,
        bugzilla_id VARCHAR(20),
        bugzilla_description TEXT,
        cvss3_score DECIMAL(3,1),
        cvss3_vector TEXT,
        details TEXT,
        statement TEXT,
        raw_json JSONB,
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    execute_query(query)
    print("Created raw.redhat_cves table")


def create_raw_redhat_affected_table():
    """Create raw table for Red Hat affected releases."""
    query = """
    CREATE TABLE IF NOT EXISTS raw.redhat_affected_releases (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(20),
        product_name VARCHAR(255),
        release_date TIMESTAMP,
        advisory_id VARCHAR(50),
        package_name TEXT,
        fix_state VARCHAR(50),
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    execute_query(query)
    print("Created raw.redhat_affected_releases table")


def create_raw_cisa_kev_table():
    """Create raw table for CISA KEV data."""
    query = """
    CREATE TABLE IF NOT EXISTS raw.cisa_kev (
        cve_id VARCHAR(20) PRIMARY KEY,
        vendor_project VARCHAR(255),
        product VARCHAR(255),
        vulnerability_name TEXT,
        date_added DATE,
        short_description TEXT,
        required_action TEXT,
        due_date DATE,
        known_ransomware_use VARCHAR(20),
        raw_json JSONB,
        ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    execute_query(query)
    print("Created raw.cisa_kev table")


def main():
    """Create all raw tables."""
    print("Creating raw tables...")
    create_raw_nvd_table()
    create_raw_osv_table()
    create_raw_osv_affected_table()
    create_raw_redhat_table()
    create_raw_redhat_affected_table()
    create_raw_cisa_kev_table()
    print("All raw tables created successfully!")


if __name__ == "__main__":
    main()