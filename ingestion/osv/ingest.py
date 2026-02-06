"""
OSV (Open Source Vulnerabilities) Ingestion Script

Source: https://osv.dev/
Data: Vulnerabilities mapped to specific package versions
"""
import sys
from pathlib import Path

# Add ingestion directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import requests
import json
from datetime import datetime
from db_utils import get_connection

# API endpoint
OSV_API_URL = "https://api.osv.dev/v1/vulns"

# Ecosystems we care about (add more as needed)
ECOSYSTEMS = ["PyPI", "npm", "Maven", "Go", "crates.io"]

# Sample packages to query (for demo purposes)
# In production, you'd have a list of packages your company uses
SAMPLE_PACKAGES = [
    {"ecosystem": "PyPI", "name": "requests"},
    {"ecosystem": "PyPI", "name": "django"},
    {"ecosystem": "PyPI", "name": "flask"},
    {"ecosystem": "PyPI", "name": "numpy"},
    {"ecosystem": "PyPI", "name": "pandas"},
    {"ecosystem": "npm", "name": "lodash"},
    {"ecosystem": "npm", "name": "express"},
    {"ecosystem": "npm", "name": "axios"},
    {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
    {"ecosystem": "Maven", "name": "com.fasterxml.jackson.core:jackson-databind"},
]


def fetch_vulnerabilities_for_package(ecosystem, package_name):
    """Query OSV for vulnerabilities affecting a specific package."""
    url = "https://api.osv.dev/v1/query"
    
    payload = {
        "package": {
            "ecosystem": ecosystem,
            "name": package_name
        }
    }
    
    response = requests.post(url, json=payload)
    response.raise_for_status()
    
    data = response.json()
    return data.get("vulns", [])


def fetch_vulnerability_details(vuln_id):
    """Fetch full details for a specific vulnerability."""
    url = f"{OSV_API_URL}/{vuln_id}"
    
    response = requests.get(url)
    response.raise_for_status()
    
    return response.json()


def extract_cve_id(aliases):
    """Extract CVE ID from aliases list."""
    if not aliases:
        return None
    
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias
    
    return None


def extract_severity(vuln):
    """Extract severity from various possible locations."""
    # Try database_specific first
    db_specific = vuln.get("database_specific", {})
    if db_specific.get("severity"):
        return db_specific.get("severity")
    
    # Try severity array
    severity_list = vuln.get("severity", [])
    for sev in severity_list:
        if sev.get("type") == "CVSS_V3":
            score = sev.get("score", "")
            # Extract severity from CVSS vector if present
            if "CVSS:3" in score:
                return None  # We'd need to calculate, skip for now
    
    return None


def parse_vulnerability(vuln):
    """
    Parse vulnerability for main table.
    
    Returns:
        Tuple matching raw.osv_vulnerabilities columns
    """
    return (
        vuln.get("id"),
        extract_cve_id(vuln.get("aliases", [])),
        vuln.get("summary"),
        vuln.get("details"),
        vuln.get("published"),
        vuln.get("modified"),
        extract_severity(vuln),
        json.dumps(vuln)
    )


def parse_affected_packages(vuln):
    """
    Parse affected packages from vulnerability.
    
    Returns:
        List of tuples matching raw.osv_affected_packages columns
    """
    affected_list = []
    osv_id = vuln.get("id")
    
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        package_name = package.get("name")
        ecosystem = package.get("ecosystem")
        
        # Extract version ranges
        version_introduced = None
        version_fixed = None
        
        for range_info in affected.get("ranges", []):
            for event in range_info.get("events", []):
                if "introduced" in event:
                    version_introduced = event["introduced"]
                if "fixed" in event:
                    version_fixed = event["fixed"]
        
        # Get explicit affected versions
        affected_versions = affected.get("versions", [])
        
        affected_list.append((
            osv_id,
            package_name,
            ecosystem,
            version_introduced,
            version_fixed,
            affected_versions if affected_versions else None
        ))
    
    return affected_list


def load_vulnerability(cursor, vuln):
    """Load a single vulnerability and its affected packages."""
    # Insert main vulnerability record
    vuln_query = """
        INSERT INTO raw.osv_vulnerabilities (
            osv_id, cve_id, summary, details,
            published_date, modified_date, severity, raw_json
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (osv_id) DO UPDATE SET
            cve_id = EXCLUDED.cve_id,
            summary = EXCLUDED.summary,
            details = EXCLUDED.details,
            published_date = EXCLUDED.published_date,
            modified_date = EXCLUDED.modified_date,
            severity = EXCLUDED.severity,
            raw_json = EXCLUDED.raw_json,
            ingested_at = CURRENT_TIMESTAMP;
    """
    
    parsed_vuln = parse_vulnerability(vuln)
    cursor.execute(vuln_query, parsed_vuln)
    
    # Insert affected packages
    affected_query = """
        INSERT INTO raw.osv_affected_packages (
            osv_id, package_name, ecosystem,
            version_introduced, version_fixed, affected_versions
        ) VALUES (%s, %s, %s, %s, %s, %s);
    """
    
    # Delete old affected packages for this vulnerability (to avoid duplicates)
    cursor.execute("DELETE FROM raw.osv_affected_packages WHERE osv_id = %s", (vuln.get("id"),))
    
    for affected in parse_affected_packages(vuln):
        cursor.execute(affected_query, affected)


def main():
    """Main ingestion pipeline."""
    print("=" * 50)
    print("OSV Ingestion")
    print(f"Started at: {datetime.now()}")
    print("=" * 50)
    
    conn = get_connection()
    cursor = conn.cursor()
    
    seen_vulns = set()  # Track already processed vulnerabilities
    total_vulns = 0
    total_packages = 0
    
    for package in SAMPLE_PACKAGES:
        ecosystem = package["ecosystem"]
        name = package["name"]
        
        print(f"\nQuerying {ecosystem}/{name}...")
        
        try:
            vulns = fetch_vulnerabilities_for_package(ecosystem, name)
            print(f"  Found {len(vulns)} vulnerabilities")
            
            for vuln in vulns:
                vuln_id = vuln.get("id")
                
                # Skip if already processed
                if vuln_id in seen_vulns:
                    continue
                
                seen_vulns.add(vuln_id)
                
                # Fetch full details
                full_vuln = fetch_vulnerability_details(vuln_id)
                
                # Load to database
                load_vulnerability(cursor, full_vuln)
                total_vulns += 1
                total_packages += len(full_vuln.get("affected", []))
                
        except Exception as e:
            print(f"  Error: {e}")
            continue
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print("\n" + "=" * 50)
    print(f"Loaded {total_vulns} vulnerabilities")
    print(f"Loaded {total_packages} affected package records")
    print(f"Completed at: {datetime.now()}")
    print("=" * 50)


if __name__ == "__main__":
    main()