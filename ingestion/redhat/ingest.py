"""
Red Hat Security Data Ingestion Script

Source: https://access.redhat.com/hydra/rest/securitydata/
Data: RHEL-specific advisories, patches, and fix states
"""
import sys
sys.path.append('..')

import requests
import json
import time
from datetime import datetime
from db_utils import get_connection

# API endpoint
REDHAT_API_URL = "https://access.redhat.com/hydra/rest/securitydata/cve"

# Delay between requests (be nice to their API)
REQUEST_DELAY = 1


def get_cve_ids_to_fetch():
    """
    Get CVE IDs from our existing data to look up in Red Hat.
    Prioritizes CISA KEV (actively exploited) and high-severity NVD CVEs.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get CVEs from CISA KEV (high priority)
    cursor.execute("SELECT cve_id FROM raw.cisa_kev")
    kev_cves = [row[0] for row in cursor.fetchall()]
    
    # Get high/critical CVEs from NVD
    cursor.execute("""
        SELECT cve_id FROM raw.nvd_cves 
        WHERE cvss_v31_severity IN ('HIGH', 'CRITICAL')
        LIMIT 200
    """)
    nvd_cves = [row[0] for row in cursor.fetchall()]
    
    cursor.close()
    conn.close()
    
    # Combine and deduplicate
    all_cves = list(set(kev_cves + nvd_cves))
    print(f"Found {len(kev_cves)} CISA KEV CVEs")
    print(f"Found {len(nvd_cves)} high/critical NVD CVEs")
    print(f"Total unique CVEs to query: {len(all_cves)}")
    
    return all_cves


def fetch_redhat_cve(cve_id):
    """Fetch Red Hat data for a single CVE."""
    url = f"{REDHAT_API_URL}/{cve_id}.json"
    
    headers = {
        "User-Agent": "VulnIntelPlatform/1.0 (learning project)"
    }
    
    response = requests.get(url, headers=headers)
    
    # Red Hat returns 404 for CVEs they don't track
    if response.status_code == 404:
        return None
    
    response.raise_for_status()
    return response.json()


def parse_cve(data):
    """
    Parse main CVE record from Red Hat response.
    
    Returns:
        Tuple matching raw.redhat_cves columns
    """
    bugzilla = data.get("bugzilla", {})
    cvss3 = data.get("cvss3", {})
    
    # Details is sometimes a list, sometimes a string
    details = data.get("details", [])
    if isinstance(details, list):
        details = " ".join(details)
    
    return (
        data.get("name"),              # CVE ID field is "name"
        data.get("threat_severity"),   # Severity field is "threat_severity"
        data.get("public_date"),
        bugzilla.get("id"),
        bugzilla.get("description"),
        cvss3.get("cvss3_base_score"),
        cvss3.get("cvss3_scoring_vector"),
        details,
        data.get("statement"),
        json.dumps(data)
    )


def parse_affected_releases(data):
    """
    Parse affected releases from Red Hat response.
    
    Returns:
        List of tuples matching raw.redhat_affected_releases columns
    """
    cve_id = data.get("name")  # CVE ID field is "name"
    releases = []
    
    # Parse affected_release (has patches)
    for release in data.get("affected_release", []):
        releases.append((
            cve_id,
            release.get("product_name"),
            release.get("release_date"),
            release.get("advisory"),
            release.get("package"),
            "Fixed"  # Has a release, so it's fixed
        ))
    
    # Parse package_state (may or may not have fixes)
    for state in data.get("package_state", []):
        releases.append((
            cve_id,
            state.get("product_name"),
            None,  # No release date for package_state
            None,  # No advisory
            state.get("package_name"),
            state.get("fix_state")  # "Not affected", "Will not fix", etc.
        ))
    
    return releases


def load_cve(cursor, data):
    """Load a single CVE and its affected releases."""
    
    # Insert main CVE record
    cve_query = """
        INSERT INTO raw.redhat_cves (
            cve_id, severity, public_date, bugzilla_id,
            bugzilla_description, cvss3_score, cvss3_vector,
            details, statement, raw_json
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE SET
            severity = EXCLUDED.severity,
            public_date = EXCLUDED.public_date,
            bugzilla_id = EXCLUDED.bugzilla_id,
            bugzilla_description = EXCLUDED.bugzilla_description,
            cvss3_score = EXCLUDED.cvss3_score,
            cvss3_vector = EXCLUDED.cvss3_vector,
            details = EXCLUDED.details,
            statement = EXCLUDED.statement,
            raw_json = EXCLUDED.raw_json,
            ingested_at = CURRENT_TIMESTAMP;
    """
    
    parsed_cve = parse_cve(data)
    cursor.execute(cve_query, parsed_cve)
    
    # Delete old affected releases
    cursor.execute(
        "DELETE FROM raw.redhat_affected_releases WHERE cve_id = %s",
        (data.get("name"),)
    )
    
    # Insert affected releases
    release_query = """
        INSERT INTO raw.redhat_affected_releases (
            cve_id, product_name, release_date,
            advisory_id, package_name, fix_state
        ) VALUES (%s, %s, %s, %s, %s, %s);
    """
    
    for release in parse_affected_releases(data):
        cursor.execute(release_query, release)


def main():
    """Main ingestion pipeline."""
    print("=" * 50)
    print("Red Hat Security Data Ingestion")
    print(f"Started at: {datetime.now()}")
    print("=" * 50)
    
    # Get CVEs to look up
    cve_ids = get_cve_ids_to_fetch()
    
    if not cve_ids:
        print("No CVEs to fetch. Run NVD or CISA KEV ingestion first.")
        return
    
    conn = get_connection()
    cursor = conn.cursor()
    
    found_count = 0
    not_found_count = 0
    error_count = 0
    
    for i, cve_id in enumerate(cve_ids):
        # Progress indicator
        if (i + 1) % 50 == 0:
            print(f"Progress: {i + 1}/{len(cve_ids)}")
        
        try:
            data = fetch_redhat_cve(cve_id)
            
            if data is None:
                not_found_count += 1
                continue
            
            load_cve(cursor, data)
            found_count += 1
            
            # Rate limiting
            time.sleep(REQUEST_DELAY)
            
        except Exception as e:
            print(f"Error fetching {cve_id}: {e}")
            error_count += 1
            continue
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print("\n" + "=" * 50)
    print(f"Found in Red Hat: {found_count}")
    print(f"Not tracked by Red Hat: {not_found_count}")
    print(f"Errors: {error_count}")
    print(f"Completed at: {datetime.now()}")
    print("=" * 50)


if __name__ == "__main__":
    main()