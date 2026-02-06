"""
CISA KEV (Known Exploited Vulnerabilities) Ingestion Script

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Data: List of vulnerabilities actively exploited in the wild
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
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_data():
    """Download CISA KEV JSON file."""
    print(f"Fetching data from CISA KEV...")
    response = requests.get(CISA_KEV_URL)
    response.raise_for_status()
    data = response.json()
    print(f"Found {len(data['vulnerabilities'])} vulnerabilities")
    return data


def parse_vulnerability(vuln):
    """
    Parse a single vulnerability record.
    
    Args:
        vuln: Raw vulnerability dict from API
        
    Returns:
        Tuple of values matching raw.cisa_kev table columns
    """
    return (
        vuln.get('cveID'),
        vuln.get('vendorProject'),
        vuln.get('product'),
        vuln.get('vulnerabilityName'),
        vuln.get('dateAdded'),
        vuln.get('shortDescription'),
        vuln.get('requiredAction'),
        vuln.get('dueDate'),
        vuln.get('knownRansomwareCampaignUse'),
        json.dumps(vuln)  # Store raw JSON for reference
    )


def load_to_database(vulnerabilities):
    """
    Load vulnerabilities into raw.cisa_kev table.
    Uses upsert (insert or update) to handle re-runs.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    insert_query = """
        INSERT INTO raw.cisa_kev (
            cve_id,
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            short_description,
            required_action,
            due_date,
            known_ransomware_use,
            raw_json
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (cve_id) DO UPDATE SET
            vendor_project = EXCLUDED.vendor_project,
            product = EXCLUDED.product,
            vulnerability_name = EXCLUDED.vulnerability_name,
            date_added = EXCLUDED.date_added,
            short_description = EXCLUDED.short_description,
            required_action = EXCLUDED.required_action,
            due_date = EXCLUDED.due_date,
            known_ransomware_use = EXCLUDED.known_ransomware_use,
            raw_json = EXCLUDED.raw_json,
            ingested_at = CURRENT_TIMESTAMP;
    """
    
    success_count = 0
    error_count = 0
    
    for vuln in vulnerabilities:
        try:
            parsed = parse_vulnerability(vuln)
            cursor.execute(insert_query, parsed)
            success_count += 1
        except Exception as e:
            print(f"Error inserting {vuln.get('cveID')}: {e}")
            error_count += 1
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print(f"Loaded {success_count} records, {error_count} errors")


def main():
    """Main ingestion pipeline."""
    print("=" * 50)
    print("CISA KEV Ingestion")
    print(f"Started at: {datetime.now()}")
    print("=" * 50)
    
    # Extract
    data = fetch_kev_data()
    
    # Load
    load_to_database(data['vulnerabilities'])
    
    print("=" * 50)
    print(f"Completed at: {datetime.now()}")
    print("=" * 50)


if __name__ == "__main__":
    main()