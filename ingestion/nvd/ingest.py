"""
NVD (National Vulnerability Database) Ingestion Script

Source: https://nvd.nist.gov/
Data: Official CVE records with severity scores
"""
import sys
sys.path.append('..')

import requests
import json
import time
from datetime import datetime, timedelta
from db_utils import get_connection

# API endpoint
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# How many days back to fetch (adjust as needed)
LOOKBACK_DAYS = 30

# NVD returns max 2000 per request
PAGE_SIZE = 2000

# Delay between requests (NVD rate limit: 5 requests per 30 seconds without API key)
REQUEST_DELAY = 6


def get_date_range():
    """Calculate date range for API query."""
    end_date = datetime.now()
    start_date = end_date - timedelta(days=LOOKBACK_DAYS)
    
    # NVD requires ISO format with timezone
    start_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
    end_str = end_date.strftime("%Y-%m-%dT23:59:59.999")
    
    return start_str, end_str


def fetch_nvd_page(start_index, start_date, end_date):
    """Fetch a single page of CVEs from NVD."""
    params = {
        "lastModStartDate": start_date,
        "lastModEndDate": end_date,
        "startIndex": start_index,
        "resultsPerPage": PAGE_SIZE
    }
    
    response = requests.get(NVD_BASE_URL, params=params)
    response.raise_for_status()
    
    return response.json()


def fetch_all_cves():
    """Fetch all CVEs within date range, handling pagination."""
    start_date, end_date = get_date_range()
    print(f"Fetching CVEs modified between {start_date} and {end_date}")
    
    all_cves = []
    start_index = 0
    total_results = None
    
    while True:
        print(f"Fetching from index {start_index}...")
        
        data = fetch_nvd_page(start_index, start_date, end_date)
        
        # First request tells us total count
        if total_results is None:
            total_results = data.get("totalResults", 0)
            print(f"Total CVEs to fetch: {total_results}")
        
        vulnerabilities = data.get("vulnerabilities", [])
        all_cves.extend(vulnerabilities)
        
        # Check if we've fetched all
        if start_index + PAGE_SIZE >= total_results:
            break
        
        start_index += PAGE_SIZE
        
        # Rate limiting
        print(f"Waiting {REQUEST_DELAY} seconds (rate limit)...")
        time.sleep(REQUEST_DELAY)
    
    print(f"Fetched {len(all_cves)} CVEs total")
    return all_cves


def extract_cvss_v31(metrics):
    """Extract CVSS v3.1 score from metrics object."""
    if not metrics:
        return None, None, None
    
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if not cvss_v31:
        return None, None, None
    
    # Get primary score (usually first one from NVD)
    primary = cvss_v31[0].get("cvssData", {})
    
    return (
        primary.get("baseScore"),
        primary.get("baseSeverity"),
        primary.get("vectorString")
    )


def extract_cwe(weaknesses):
    """Extract primary CWE ID from weaknesses list."""
    if not weaknesses:
        return None
    
    for weakness in weaknesses:
        descriptions = weakness.get("description", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                return desc.get("value")
    
    return None


def extract_description(descriptions):
    """Extract English description."""
    if not descriptions:
        return None
    
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value")
    
    return descriptions[0].get("value") if descriptions else None


def parse_cve(vuln_wrapper):
    """
    Parse a single CVE record.
    
    Args:
        vuln_wrapper: Dict containing 'cve' key with CVE data
        
    Returns:
        Tuple matching raw.nvd_cves table columns
    """
    cve = vuln_wrapper.get("cve", {})
    
    cvss_score, cvss_severity, cvss_vector = extract_cvss_v31(cve.get("metrics"))
    cwe_id = extract_cwe(cve.get("weaknesses"))
    description = extract_description(cve.get("descriptions"))
    
    return (
        cve.get("id"),
        cve.get("sourceIdentifier"),
        cve.get("vulnStatus"),
        cve.get("published"),
        cve.get("lastModified"),
        description,
        cvss_score,
        cvss_severity,
        cvss_vector,
        cwe_id,
        json.dumps(vuln_wrapper)
    )


def load_to_database(cves):
    """Load CVEs into raw.nvd_cves table using upsert."""
    conn = get_connection()
    cursor = conn.cursor()
    
    insert_query = """
        INSERT INTO raw.nvd_cves (
            cve_id,
            source_identifier,
            vuln_status,
            published_date,
            last_modified_date,
            description,
            cvss_v31_score,
            cvss_v31_severity,
            cvss_v31_vector,
            cwe_id,
            raw_json
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        )
        ON CONFLICT (cve_id) DO UPDATE SET
            source_identifier = EXCLUDED.source_identifier,
            vuln_status = EXCLUDED.vuln_status,
            published_date = EXCLUDED.published_date,
            last_modified_date = EXCLUDED.last_modified_date,
            description = EXCLUDED.description,
            cvss_v31_score = EXCLUDED.cvss_v31_score,
            cvss_v31_severity = EXCLUDED.cvss_v31_severity,
            cvss_v31_vector = EXCLUDED.cvss_v31_vector,
            cwe_id = EXCLUDED.cwe_id,
            raw_json = EXCLUDED.raw_json,
            ingested_at = CURRENT_TIMESTAMP;
    """
    
    success_count = 0
    error_count = 0
    
    for cve in cves:
        try:
            parsed = parse_cve(cve)
            cursor.execute(insert_query, parsed)
            success_count += 1
        except Exception as e:
            cve_id = cve.get("cve", {}).get("id", "unknown")
            print(f"Error inserting {cve_id}: {e}")
            error_count += 1
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print(f"Loaded {success_count} records, {error_count} errors")


def main():
    """Main ingestion pipeline."""
    print("=" * 50)
    print("NVD Ingestion")
    print(f"Started at: {datetime.now()}")
    print("=" * 50)
    
    # Extract
    cves = fetch_all_cves()
    
    # Load
    if cves:
        load_to_database(cves)
    else:
        print("No CVEs to load")
    
    print("=" * 50)
    print(f"Completed at: {datetime.now()}")
    print("=" * 50)


if __name__ == "__main__":
    main()