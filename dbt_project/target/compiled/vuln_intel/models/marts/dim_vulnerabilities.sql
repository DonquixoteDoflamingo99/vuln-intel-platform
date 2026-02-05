

select
    cve_id,
    description,
    cvss_score,
    cvss_severity,
    cvss_vector,
    cwe_id,
    published_date,
    last_modified_date,
    is_cisa_kev,
    kev_date_added,
    kev_due_date,
    known_ransomware_use,
    osv_id,
    in_nvd,
    in_osv,
    in_redhat
from "vuln_db"."staging_intermediate"."int_unified_vulnerabilities"