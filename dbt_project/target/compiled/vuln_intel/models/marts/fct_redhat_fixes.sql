

select
    cve_id,
    product_name,
    release_date,
    advisory_id,
    package_name,
    fix_state,
    cvss_score,
    cvss_severity,
    is_cisa_kev
from "vuln_db"."staging_intermediate"."int_redhat_fixes"