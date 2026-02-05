

select
    cve_id,
    description,
    cvss_score,
    cvss_severity,
    is_cisa_kev,
    known_ransomware_use,
    published_date,
    kev_due_date
from "vuln_db"."staging_marts"."dim_vulnerabilities"
where 
    cvss_severity in ('critical', 'high')
    or is_cisa_kev = true
order by 
    is_cisa_kev desc,
    cvss_score desc nulls last