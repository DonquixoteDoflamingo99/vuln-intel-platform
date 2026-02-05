
  
    

  create  table "vuln_db"."staging_marts"."fct_package_vulnerabilities__dbt_tmp"
  
  
    as
  
  (
    

select
    osv_id,
    cve_id,
    package_name,
    ecosystem,
    version_introduced,
    version_fixed,
    affected_versions,
    cvss_score,
    cvss_severity,
    is_cisa_kev
from "vuln_db"."staging_intermediate"."int_package_vulnerabilities"
  );
  