
  create view "vuln_db"."staging_intermediate"."int_redhat_fixes__dbt_tmp"
    
    
  as (
    

with releases as (
    select
        cve_id,
        product_name,
        release_date,
        advisory_id,
        package_name,
        fix_state
    from "vuln_db"."staging_staging"."stg_redhat_affected_releases"
),

unified_vulns as (
    select
        cve_id,
        cvss_score,
        cvss_severity,
        is_cisa_kev
    from "vuln_db"."staging_intermediate"."int_unified_vulnerabilities"
),

redhat_fixes as (
    select
        r.cve_id,
        r.product_name,
        r.release_date,
        r.advisory_id,
        r.package_name,
        r.fix_state,
        uv.cvss_score,
        uv.cvss_severity,
        uv.is_cisa_kev
    from releases r
    left join unified_vulns uv on r.cve_id = uv.cve_id
)

select * from redhat_fixes
  );