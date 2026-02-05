
  create view "vuln_db"."staging_staging"."stg_osv_vulnerabilities__dbt_tmp"
    
    
  as (
    with source as (
    select * from "vuln_db"."raw"."osv_vulnerabilities"
),

staged as (
    select
        osv_id,
        cve_id,
        summary,
        details,
        published_date,
        modified_date,
        severity,
        ingested_at
    from source
)

select * from staged
  );