
  create view "vuln_db"."staging_staging"."stg_redhat_cves__dbt_tmp"
    
    
  as (
    with source as (
    select * from "vuln_db"."raw"."redhat_cves"
),

staged as (
    select
        cve_id,
        severity,
        public_date,
        bugzilla_id,
        bugzilla_description,
        cvss3_score,
        cvss3_vector,
        details,
        statement,
        ingested_at
    from source
)

select * from staged
  );