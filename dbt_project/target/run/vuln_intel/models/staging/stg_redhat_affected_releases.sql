
  create view "vuln_db"."staging_staging"."stg_redhat_affected_releases__dbt_tmp"
    
    
  as (
    with source as (
    select * from "vuln_db"."raw"."redhat_affected_releases"
),

staged as (
    select
        id,
        cve_id,
        product_name,
        release_date,
        advisory_id,
        package_name,
        fix_state,
        ingested_at
    from source
)

select * from staged
  );