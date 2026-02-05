
  create view "vuln_db"."staging_staging"."stg_osv_affected_packages__dbt_tmp"
    
    
  as (
    with source as (
    select * from "vuln_db"."raw"."osv_affected_packages"
),

staged as (
    select
        id,
        osv_id,
        package_name,
        ecosystem,
        version_introduced,
        version_fixed,
        affected_versions,
        ingested_at
    from source
)

select * from staged
  );