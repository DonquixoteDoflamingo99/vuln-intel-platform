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