

with packages as (
    select distinct
        package_name,
        ecosystem
    from "vuln_db"."staging_intermediate"."int_package_vulnerabilities"
    where package_name is not null
)

select
    md5(cast(coalesce(cast(package_name as TEXT), '_dbt_utils_surrogate_key_null_') || '-' || coalesce(cast(ecosystem as TEXT), '_dbt_utils_surrogate_key_null_') as TEXT)) as package_id,
    package_name,
    ecosystem
from packages