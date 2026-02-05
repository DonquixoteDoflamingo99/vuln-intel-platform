{{
    config(
        materialized='table'
    )
}}

with packages as (
    select distinct
        package_name,
        ecosystem
    from {{ ref('int_package_vulnerabilities') }}
    where package_name is not null
)

select
    {{ dbt_utils.generate_surrogate_key(['package_name', 'ecosystem']) }} as package_id,
    package_name,
    ecosystem
from packages