{{
    config(
        materialized='table'
    )
}}

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
from {{ ref('int_package_vulnerabilities') }}