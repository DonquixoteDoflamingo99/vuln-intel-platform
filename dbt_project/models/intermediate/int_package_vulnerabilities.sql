{{
    config(
        materialized='view'
    )
}}

with osv_packages as (
    select
        osv_id,
        package_name,
        ecosystem,
        version_introduced,
        version_fixed,
        affected_versions
    from {{ ref('stg_osv_affected_packages') }}
),

osv_vulns as (
    select
        osv_id,
        cve_id
    from {{ ref('stg_osv_vulnerabilities') }}
),

unified_vulns as (
    select
        cve_id,
        cvss_score,
        cvss_severity,
        is_cisa_kev
    from {{ ref('int_unified_vulnerabilities') }}
),

package_vulns as (
    select
        p.osv_id,
        v.cve_id,
        p.package_name,
        p.ecosystem,
        p.version_introduced,
        p.version_fixed,
        p.affected_versions,
        uv.cvss_score,
        uv.cvss_severity,
        uv.is_cisa_kev
    from osv_packages p
    inner join osv_vulns v on p.osv_id = v.osv_id
    left join unified_vulns uv on v.cve_id = uv.cve_id
)

select * from package_vulns