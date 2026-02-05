{{
    config(
        materialized='view'
    )
}}

with nvd as (
    select
        cve_id,
        description,
        cvss_v31_score as cvss_score,
        cvss_severity,
        cvss_v31_vector as cvss_vector,
        cwe_id,
        published_date,
        last_modified_date,
        'nvd' as primary_source
    from {{ ref('stg_nvd_cves') }}
),

cisa_kev as (
    select
        cve_id,
        vulnerability_name,
        date_added as kev_date_added,
        due_date as kev_due_date,
        known_ransomware_use
    from {{ ref('stg_cisa_kev') }}
),

osv as (
    select
        cve_id,
        osv_id,
        summary as osv_summary,
        severity as osv_severity
    from {{ ref('stg_osv_vulnerabilities') }}
    where cve_id is not null
),

redhat as (
    select
        cve_id,
        severity as redhat_severity,
        cvss3_score as redhat_cvss_score,
        statement as redhat_statement
    from {{ ref('stg_redhat_cves') }}
),

unified as (
    select
        nvd.cve_id,
        nvd.description,
        nvd.cvss_score,
        nvd.cvss_severity,
        nvd.cvss_vector,
        nvd.cwe_id,
        nvd.published_date,
        nvd.last_modified_date,
        
        -- CISA KEV fields
        case when cisa_kev.cve_id is not null then true else false end as is_cisa_kev,
        cisa_kev.kev_date_added,
        cisa_kev.kev_due_date,
        cisa_kev.known_ransomware_use,
        
        -- OSV fields
        osv.osv_id,
        osv.osv_summary,
        
        -- Red Hat fields
        redhat.redhat_severity,
        redhat.redhat_cvss_score,
        redhat.redhat_statement,
        
        -- Source tracking
        case when nvd.cve_id is not null then true else false end as in_nvd,
        case when osv.cve_id is not null then true else false end as in_osv,
        case when redhat.cve_id is not null then true else false end as in_redhat
        
    from nvd
    left join cisa_kev on nvd.cve_id = cisa_kev.cve_id
    left join osv on nvd.cve_id = osv.cve_id
    left join redhat on nvd.cve_id = redhat.cve_id
)

select * from unified