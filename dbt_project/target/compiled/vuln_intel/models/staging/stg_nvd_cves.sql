with source as (
    select * from "vuln_db"."raw"."nvd_cves"
),

staged as (
    select
        cve_id,
        source_identifier,
        vuln_status,
        published_date,
        last_modified_date,
        description,
        cvss_v31_score,
        lower(cvss_v31_severity) as cvss_severity,
        cvss_v31_vector,
        cwe_id,
        ingested_at
    from source
    where vuln_status in ('Analyzed', 'Modified')
)

select * from staged