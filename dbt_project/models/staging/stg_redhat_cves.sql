with source as (
    select * from {{ source('raw', 'redhat_cves') }}
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