with source as (
    select * from {{ source('raw', 'osv_vulnerabilities') }}
),

staged as (
    select
        osv_id,
        cve_id,
        summary,
        details,
        published_date,
        modified_date,
        severity,
        ingested_at
    from source
)

select * from staged