with source as (
    select * from {{ source('raw', 'cisa_kev') }}
),

staged as (
    select
        cve_id,
        vendor_project,
        product,
        vulnerability_name,
        date_added,
        short_description,
        required_action,
        due_date,
        known_ransomware_use,
        ingested_at
    from source
)

select * from staged