
  create view "vuln_db"."staging_staging"."stg_cisa_kev__dbt_tmp"
    
    
  as (
    with source as (
    select * from "vuln_db"."raw"."cisa_kev"
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
  );