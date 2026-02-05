
    
    

select
    cve_id as unique_field,
    count(*) as n_records

from "vuln_db"."staging_staging"."stg_cisa_kev"
where cve_id is not null
group by cve_id
having count(*) > 1


