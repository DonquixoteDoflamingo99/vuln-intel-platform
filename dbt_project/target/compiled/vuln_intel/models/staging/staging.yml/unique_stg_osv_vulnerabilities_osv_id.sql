
    
    

select
    osv_id as unique_field,
    count(*) as n_records

from "vuln_db"."staging_staging"."stg_osv_vulnerabilities"
where osv_id is not null
group by osv_id
having count(*) > 1


