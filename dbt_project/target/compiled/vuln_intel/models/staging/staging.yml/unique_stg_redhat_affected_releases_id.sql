
    
    

select
    id as unique_field,
    count(*) as n_records

from "vuln_db"."staging_staging"."stg_redhat_affected_releases"
where id is not null
group by id
having count(*) > 1


