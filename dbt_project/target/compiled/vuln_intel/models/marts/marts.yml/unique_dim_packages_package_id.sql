
    
    

select
    package_id as unique_field,
    count(*) as n_records

from "vuln_db"."staging_marts"."dim_packages"
where package_id is not null
group by package_id
having count(*) > 1


