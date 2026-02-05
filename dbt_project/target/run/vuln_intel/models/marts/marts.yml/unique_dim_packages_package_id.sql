select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
    

select
    package_id as unique_field,
    count(*) as n_records

from "vuln_db"."staging_marts"."dim_packages"
where package_id is not null
group by package_id
having count(*) > 1



      
    ) dbt_internal_test