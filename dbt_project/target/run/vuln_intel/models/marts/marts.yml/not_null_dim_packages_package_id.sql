select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
    



select package_id
from "vuln_db"."staging_marts"."dim_packages"
where package_id is null



      
    ) dbt_internal_test