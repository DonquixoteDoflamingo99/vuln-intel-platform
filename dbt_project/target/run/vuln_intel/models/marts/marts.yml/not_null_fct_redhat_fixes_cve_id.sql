select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
    



select cve_id
from "vuln_db"."staging_marts"."fct_redhat_fixes"
where cve_id is null



      
    ) dbt_internal_test