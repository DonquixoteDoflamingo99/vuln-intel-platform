select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
    



select osv_id
from "vuln_db"."staging_staging"."stg_osv_vulnerabilities"
where osv_id is null



      
    ) dbt_internal_test