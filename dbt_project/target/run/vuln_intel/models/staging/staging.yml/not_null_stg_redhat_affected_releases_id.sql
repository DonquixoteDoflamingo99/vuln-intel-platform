select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
    



select id
from "vuln_db"."staging_staging"."stg_redhat_affected_releases"
where id is null



      
    ) dbt_internal_test