select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
    



select cve_id
from "vuln_db"."staging_staging"."stg_nvd_cves"
where cve_id is null



      
    ) dbt_internal_test