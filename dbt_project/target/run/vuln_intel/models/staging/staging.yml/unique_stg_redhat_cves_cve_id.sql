select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
    

select
    cve_id as unique_field,
    count(*) as n_records

from "vuln_db"."staging_staging"."stg_redhat_cves"
where cve_id is not null
group by cve_id
having count(*) > 1



      
    ) dbt_internal_test