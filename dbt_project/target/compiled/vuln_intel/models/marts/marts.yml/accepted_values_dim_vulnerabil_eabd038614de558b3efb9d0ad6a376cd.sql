
    
    

with all_values as (

    select
        cvss_severity as value_field,
        count(*) as n_records

    from "vuln_db"."staging_marts"."dim_vulnerabilities"
    group by cvss_severity

)

select *
from all_values
where value_field not in (
    'critical','high','medium','low','None'
)


