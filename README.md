# Vulnerability Intelligence Platform

A data engineering project that aggregates vulnerability data from multiple security sources into a unified data warehouse for analysis and reporting.

## Project Overview

This platform collects CVE (Common Vulnerabilities and Exposures) data from multiple authoritative sources, transforms it through a layered data architecture, and produces analytics-ready tables for security analysis.

### Business Questions This Platform Answers

- Which vulnerabilities are actively being exploited (CISA KEV)?
- What packages in our ecosystem have critical vulnerabilities?
- Which Red Hat products have patches available?
- What's the severity distribution of recent vulnerabilities?
- Which CVEs are flagged for ransomware campaigns?

## Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                        DATA SOURCES                             │
├─────────────────┬─────────────────┬──────────────┬──────────────┤
│    CISA KEV     │      NVD        │     OSV      │   Red Hat    │
│  (Exploited)    │  (CVE Authority)│  (Packages)  │  (RHEL Fixes)│
└────────┬────────┴────────┬────────┴───────┬──────┴───────┬──────┘
         │                 │                │              │
         ▼                 ▼                ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     INGESTION LAYER (Python)                    │
│         Raw JSON → Parsed → PostgreSQL (raw schema)             │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                   TRANSFORMATION LAYER (dbt)                    │
├─────────────────────────────────────────────────────────────────┤
│  staging          │ Clean, type, rename columns                 │
│  intermediate     │ Join sources, deduplicate, business logic   │
│  marts            │ Analytics-ready dimensions and facts        │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ANALYTICS LAYER                            │
│              dim_vulnerabilities, dim_packages                  │
│         fct_package_vulnerabilities, fct_redhat_fixes           │
│              rpt_critical_vulnerabilities                       │
└─────────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| Database | PostgreSQL 15 |
| Containerization | Docker |
| Ingestion | Python (requests, psycopg2) |
| Transformation | dbt-core 1.7 |
| Testing | dbt tests |

## Data Sources

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited vulnerabilities | ~Weekly |
| [NVD](https://nvd.nist.gov/) | Official CVE database with severity scores | Daily |
| [OSV](https://osv.dev/) | Open source package vulnerability mappings | Daily |
| [Red Hat Security](https://access.redhat.com/security/security-updates/) | RHEL-specific advisories and patches | Daily |

## Project Structure
```
vuln-intel-platform/
├── docker-compose.yml          # PostgreSQL container
├── docker/
│   └── init.sql                # Database schema setup
├── ingestion/
│   ├── db_utils.py             # Database utilities
│   ├── create_raw_tables.py    # Table creation script
│   ├── cisa_kev/
│   │   └── ingest.py           # CISA KEV ingestion
│   ├── nvd/
│   │   └── ingest.py           # NVD ingestion
│   ├── osv/
│   │   └── ingest.py           # OSV ingestion
│   └── redhat/
│       └── ingest.py           # Red Hat ingestion
├── dbt_project/
│   ├── dbt_project.yml         # dbt configuration
│   ├── packages.yml            # dbt packages
│   ├── profiles.yml            # Database connection
│   └── models/
│       ├── staging/            # 6 staging models
│       ├── intermediate/       # 3 intermediate models
│       └── marts/              # 5 mart models
└── README.md
```

## Data Models

### Staging Layer (6 models)
- `stg_cisa_kev` - Cleaned CISA KEV data
- `stg_nvd_cves` - Cleaned NVD CVE data (Analyzed/Modified only)
- `stg_osv_vulnerabilities` - Cleaned OSV vulnerability data
- `stg_osv_affected_packages` - Cleaned OSV package mappings
- `stg_redhat_cves` - Cleaned Red Hat CVE data
- `stg_redhat_affected_releases` - Cleaned Red Hat release data

### Intermediate Layer (3 models)
- `int_unified_vulnerabilities` - Joined CVE data from all sources
- `int_package_vulnerabilities` - Package-to-vulnerability mappings with severity
- `int_redhat_fixes` - Red Hat fixes with vulnerability context

### Mart Layer (5 models)
- `dim_vulnerabilities` - Vulnerability dimension table
- `dim_packages` - Package dimension table
- `fct_package_vulnerabilities` - Package vulnerability facts
- `fct_redhat_fixes` - Red Hat fix facts
- `rpt_critical_vulnerabilities` - Critical/high severity report

## Setup Instructions

### Prerequisites
- Docker Desktop
- Python 3.10+
- Git

### 1. Clone Repository
```bash
git clone https://github.com/YOUR_USERNAME/vuln-intel-platform.git
cd vuln-intel-platform
```

### 2. Create Environment File
```bash
# Create .env file with database credentials
cat > .env << EOF
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vuln_db
DB_USER=vuln_user
DB_PASSWORD=vuln_password
EOF
```

### 3. Start Database
```bash
docker-compose up -d
```

### 4. Setup Python Environment
```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate

pip install -r requirements.txt
```

### 5. Create Raw Tables
```bash
cd ingestion
python create_raw_tables.py
```

### 6. Run Ingestion
```bash
# Run each ingestion script
cd cisa_kev && python ingest.py && cd ..
cd nvd && python ingest.py && cd ..
cd osv && python ingest.py && cd ..
cd redhat && python ingest.py && cd ..
```

### 7. Run dbt
```bash
# Windows
.\run_dbt.bat deps
.\run_dbt.bat run
.\run_dbt.bat test

# Linux/Mac
cd dbt_project
dbt deps
dbt run
dbt test
```

### 8. View Documentation
```bash
.\run_dbt.bat docs generate
.\run_dbt.bat docs serve
```

## Sample Queries

### Critical Vulnerabilities with Active Exploits
```sql
SELECT 
    cve_id,
    cvss_score,
    cvss_severity,
    known_ransomware_use,
    kev_due_date
FROM marts.rpt_critical_vulnerabilities
WHERE is_cisa_kev = true
ORDER BY cvss_score DESC
LIMIT 20;
```

### Most Vulnerable Packages by Ecosystem
```sql
SELECT 
    ecosystem,
    package_name,
    COUNT(DISTINCT cve_id) as vuln_count,
    MAX(cvss_score) as max_severity
FROM marts.fct_package_vulnerabilities
GROUP BY ecosystem, package_name
ORDER BY vuln_count DESC
LIMIT 20;
```

### Red Hat Products Needing Patches
```sql
SELECT 
    product_name,
    COUNT(*) as pending_fixes,
    SUM(CASE WHEN is_cisa_kev THEN 1 ELSE 0 END) as critical_exploited
FROM marts.fct_redhat_fixes
WHERE fix_state = 'Affected'
GROUP BY product_name
ORDER BY critical_exploited DESC, pending_fixes DESC;
```

## Test Coverage

- 19 dbt tests passing
- Unique and not-null tests on primary keys
- Accepted values tests on severity fields

## Future Enhancements

- [ ] Orchestration with Airflow or Dagster
- [ ] Simulated company inventory (seed data)
- [ ] Dashboard with Metabase or Evidence
- [ ] Incremental loading for large tables
- [ ] CI/CD pipeline with GitHub Actions

## Learning Resources

For orchestration (next phase):

**Airflow:**
- [Official Airflow Tutorial](https://airflow.apache.org/docs/apache-airflow/stable/tutorial/index.html)
- [Airflow with dbt](https://docs.getdbt.com/docs/deploy/deployment-tools#airflow)

**Dagster:**
- [Official Dagster Tutorial](https://docs.dagster.io/getting-started)
- [Dagster with dbt](https://docs.dagster.io/integrations/dbt)

## Orchestration

The pipeline is orchestrated using Dagster.

### Run Dagster UI
```bash
cd orchestration
dagster dev
```

Open `http://localhost:3000` to view the pipeline.

### Pipeline Flow

1. **Ingestion** (parallel): CISA KEV, NVD, OSV
2. **Ingestion** (sequential): Red Hat (depends on CISA KEV + NVD)
3. **Transform**: dbt staging → intermediate → marts
4. **Test**: dbt tests

### Schedule

Pipeline runs daily at 6:00 AM (when schedule is enabled).

## License

MIT