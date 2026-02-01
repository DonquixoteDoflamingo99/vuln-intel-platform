# Vulnerability Intelligence Platform

A platform for ingesting, transforming, and analyzing vulnerability data from multiple sources.

## Project Structure

- **ingestion/** - Data ingestion modules for various vulnerability sources
  - `nvd/` - National Vulnerability Database
  - `osv/` - Open Source Vulnerabilities
  - `redhat/` - Red Hat Security Advisories
  - `github_advisory/` - GitHub Security Advisories
- **dbt_project/** - dbt models for data transformation
  - `models/staging/` - Raw data staging models
  - `models/intermediate/` - Intermediate transformation models
  - `models/marts/` - Final analytics-ready models
  - `seeds/` - Fake company inventory data
  - `tests/` - dbt tests
- **orchestration/** - Workflow orchestration
- **docs/** - Documentation

## Getting Started

1. Configure your environment
2. Run `docker-compose up` to start services
3. Execute dbt models to transform data
