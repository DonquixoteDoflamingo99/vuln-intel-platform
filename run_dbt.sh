#This script reads database connection details from a .env file
#and sets them as environment variables before running dbt commands.

#!/bin/bash
set -a
source .env
set +a
cd dbt_project
dbt "$@"