"""
Dagster definitions - main entry point.
"""
from dagster import Definitions, load_assets_from_modules, define_asset_job, ScheduleDefinition

from vuln_intel import assets

all_assets = load_assets_from_modules([assets])

# Define a job that runs all assets
full_pipeline_job = define_asset_job(
    name="full_pipeline_job",
    selection="*"  # All assets
)

# Schedule to run daily at 6 AM
daily_schedule = ScheduleDefinition(
    job=full_pipeline_job,
    cron_schedule="0 6 * * *",  # 6:00 AM every day
    name="daily_vulnerability_refresh"
)

defs = Definitions(
    assets=all_assets,
    jobs=[full_pipeline_job],
    schedules=[daily_schedule],
)