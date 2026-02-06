"""
Dagster assets for vulnerability data pipeline.
"""
import subprocess
import sys
import os
from pathlib import Path
from dagster import asset, AssetExecutionContext
from dotenv import load_dotenv

# Get project root directory
PROJECT_ROOT = Path(__file__).parent.parent.parent
INGESTION_DIR = PROJECT_ROOT / "ingestion"
DBT_PROJECT_DIR = PROJECT_ROOT / "dbt_project"

# Load environment variables
ENV_FILE = PROJECT_ROOT / ".env"
load_dotenv(ENV_FILE)


@asset(group_name="ingestion")
def cisa_kev_raw(context: AssetExecutionContext):
    """Ingest CISA KEV data into raw table."""
    context.log.info("Starting CISA KEV ingestion...")
    
    result = subprocess.run(
        [sys.executable, "cisa_kev/ingest.py"],
        cwd=INGESTION_DIR,
        capture_output=True,
        text=True
    )
    
    context.log.info(f"stdout: {result.stdout}")
    
    if result.returncode != 0:
        context.log.error(f"stderr: {result.stderr}")
        raise Exception(f"CISA KEV ingestion failed: {result.stderr}")
    
    return "CISA KEV ingestion complete"


@asset(group_name="ingestion")
def nvd_raw(context: AssetExecutionContext):
    """Ingest NVD data into raw table."""
    context.log.info("Starting NVD ingestion...")
    
    result = subprocess.run(
        [sys.executable, "nvd/ingest.py"],
        cwd=INGESTION_DIR,
        capture_output=True,
        text=True
    )
    
    context.log.info(f"stdout: {result.stdout}")
    
    if result.returncode != 0:
        context.log.error(f"stderr: {result.stderr}")
        raise Exception(f"NVD ingestion failed: {result.stderr}")
    
    return "NVD ingestion complete"


@asset(group_name="ingestion")
def osv_raw(context: AssetExecutionContext):
    """Ingest OSV data into raw table."""
    context.log.info("Starting OSV ingestion...")
    
    result = subprocess.run(
        [sys.executable, "osv/ingest.py"],
        cwd=INGESTION_DIR,
        capture_output=True,
        text=True
    )
    
    context.log.info(f"stdout: {result.stdout}")
    
    if result.returncode != 0:
        context.log.error(f"stderr: {result.stderr}")
        raise Exception(f"OSV ingestion failed: {result.stderr}")
    
    return "OSV ingestion complete"


@asset(group_name="ingestion", deps=[cisa_kev_raw, nvd_raw])
def redhat_raw(context: AssetExecutionContext):
    """Ingest Red Hat data into raw table. Depends on CISA KEV and NVD."""
    context.log.info("Starting Red Hat ingestion...")
    
    result = subprocess.run(
        [sys.executable, "redhat/ingest.py"],
        cwd=INGESTION_DIR,
        capture_output=True,
        text=True
    )
    
    context.log.info(f"stdout: {result.stdout}")
    
    if result.returncode != 0:
        context.log.error(f"stderr: {result.stderr}")
        raise Exception(f"Red Hat ingestion failed: {result.stderr}")
    
    return "Red Hat ingestion complete"


@asset(
    group_name="transform",
    deps=[cisa_kev_raw, nvd_raw, osv_raw, redhat_raw]
)
def dbt_staging(context: AssetExecutionContext):
    """Run dbt staging models."""
    context.log.info("Running dbt staging models...")
    
    env = os.environ.copy()
    
    result = subprocess.run(
        ["dbt", "run", "--select", "staging", "--profiles-dir", "."],
        cwd=DBT_PROJECT_DIR,
        capture_output=True,
        text=True,
        env=env
    )
    
    context.log.info(f"stdout: {result.stdout}")
    context.log.info(f"stderr: {result.stderr}")
    
    if result.returncode != 0:
        raise Exception(f"dbt staging failed: {result.stdout}\n{result.stderr}")
    
    return "dbt staging complete"


@asset(group_name="transform", deps=[dbt_staging])
def dbt_intermediate(context: AssetExecutionContext):
    """Run dbt intermediate models."""
    context.log.info("Running dbt intermediate models...")
    
    env = os.environ.copy()
    
    result = subprocess.run(
        ["dbt", "run", "--select", "intermediate", "--profiles-dir", "."],
        cwd=DBT_PROJECT_DIR,
        capture_output=True,
        text=True,
        env=env
    )
    
    context.log.info(f"stdout: {result.stdout}")
    context.log.info(f"stderr: {result.stderr}")
    
    if result.returncode != 0:
        raise Exception(f"dbt intermediate failed: {result.stdout}\n{result.stderr}")
    
    return "dbt intermediate complete"


@asset(group_name="transform", deps=[dbt_intermediate])
def dbt_marts(context: AssetExecutionContext):
    """Run dbt mart models."""
    context.log.info("Running dbt mart models...")
    
    env = os.environ.copy()
    
    result = subprocess.run(
        ["dbt", "run", "--select", "marts", "--profiles-dir", "."],
        cwd=DBT_PROJECT_DIR,
        capture_output=True,
        text=True,
        env=env
    )
    
    context.log.info(f"stdout: {result.stdout}")
    context.log.info(f"stderr: {result.stderr}")
    
    if result.returncode != 0:
        raise Exception(f"dbt marts failed: {result.stdout}\n{result.stderr}")
    
    return "dbt marts complete"


@asset(group_name="test", deps=[dbt_marts])
def dbt_tests(context: AssetExecutionContext):
    """Run dbt tests."""
    context.log.info("Running dbt tests...")
    
    env = os.environ.copy()
    
    result = subprocess.run(
        ["dbt", "test", "--profiles-dir", "."],
        cwd=DBT_PROJECT_DIR,
        capture_output=True,
        text=True,
        env=env
    )
    
    context.log.info(f"stdout: {result.stdout}")
    context.log.info(f"stderr: {result.stderr}")
    
    if result.returncode != 0:
        raise Exception(f"dbt tests failed: {result.stdout}\n{result.stderr}")
    
    return "dbt tests complete"