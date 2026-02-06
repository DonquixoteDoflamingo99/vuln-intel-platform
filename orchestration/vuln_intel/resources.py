"""
Dagster resources for database connections and configurations.
"""
import os
from dagster import resource

@resource
def db_config(context):
    """Database configuration resource."""
    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
        "dbname": os.getenv("DB_NAME", "vuln_db"),
        "user": os.getenv("DB_USER", "vuln_user"),
        "password": os.getenv("DB_PASSWORD", "vuln_password"),
    }