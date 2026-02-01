"""
Database utility functions for connecting and loading data.
"""
import os
from pathlib import Path
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Load .env from project root
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)


def get_connection():
    """Create and return a database connection."""
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )


def execute_query(query, params=None):
    """Execute a single query."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            conn.commit()
    finally:
        conn.close()


def fetch_all(query, params=None):
    """Fetch all results from a query."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()
    finally:
        conn.close()


def bulk_insert(table, columns, data):
    """
    Bulk insert data into a table.
    
    Args:
        table: Full table name including schema (e.g., 'raw.nvd_cves')
        columns: List of column names
        data: List of tuples containing values
    """
    if not data:
        print(f"No data to insert into {table}")
        return
    
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cols = ", ".join(columns)
            query = f"INSERT INTO {table} ({cols}) VALUES %s"
            execute_values(cur, query, data)
            conn.commit()
            print(f"Inserted {len(data)} rows into {table}")
    finally:
        conn.close()