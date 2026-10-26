"""PostgreSQL access without a background connection-pool thread.

This deliberately opens one short-lived connection per operation. It is a
simple, predictable option for small Render deployments and avoids pool worker
threads being left alive if Gunicorn startup fails.
"""
import os
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL is missing. In Render, add the PostgreSQL database's "
        "Internal Database URL to the web service Environment."
    )

# Preserve existing query parameters and require TLS when the URL does not
# already specify an SSL mode.
if "sslmode=" not in DATABASE_URL:
    DATABASE_URL += ("&" if "?" in DATABASE_URL else "?") + "sslmode=require"

@contextmanager
def get_conn():
    """Yield a dict-row PostgreSQL connection; commit on success, rollback on error."""
    with psycopg.connect(
        conninfo=DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=10,
        application_name="secure-pos",
    ) as conn:
        yield conn

def init_db():
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = f.read()
    with get_conn() as conn:
        conn.execute(schema)
