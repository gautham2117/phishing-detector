"""
backend/modules/system_health.py
Phase 15 — System Health & Architecture Monitor
Provides health checks, system metrics, DB stats,
and request rate tracking.
"""

import os
import time
import logging
import datetime
import threading
from collections import deque
from typing import Optional

logger = logging.getLogger(__name__)

# ── Request rate tracker ───────────────────────────────────────────────────────
# Stores timestamps of recent requests in a thread-safe deque
_request_log  = deque(maxlen=10000)
_request_lock = threading.Lock()


def record_request() -> None:
    """Call this on every incoming FastAPI request."""
    with _request_lock:
        _request_log.append(time.monotonic())


def get_requests_per_minute() -> float:
    """Count requests in the last 60 seconds."""
    now    = time.monotonic()
    cutoff = now - 60.0
    with _request_lock:
        count = sum(1 for t in _request_log if t >= cutoff)
    return float(count)


def get_request_rate_history(buckets: int = 10) -> list:
    """
    Return request counts for the last N×6-second buckets.
    Each bucket = 6 seconds → 10 buckets = last 60 seconds.
    """
    now    = time.monotonic()
    bucket_size = 6.0
    result = []
    with _request_lock:
        log_copy = list(_request_log)

    for i in range(buckets - 1, -1, -1):
        bucket_end   = now - i * bucket_size
        bucket_start = bucket_end - bucket_size
        count = sum(1 for t in log_copy
                    if bucket_start <= t < bucket_end)
        label = datetime.datetime.utcnow() - datetime.timedelta(
            seconds=i * bucket_size
        )
        result.append({
            "label": label.strftime("%H:%M:%S"),
            "count": count,
        })
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM METRICS (CPU + Memory)
# ══════════════════════════════════════════════════════════════════════════════

def get_system_metrics() -> dict:
    """Return CPU and memory usage of the current process."""
    metrics = {
        "cpu_percent":    0.0,
        "memory_mb":      0.0,
        "memory_percent": 0.0,
        "total_memory_mb":0.0,
        "available":      True,
    }
    try:
        import psutil # pyright: ignore[reportMissingModuleSource]
        proc = psutil.Process(os.getpid())

        # CPU — measure over a short interval
        metrics["cpu_percent"]    = round(proc.cpu_percent(interval=0.1), 1)

        mem = proc.memory_info()
        metrics["memory_mb"]      = round(mem.rss / 1024 / 1024, 1)

        vm  = psutil.virtual_memory()
        metrics["memory_percent"] = round(
            (mem.rss / vm.total) * 100, 1
        )
        metrics["total_memory_mb"]= round(vm.total / 1024 / 1024, 1)

    except ImportError:
        metrics["available"] = False
        logger.warning("psutil not installed — system metrics unavailable.")
    except Exception as ex:
        metrics["available"] = False
        logger.warning("System metrics error: %s", ex)

    return metrics


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE STATS
# ══════════════════════════════════════════════════════════════════════════════

# Table list — all models defined so far across all phases
ALL_TABLES = [
    "email_scans",
    "url_scans",
    "network_scans",
    "port_results",
    "attachment_scans",
    "ai_detection_scans",
    "image_analysis_scans",
    "monitored_targets",
    "monitor_scan_results",
    "aggregated_risk_scores",
    "feedback_samples",
    "model_versions",
    "alerts",
    "audit_logs",
    "extension_scans",
]


def get_db_stats() -> dict:
    """Return row counts per table and SQLite file size."""
    stats = {
        "tables":     [],
        "total_rows": 0,
        "db_size_mb": 0.0,
        "db_path":    "",
        "available":  True,
    }
    try:
        from backend.app.database import db
        from sqlalchemy import text

        # File size
        try:
            engine  = db.engine
            db_path = str(engine.url).replace("sqlite:///", "")
            if os.path.exists(db_path):
                stats["db_size_mb"] = round(
                    os.path.getsize(db_path) / 1024 / 1024, 3
                )
                stats["db_path"] = db_path
        except Exception:
            pass

        # Row counts
        with engine.connect() as conn:
            for table in ALL_TABLES:
                try:
                    result = conn.execute(
                        text(f"SELECT COUNT(*) FROM {table}")
                    )
                    count = result.scalar() or 0
                    stats["tables"].append({
                        "name":  table,
                        "rows":  count,
                    })
                    stats["total_rows"] += count
                except Exception:
                    stats["tables"].append({
                        "name":  table,
                        "rows":  None,   # table doesn't exist yet
                    })

    except Exception as ex:
        stats["available"] = False
        logger.warning("DB stats error: %s", ex)

    return stats


# ══════════════════════════════════════════════════════════════════════════════
# MODULE HEALTH CHECKS
# ══════════════════════════════════════════════════════════════════════════════

# Each entry: (display_name, fastapi_path, method, payload)
MODULE_HEALTH_CHECKS = [
    ("Email Scanner",      "/api/scan/email",         "POST",
     '{"raw_email": "From: test@test.com\\nSubject: test\\n\\ntest"}'),
    ("URL Intelligence",   "/api/scan/url",            "POST",
     '{"url": "https://httpbin.org"}'),
    ("Rule Engine",        "/api/rules/list",          "GET",  None),
    ("ML Classifier",      "/api/scan/ml/url",         "POST",
     '{"url": "https://httpbin.org"}'),
    ("File Analyzer",      "/api/extension/status",    "GET",  None),
    ("AI Detection",       "/api/monitor/stats",       "GET",  None),
    ("Platform Monitor",   "/api/platform/feed",       "GET",  None),
    ("Risk Aggregator",    "/api/risk/history",        "GET",  None),
    ("Live Monitor",       "/api/monitor/feed",        "GET",  None),
    ("Model Management",   "/api/models/versions",     "GET",  None),
    ("Alerts System",      "/api/alerts/stats",        "GET",  None),
    ("Extension API",      "/api/extension/status",    "GET",  None),
]

# Timeout for each health check (seconds)
HEALTH_CHECK_TIMEOUT = 4


def check_module_health(fastapi_base: str = "http://127.0.0.1:8001") -> list:
    """
    Ping each module endpoint and return health status.
    Runs checks concurrently using threads for speed.
    """
    import requests
    results = [None] * len(MODULE_HEALTH_CHECKS)

    def _check(index: int, name: str, path: str,
                method: str, payload: Optional[str]) -> None:
        url    = fastapi_base + path
        start  = time.monotonic()
        status = "offline"
        latency_ms = 0

        try:
            if method == "GET":
                resp = requests.get(
                    url, timeout=HEALTH_CHECK_TIMEOUT
                )
            else:
                headers = {"Content-Type": "application/json"}
                resp    = requests.post(
                    url,
                    data    = payload or "{}",
                    headers = headers,
                    timeout = HEALTH_CHECK_TIMEOUT,
                )
            latency_ms = round((time.monotonic() - start) * 1000)

            if resp.status_code < 500:
                status = "online"
            else:
                status = "degraded"

        except requests.exceptions.Timeout:
            latency_ms = HEALTH_CHECK_TIMEOUT * 1000
            status     = "degraded"
        except Exception:
            latency_ms = round((time.monotonic() - start) * 1000)
            status     = "offline"

        results[index] = {
            "name":       name,
            "path":       path,
            "status":     status,
            "latency_ms": latency_ms,
        }

    threads = []
    for i, (name, path, method, payload) in enumerate(MODULE_HEALTH_CHECKS):
        t = threading.Thread(
            target=_check,
            args=(i, name, path, method, payload),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=HEALTH_CHECK_TIMEOUT + 1)

    # Replace any None (thread didn't finish) with offline
    for i in range(len(results)):
        if results[i] is None:
            results[i] = {
                "name":       MODULE_HEALTH_CHECKS[i][0],
                "path":       MODULE_HEALTH_CHECKS[i][1],
                "status":     "offline",
                "latency_ms": 0,
            }

    return results


# ══════════════════════════════════════════════════════════════════════════════
# MIGRATION PLAN DATA
# ══════════════════════════════════════════════════════════════════════════════

def get_migration_plan() -> dict:
    """
    Returns a structured SQLite → PostgreSQL migration plan.
    Displayed on the dashboard as an accordion.
    """
    return {
        "title":    "SQLite → PostgreSQL Migration Plan",
        "subtitle": "Schema versioning with Alembic · Zero-downtime strategy",
        "phases": [
            {
                "phase":       1,
                "name":        "Install Dependencies",
                "status":      "ready",
                "description": (
                    "Install the PostgreSQL adapter and Alembic schema "
                    "migration tool. These replace the SQLite driver and "
                    "provide version-controlled schema changes."
                ),
                "commands": [
                    "pip install psycopg2-binary alembic",
                    "alembic init alembic",
                ],
                "notes": (
                    "psycopg2-binary is a self-contained wheel that includes "
                    "the PostgreSQL C library. Use psycopg2 (without -binary) "
                    "in production for better performance."
                ),
            },
            {
                "phase":       2,
                "name":        "Update Database URI",
                "status":      "ready",
                "description": (
                    "Replace the SQLite URI in config.py with the PostgreSQL "
                    "connection string. Use environment variables so credentials "
                    "never appear in source code."
                ),
                "commands": [
                    "# In backend/app/config.py:",
                    "# SQLALCHEMY_DATABASE_URI = os.environ.get(",
                    "#     'DATABASE_URL',",
                    "#     'postgresql://user:pass@localhost:5432/phishguard'",
                    "# )",
                ],
                "notes": (
                    "For local development use: "
                    "postgresql://postgres:postgres@localhost:5432/phishguard. "
                    "For Docker use the service name as host: db:5432."
                ),
            },
            {
                "phase":       3,
                "name":        "Configure Alembic",
                "status":      "ready",
                "description": (
                    "Point alembic/env.py at the SQLAlchemy metadata from "
                    "models.py. This lets Alembic auto-generate migration "
                    "scripts by diffing the ORM models against the live DB schema."
                ),
                "commands": [
                    "# In alembic/env.py add:",
                    "from backend.app.models import db",
                    "target_metadata = db.metadata",
                    "",
                    "# Generate first migration:",
                    "alembic revision --autogenerate -m 'initial_schema'",
                    "alembic upgrade head",
                ],
                "notes": (
                    "Each future model change (add column, new table) "
                    "becomes one Alembic revision. Run alembic upgrade head "
                    "in CI/CD to apply migrations automatically on deploy."
                ),
            },
            {
                "phase":       4,
                "name":        "Migrate Existing Data",
                "status":      "ready",
                "description": (
                    "Export all rows from the SQLite database and import them "
                    "into PostgreSQL. Use pgloader for a one-command migration "
                    "or Python's csv/pandas pipeline for fine-grained control."
                ),
                "commands": [
                    "# Option A — pgloader (recommended, one command):",
                    "pgloader sqlite:///database/phishguard.db postgresql://user:pass@localhost/phishguard",
                    "",
                    "# Option B — Python pandas pipeline:",
                    "python migrate_data.py  # reads SQLite, writes to PostgreSQL",
                ],
                "notes": (
                    "pgloader handles type mapping automatically. "
                    "Run during a maintenance window or on a clone of the "
                    "SQLite DB to avoid data loss."
                ),
            },
            {
                "phase":       5,
                "name":        "Schema Versioning Workflow",
                "status":      "ready",
                "description": (
                    "Every model change from this point follows the "
                    "Alembic workflow: modify the ORM model, generate a "
                    "revision, review the generated script, then apply it."
                ),
                "commands": [
                    "# 1. Edit backend/app/models.py",
                    "# 2. Generate revision:",
                    "alembic revision --autogenerate -m 'add_column_x_to_table_y'",
                    "# 3. Review alembic/versions/xxxx_add_column.py",
                    "# 4. Apply to dev DB:",
                    "alembic upgrade head",
                    "# 5. Roll back if needed:",
                    "alembic downgrade -1",
                ],
                "notes": (
                    "Commit the Alembic revision files to Git alongside "
                    "the model change. Never edit existing revisions — "
                    "always create a new one."
                ),
            },
            {
                "phase":       6,
                "name":        "PostgreSQL Production Checklist",
                "status":      "ready",
                "description": (
                    "Before going live, apply these PostgreSQL-specific "
                    "optimisations that SQLite cannot provide."
                ),
                "commands": [
                    "-- Add indexes for frequently queried columns:",
                    "CREATE INDEX idx_url_scans_domain ON url_scans(domain);",
                    "CREATE INDEX idx_alerts_severity ON alerts(severity);",
                    "CREATE INDEX idx_alerts_created_at ON alerts(created_at);",
                    "CREATE INDEX idx_audit_logs_action ON audit_logs(action);",
                    "",
                    "-- Enable connection pooling (in config.py):",
                    "SQLALCHEMY_ENGINE_OPTIONS = {",
                    "    'pool_size': 10,",
                    "    'max_overflow': 20,",
                    "    'pool_pre_ping': True,",
                    "}",
                ],
                "notes": (
                    "Use PgBouncer for connection pooling in production. "
                    "Set pool_pre_ping=True to automatically recover from "
                    "dropped connections."
                ),
            },
        ],
    }