"""SQLite-backed analytics manager for tracking URL scan logs."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any
from datetime import datetime

import pandas as pd

DB_PATH = Path(__file__).resolve().parent / "analytics.db"
_SCAN_LOGS_TABLE = "scan_logs"
_DB_LOCK = Lock()


def _get_connection() -> sqlite3.Connection:
    """Create a SQLite connection for this module's analytics database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the scan_logs table if it does not already exist."""
    with _DB_LOCK, _get_connection() as conn:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_SCAN_LOGS_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                is_phishing BOOLEAN NOT NULL DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def log_scan(url: str, domain: str, is_phishing: bool) -> dict[str, Any]:
    """Insert a new scan record into the scan_logs table.

    Args:
        url: The full URL that was checked.
        domain: The extracted domain name from the URL.
        is_phishing: True if the URL was flagged as phishing, False otherwise.

    Returns:
        A dictionary containing the inserted record details.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("url must be a non-empty string")
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("domain must be a non-empty string")
    if not isinstance(is_phishing, bool):
        raise TypeError("is_phishing must be a boolean")

    init_db()

    with _DB_LOCK, _get_connection() as conn:
        cursor = conn.execute(
            f"""
            INSERT INTO {_SCAN_LOGS_TABLE} (url, domain, is_phishing)
            VALUES (?, ?, ?)
            """,
            (url.strip(), domain.strip().lower(), int(is_phishing)),
        )
        conn.commit()
        scan_id = cursor.lastrowid

    return {
        "id": scan_id,
        "url": url.strip(),
        "domain": domain.strip().lower(),
        "is_phishing": is_phishing,
        "timestamp": datetime.now().isoformat(),
    }


def get_recent_scans(limit: int = 100) -> list[dict[str, Any]]:
    """Retrieve recent scan logs ordered by timestamp (most recent first).

    Args:
        limit: Maximum number of records to return (default: 100).

    Returns:
        A list of dictionaries containing scan log records.
    """
    init_db()

    with _DB_LOCK, _get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT id, url, domain, is_phishing, timestamp
            FROM {_SCAN_LOGS_TABLE}
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "id": row["id"],
            "url": row["url"],
            "domain": row["domain"],
            "is_phishing": bool(row["is_phishing"]),
            "timestamp": row["timestamp"],
        }
        for row in rows
    ]


def get_scan_stats() -> dict[str, Any]:
    """Get aggregate statistics from scan logs.

    Returns:
        A dictionary containing total scans, phishing count, safe count,
        and the phishing detection rate.
    """
    init_db()

    with _DB_LOCK, _get_connection() as conn:
        row = conn.execute(
            f"""
            SELECT
                COUNT(*) as total_scans,
                SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing_count,
                SUM(CASE WHEN is_phishing = 0 THEN 1 ELSE 0 END) as safe_count
            FROM {_SCAN_LOGS_TABLE}
            """
        ).fetchone()

    total = row["total_scans"] or 0
    phishing = row["phishing_count"] or 0
    safe = row["safe_count"] or 0

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "safe_count": safe,
        "phishing_rate": (phishing / total * 100) if total > 0 else 0.0,
    }


def get_total_scans() -> int:
    """Return the total count of rows in scan_logs.

    Returns:
        Total number of scan records.
    """
    init_db()

    with _DB_LOCK, _get_connection() as conn:
        row = conn.execute(
            f"SELECT COUNT(*) as total FROM {_SCAN_LOGS_TABLE}"
        ).fetchone()

    return row["total"] or 0


def get_scan_ratio() -> dict[str, int]:
    """Return a dictionary with the count of 'safe' and 'phishing' scans.

    Returns:
        Dictionary with 'safe' and 'phishing' keys containing counts.
    """
    init_db()

    with _DB_LOCK, _get_connection() as conn:
        row = conn.execute(
            f"""
            SELECT
                SUM(CASE WHEN is_phishing = 0 THEN 1 ELSE 0 END) as safe,
                SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing
            FROM {_SCAN_LOGS_TABLE}
            """
        ).fetchone()

    return {
        "safe": row["safe"] or 0,
        "phishing": row["phishing"] or 0,
    }


def get_scans_over_time() -> pd.DataFrame:
    """Query scan_logs and group by date, returning counts per day.

    Returns:
        Pandas DataFrame with columns: date, safe_count, phishing_count.
    """
    init_db()

    with _DB_LOCK, _get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT
                DATE(timestamp) as date,
                SUM(CASE WHEN is_phishing = 0 THEN 1 ELSE 0 END) as safe_count,
                SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing_count
            FROM {_SCAN_LOGS_TABLE}
            GROUP BY DATE(timestamp)
            ORDER BY DATE(timestamp)
            """
        ).fetchall()

    data = [
        {
            "date": row["date"],
            "safe_count": row["safe_count"] or 0,
            "phishing_count": row["phishing_count"] or 0,
        }
        for row in rows
    ]

    df = pd.DataFrame(data, columns=["date", "safe_count", "phishing_count"])
    
    # Convert date column to datetime
    if not df.empty:
        df["date"] = pd.to_datetime(df["date"])
    else:
        # Return empty DataFrame with correct columns and dtypes
        df = pd.DataFrame({"date": pd.Series(dtype="datetime64[ns]"),
                          "safe_count": pd.Series(dtype="int64"),
                          "phishing_count": pd.Series(dtype="int64")})

    return df


def get_top_risky_domains(limit: int = 5) -> list[dict[str, Any]]:
    """Query for domains with the highest count of phishing scans.

    Args:
        limit: Maximum number of domains to return (default: 5).

    Returns:
        List of dictionaries containing domain and phishing count.
    """
    init_db()

    with _DB_LOCK, _get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT
                domain,
                COUNT(*) as phishing_count
            FROM {_SCAN_LOGS_TABLE}
            WHERE is_phishing = 1
            GROUP BY domain
            ORDER BY phishing_count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "domain": row["domain"],
            "phishing_count": row["phishing_count"],
        }
        for row in rows
    ]


__all__ = [
    "init_db",
    "log_scan",
    "get_recent_scans",
    "get_scan_stats",
    "get_total_scans",
    "get_scan_ratio",
    "get_scans_over_time",
    "get_top_risky_domains",
]
