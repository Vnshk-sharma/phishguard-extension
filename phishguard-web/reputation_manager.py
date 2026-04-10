"""SQLite-backed domain reputation manager for phishing detection."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlparse

DB_PATH = Path(__file__).resolve().parent / "reputation.db"
_TABLE_NAME = "domain_reputation"
_DB_LOCK = Lock()


def _get_connection() -> sqlite3.Connection:
    """Create a SQLite connection for this module's reputation database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the domain reputation table if it does not already exist."""
    with _DB_LOCK, _get_connection() as conn:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_TABLE_NAME} (
                domain TEXT PRIMARY KEY,
                total_checks INTEGER NOT NULL DEFAULT 0,
                flagged_count INTEGER NOT NULL DEFAULT 0,
                risk_score FLOAT NOT NULL DEFAULT 0.0
            )
            """
        )
        conn.commit()


def extract_domain(url: str) -> str:
    """Safely parse a URL-like value and return a normalized domain name.

    Raises:
        ValueError: If no domain could be extracted.
    """
    if not isinstance(url, str):
        raise TypeError("url must be a string")

    candidate = url.strip()
    if not candidate:
        raise ValueError("url cannot be empty")

    # Handle inputs without a scheme (e.g., example.com/login).
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    domain = (parsed.hostname or "").strip().lower().rstrip(".")

    if not domain:
        raise ValueError(f"Could not extract domain from URL: {url!r}")

    return domain


def update_domain_reputation(domain: str, is_phishing: bool) -> dict[str, Any]:
    """Update reputation counters for a domain and return the latest stats."""
    normalized_domain = _normalize_domain(domain)
    init_db()

    with _DB_LOCK, _get_connection() as conn:
        row = conn.execute(
            f"SELECT total_checks, flagged_count FROM {_TABLE_NAME} WHERE domain = ?",
            (normalized_domain,),
        ).fetchone()

        total_checks = 0
        flagged_count = 0
        if row is not None:
            total_checks = int(row["total_checks"])
            flagged_count = int(row["flagged_count"])

        total_checks += 1
        if is_phishing:
            flagged_count += 1

        risk_score = (flagged_count / total_checks) * 100 if total_checks else 0.0

        conn.execute(
            f"""
            INSERT INTO {_TABLE_NAME} (domain, total_checks, flagged_count, risk_score)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                total_checks = excluded.total_checks,
                flagged_count = excluded.flagged_count,
                risk_score = excluded.risk_score
            """,
            (normalized_domain, total_checks, flagged_count, risk_score),
        )
        conn.commit()

    return {
        "domain": normalized_domain,
        "total_checks": total_checks,
        "flagged_count": flagged_count,
        "risk_score": risk_score,
    }


def get_domain_reputation(domain: str) -> dict[str, Any] | None:
    """Return current reputation stats for a domain, or None if missing."""
    normalized_domain = _normalize_domain(domain)
    init_db()

    with _DB_LOCK, _get_connection() as conn:
        row = conn.execute(
            f"""
            SELECT domain, total_checks, flagged_count, risk_score
            FROM {_TABLE_NAME}
            WHERE domain = ?
            """,
            (normalized_domain,),
        ).fetchone()

    if row is None:
        return None

    return {
        "domain": row["domain"],
        "total_checks": int(row["total_checks"]),
        "flagged_count": int(row["flagged_count"]),
        "risk_score": float(row["risk_score"]),
    }


def _normalize_domain(domain: str) -> str:
    """Normalize domain input and validate it is non-empty."""
    if not isinstance(domain, str):
        raise TypeError("domain must be a string")

    normalized = domain.strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("domain cannot be empty")

    return normalized


__all__ = [
    "init_db",
    "extract_domain",
    "update_domain_reputation",
    "get_domain_reputation",
]
