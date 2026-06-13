"""SQLite storage for local lists and SignalShield analytics."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from core.domain_utils import extract_hostname, extract_registered_domain, normalize_url


DB_ENV_VAR = "SIGNALSHIELD_DB_PATH"
LIST_BLACKLIST = "blacklist"
LIST_TRUSTED = "trusted"
SCOPE_DOMAIN = "domain"
SCOPE_URL = "url"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "signalshield.sqlite3"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_iso(value: datetime | None = None) -> str:
    return (value or utc_now()).replace(microsecond=0).isoformat()


def expiry_from_choice(choice: str) -> str | None:
    durations = {
        "24 hours": timedelta(hours=24),
        "7 days": timedelta(days=7),
        "30 days": timedelta(days=30),
    }
    duration = durations.get(choice)
    return utc_iso(utc_now() + duration) if duration else None


def get_db_path() -> Path:
    custom_path = os.environ.get(DB_ENV_VAR, "").strip()
    return Path(custom_path) if custom_path else DEFAULT_DB_PATH


def connect() -> sqlite3.Connection:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    initialize(connection)
    return connection


def initialize(connection: sqlite3.Connection | None = None) -> None:
    owns_connection = connection is None
    connection = connection or sqlite3.connect(get_db_path())

    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS list_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                list_type TEXT NOT NULL,
                scope TEXT NOT NULL,
                value TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                original_value TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                UNIQUE(list_type, scope, value)
            );

            CREATE INDEX IF NOT EXISTS idx_list_entries_lookup
            ON list_entries(list_type, scope, value, active, expires_at);

            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                page_url TEXT NOT NULL DEFAULT '',
                page_hostname TEXT NOT NULL DEFAULT '',
                page_domain TEXT NOT NULL DEFAULT '',
                target_url TEXT NOT NULL,
                target_hostname TEXT NOT NULL DEFAULT '',
                target_domain TEXT NOT NULL DEFAULT '',
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT 'unknown',
                reasons_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_scan_events_page_domain
            ON scan_events(page_domain, created_at);

            CREATE INDEX IF NOT EXISTS idx_scan_events_verdict
            ON scan_events(verdict, created_at);
            """
        )
        connection.commit()
    finally:
        if owns_connection:
            connection.close()


def normalize_scope_value(value: str, scope: str) -> str:
    raw_value = value.strip()

    if scope == SCOPE_URL:
        return normalize_url(raw_value)

    hostname = extract_hostname(raw_value)
    return (hostname or raw_value).lower().strip()


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def add_list_entry(
    list_type: str,
    scope: str,
    value: str,
    label: str = "",
    note: str = "",
    expires_at: str | None = None,
) -> dict[str, Any]:
    if list_type not in {LIST_BLACKLIST, LIST_TRUSTED}:
        raise ValueError("Unsupported list type.")
    if scope not in {SCOPE_DOMAIN, SCOPE_URL}:
        raise ValueError("Unsupported list scope.")

    normalized_value = normalize_scope_value(value, scope)

    if not normalized_value:
        raise ValueError("List value is empty or invalid.")

    with connect() as connection:
        connection.execute(
            """
            INSERT INTO list_entries (
                list_type, scope, value, label, note, original_value,
                created_at, expires_at, active
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(list_type, scope, value) DO UPDATE SET
                label = excluded.label,
                note = excluded.note,
                original_value = excluded.original_value,
                expires_at = excluded.expires_at,
                active = 1
            """,
            (
                list_type,
                scope,
                normalized_value,
                label.strip(),
                note.strip(),
                value.strip(),
                utc_iso(),
                expires_at,
            ),
        )
        row = connection.execute(
            """
            SELECT *
            FROM list_entries
            WHERE list_type = ? AND scope = ? AND value = ?
            """,
            (list_type, scope, normalized_value),
        ).fetchone()

    saved = row_to_dict(row)

    if saved is None:
        raise RuntimeError("List entry was not saved.")

    return saved


def deactivate_list_entry(entry_id: int) -> None:
    with connect() as connection:
        connection.execute(
            "UPDATE list_entries SET active = 0 WHERE id = ?",
            (entry_id,),
        )


def list_entries(include_inactive: bool = False) -> list[dict[str, Any]]:
    query = """
        SELECT *
        FROM list_entries
    """
    params: tuple[Any, ...] = ()

    if not include_inactive:
        query += " WHERE active = 1"

    query += " ORDER BY list_type, scope, value"

    with connect() as connection:
        rows = connection.execute(query, params).fetchall()

    return [dict(row) for row in rows]


def active_expiry_clause() -> str:
    return "(expires_at IS NULL OR expires_at = '' OR expires_at > ?)"


def find_list_match(url: str, list_type: str | None = None) -> dict[str, Any] | None:
    normalized_url = normalize_url(url)
    hostname = extract_hostname(normalized_url)

    if not normalized_url or not hostname:
        return None

    query = f"""
        SELECT *
        FROM list_entries
        WHERE active = 1
          AND {active_expiry_clause()}
          AND (
            (scope = ? AND value = ?)
            OR (scope = ? AND value = ?)
          )
    """
    params: list[Any] = [utc_iso(), SCOPE_URL, normalized_url, SCOPE_DOMAIN, hostname]

    if list_type:
        query += " AND list_type = ?"
        params.append(list_type)

    query += """
        ORDER BY
            CASE list_type WHEN 'blacklist' THEN 0 ELSE 1 END,
            CASE scope WHEN 'url' THEN 0 ELSE 1 END,
            id DESC
        LIMIT 1
    """

    with connect() as connection:
        row = connection.execute(query, tuple(params)).fetchone()

    return row_to_dict(row)


def record_scan_event(
    target_url: str,
    result: dict[str, Any],
    page_url: str = "",
    source: str = "streamlit",
) -> None:
    normalized_target = normalize_url(target_url)
    normalized_page = page_url.strip()
    reasons = result.get("reasons", [])

    with connect() as connection:
        connection.execute(
            """
            INSERT INTO scan_events (
                page_url, page_hostname, page_domain,
                target_url, target_hostname, target_domain,
                verdict, score, source, reasons_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_page,
                extract_hostname(normalized_page),
                extract_registered_domain(normalized_page),
                normalized_target,
                extract_hostname(normalized_target),
                extract_registered_domain(normalized_target),
                str(result.get("verdict", "UNKNOWN")),
                int(result.get("score", 0) or 0),
                source,
                json.dumps(reasons, ensure_ascii=False),
                utc_iso(),
            ),
        )


def summarize_verdicts(page_domain: str | None = None) -> dict[str, int]:
    query = """
        SELECT verdict, COUNT(*) AS total
        FROM scan_events
    """
    params: tuple[Any, ...] = ()

    if page_domain:
        query += " WHERE page_domain = ?"
        params = (page_domain,)

    query += " GROUP BY verdict"

    with connect() as connection:
        rows = connection.execute(query, params).fetchall()

    return {row["verdict"]: int(row["total"]) for row in rows}


def summarize_page_domains(limit: int = 50) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT
                COALESCE(NULLIF(page_domain, ''), 'manual') AS page_domain,
                COUNT(*) AS events,
                COUNT(DISTINCT target_url) AS unique_links,
                SUM(CASE WHEN verdict = 'DANGEROUS' THEN 1 ELSE 0 END) AS dangerous,
                SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN verdict = 'SAFE' THEN 1 ELSE 0 END) AS safe,
                SUM(CASE WHEN verdict = 'NOT_FOUND' THEN 1 ELSE 0 END) AS not_found,
                SUM(CASE WHEN verdict = 'TRUSTED_BY_USER' THEN 1 ELSE 0 END) AS trusted_by_user,
                MAX(created_at) AS last_seen
            FROM scan_events
            GROUP BY COALESCE(NULLIF(page_domain, ''), 'manual')
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def recent_scan_events(limit: int = 100) -> list[dict[str, Any]]:
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM scan_events
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]
