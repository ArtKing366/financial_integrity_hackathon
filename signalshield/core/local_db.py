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
SOURCE_USER = "user"
SOURCE_CERT_POLSKA = "cert_polska"
SOURCE_TRUSTED_BRANDS = "trusted_brands"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "signalshield.sqlite3"
CERT_BLACKLIST_PATH = PROJECT_ROOT / "data" / "cert_blacklist.csv"
TRUSTED_BRANDS_PATH = PROJECT_ROOT / "data" / "trusted_brands.json"
BUILTIN_SYNC_VERSION = "2"


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

    if owns_connection:
        get_db_path().parent.mkdir(parents=True, exist_ok=True)

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
                source TEXT NOT NULL DEFAULT 'user',
                managed INTEGER NOT NULL DEFAULT 0,
                UNIQUE(list_type, scope, value)
            );

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

            CREATE TABLE IF NOT EXISTS db_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        ensure_list_entry_columns(connection)
        connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_list_entries_lookup_v2
            ON list_entries(list_type, scope, value, active, expires_at, source);

            CREATE INDEX IF NOT EXISTS idx_list_entries_source
            ON list_entries(source, active);
            """
        )
        connection.commit()
    finally:
        if owns_connection:
            connection.close()


def ensure_list_entry_columns(connection: sqlite3.Connection) -> None:
    rows = connection.execute("PRAGMA table_info(list_entries)").fetchall()
    columns = {row[1] for row in rows}

    if "source" not in columns:
        connection.execute(
            "ALTER TABLE list_entries ADD COLUMN source TEXT NOT NULL DEFAULT 'user'"
        )

    if "managed" not in columns:
        connection.execute(
            "ALTER TABLE list_entries ADD COLUMN managed INTEGER NOT NULL DEFAULT 0"
        )


def normalize_scope_value(value: str, scope: str) -> str:
    raw_value = value.strip()

    if scope == SCOPE_URL:
        return normalize_url(raw_value)

    hostname = extract_hostname(raw_value)
    return (hostname or raw_value).lower().strip()


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def opposite_list_type(list_type: str) -> str:
    return LIST_TRUSTED if list_type == LIST_BLACKLIST else LIST_BLACKLIST


def add_list_entry(
    list_type: str,
    scope: str,
    value: str,
    label: str = "",
    note: str = "",
    expires_at: str | None = None,
    source: str = SOURCE_USER,
    managed: bool = False,
) -> dict[str, Any]:
    if list_type not in {LIST_BLACKLIST, LIST_TRUSTED}:
        raise ValueError("Unsupported list type.")
    if scope not in {SCOPE_DOMAIN, SCOPE_URL}:
        raise ValueError("Unsupported list scope.")

    normalized_value = normalize_scope_value(value, scope)

    if not normalized_value:
        raise ValueError("List value is empty or invalid.")

    with connect() as connection:
        if source == SOURCE_USER:
            connection.execute(
                """
                UPDATE list_entries
                SET active = 0
                WHERE list_type = ?
                  AND scope = ?
                  AND value = ?
                  AND source = ?
                """,
                (opposite_list_type(list_type), scope, normalized_value, SOURCE_USER),
            )

        connection.execute(
            """
            INSERT INTO list_entries (
                list_type, scope, value, label, note, original_value,
                created_at, expires_at, active, source, managed
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(list_type, scope, value) DO UPDATE SET
                label = excluded.label,
                note = excluded.note,
                original_value = excluded.original_value,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at,
                active = 1,
                source = excluded.source,
                managed = excluded.managed
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
                source.strip() or SOURCE_USER,
                1 if managed else 0,
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


def deactivate_list_entry(entry_id: int) -> bool:
    with connect() as connection:
        cursor = connection.execute(
            "UPDATE list_entries SET active = 0 WHERE id = ?",
            (entry_id,),
        )

    return cursor.rowcount > 0


def list_entries(
    include_inactive: bool = False,
    include_expired: bool = False,
    include_system: bool = False,
) -> list[dict[str, Any]]:
    query = """
        SELECT *
        FROM list_entries
    """
    clauses: list[str] = []
    params: list[Any] = []

    if not include_inactive:
        clauses.append("active = 1")

    if not include_system:
        clauses.append("source = ?")
        params.append(SOURCE_USER)

    if not include_expired:
        clauses.append(active_expiry_clause())
        params.append(utc_iso())

    if clauses:
        query += " WHERE " + " AND ".join(clauses)

    query += " ORDER BY list_type, scope, value"

    with connect() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()

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
            CASE source WHEN 'user' THEN 0 ELSE 1 END,
            CASE list_type WHEN 'blacklist' THEN 0 ELSE 1 END,
            CASE scope WHEN 'url' THEN 0 ELSE 1 END,
            id DESC
        LIMIT 1
    """

    with connect() as connection:
        row = connection.execute(query, tuple(params)).fetchone()

    return row_to_dict(row)


def file_signature(path: Path) -> str:
    if not path.exists():
        return f"{BUILTIN_SYNC_VERSION}:missing"

    stat = path.stat()
    return f"{BUILTIN_SYNC_VERSION}:{stat.st_mtime_ns}:{stat.st_size}"


def metadata_value(connection: sqlite3.Connection, key: str) -> str:
    row = connection.execute(
        "SELECT value FROM db_metadata WHERE key = ?",
        (key,),
    ).fetchone()

    return row["value"] if row else ""


def set_metadata_value(connection: sqlite3.Connection, key: str, value: str) -> None:
    connection.execute(
        """
        INSERT INTO db_metadata (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )


def read_cert_blacklist_domains() -> set[str]:
    domains: set[str] = set()

    if CERT_BLACKLIST_PATH.exists():
        with CERT_BLACKLIST_PATH.open(encoding="utf-8") as file:
            for line in file:
                value = line.strip().lower()

                if value and value != "domain":
                    domains.add(value)

    try:
        from core.blacklist import FALLBACK_DOMAINS

        domains.update(FALLBACK_DOMAINS)
    except Exception:
        pass

    return {
        normalize_scope_value(domain, SCOPE_DOMAIN)
        for domain in domains
        if normalize_scope_value(domain, SCOPE_DOMAIN)
    }


def read_trusted_brand_domains() -> set[str]:
    if not TRUSTED_BRANDS_PATH.exists():
        return set()

    with TRUSTED_BRANDS_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    domains: list[str] = []

    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                domains.extend(str(item) for item in value)
    elif isinstance(data, list):
        domains.extend(str(item) for item in data)

    return {
        normalize_scope_value(domain, SCOPE_DOMAIN)
        for domain in domains
        if normalize_scope_value(domain, SCOPE_DOMAIN)
    }


def upsert_managed_entries(
    connection: sqlite3.Connection,
    list_type: str,
    values: set[str],
    source: str,
    label: str,
    note: str,
) -> int:
    now = utc_iso()
    rows = [
        (
            list_type,
            SCOPE_DOMAIN,
            value,
            label,
            note,
            value,
            now,
            None,
            source,
            1,
        )
        for value in sorted(values)
    ]

    if not rows:
        return 0

    connection.executemany(
        """
        INSERT INTO list_entries (
            list_type, scope, value, label, note, original_value,
            created_at, expires_at, active, source, managed
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(list_type, scope, value) DO UPDATE SET
            label = excluded.label,
            note = excluded.note,
            original_value = excluded.original_value,
            expires_at = excluded.expires_at,
            active = 1,
            source = excluded.source,
            managed = excluded.managed
        WHERE list_entries.source != 'user'
        """,
        rows,
    )
    return len(rows)


def sync_builtin_lists(force: bool = False) -> dict[str, Any]:
    cert_domains = read_cert_blacklist_domains()
    trusted_domains = read_trusted_brand_domains()
    cert_signature = f"{file_signature(CERT_BLACKLIST_PATH)}:{len(cert_domains)}"
    trusted_signature = f"{file_signature(TRUSTED_BRANDS_PATH)}:{len(trusted_domains)}"
    result = {
        SOURCE_CERT_POLSKA: {
            "available": len(cert_domains),
            "synced": 0,
            "skipped": False,
        },
        SOURCE_TRUSTED_BRANDS: {
            "available": len(trusted_domains),
            "synced": 0,
            "skipped": False,
        },
    }

    with connect() as connection:
        cert_key = f"builtin_sync:{SOURCE_CERT_POLSKA}"
        trusted_key = f"builtin_sync:{SOURCE_TRUSTED_BRANDS}"

        if force or metadata_value(connection, cert_key) != cert_signature:
            result[SOURCE_CERT_POLSKA]["synced"] = upsert_managed_entries(
                connection,
                LIST_BLACKLIST,
                cert_domains,
                SOURCE_CERT_POLSKA,
                "CERT Polska blacklist",
                "Managed built-in phishing domain list.",
            )
            set_metadata_value(connection, cert_key, cert_signature)
        else:
            result[SOURCE_CERT_POLSKA]["skipped"] = True

        if force or metadata_value(connection, trusted_key) != trusted_signature:
            result[SOURCE_TRUSTED_BRANDS]["synced"] = upsert_managed_entries(
                connection,
                LIST_TRUSTED,
                trusted_domains,
                SOURCE_TRUSTED_BRANDS,
                "Trusted brand list",
                "Managed built-in trusted domain list.",
            )
            set_metadata_value(connection, trusted_key, trusted_signature)
        else:
            result[SOURCE_TRUSTED_BRANDS]["skipped"] = True

    return result


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


def database_status() -> dict[str, Any]:
    now = utc_iso()

    with connect() as connection:
        active_rows = connection.execute(
            f"""
            SELECT list_type, COUNT(*) AS total
            FROM list_entries
            WHERE active = 1 AND {active_expiry_clause()}
            GROUP BY list_type
            """,
            (now,),
        ).fetchall()
        user_rows = connection.execute(
            f"""
            SELECT list_type, COUNT(*) AS total
            FROM list_entries
            WHERE active = 1 AND source = ? AND {active_expiry_clause()}
            GROUP BY list_type
            """,
            (SOURCE_USER, now),
        ).fetchall()
        managed_rows = connection.execute(
            f"""
            SELECT list_type, COUNT(*) AS total
            FROM list_entries
            WHERE active = 1 AND source != ? AND {active_expiry_clause()}
            GROUP BY list_type
            """,
            (SOURCE_USER, now),
        ).fetchall()
        scope_rows = connection.execute(
            f"""
            SELECT scope, COUNT(*) AS total
            FROM list_entries
            WHERE active = 1 AND {active_expiry_clause()}
            GROUP BY scope
            """,
            (now,),
        ).fetchall()
        source_rows = connection.execute(
            f"""
            SELECT source, COUNT(*) AS total
            FROM list_entries
            WHERE active = 1 AND {active_expiry_clause()}
            GROUP BY source
            """,
            (now,),
        ).fetchall()
        verdict_rows = connection.execute(
            """
            SELECT verdict, COUNT(*) AS total
            FROM scan_events
            GROUP BY verdict
            """
        ).fetchall()
        total_events = connection.execute(
            "SELECT COUNT(*) AS total FROM scan_events"
        ).fetchone()
        page_domains = connection.execute(
            """
            SELECT COUNT(DISTINCT COALESCE(NULLIF(page_domain, ''), 'manual')) AS total
            FROM scan_events
            """
        ).fetchone()
        last_seen = connection.execute(
            "SELECT MAX(created_at) AS value FROM scan_events"
        ).fetchone()

    active_entries = {LIST_BLACKLIST: 0, LIST_TRUSTED: 0}
    active_entries.update({
        row["list_type"]: int(row["total"])
        for row in active_rows
    })

    user_entries = {LIST_BLACKLIST: 0, LIST_TRUSTED: 0}
    user_entries.update({
        row["list_type"]: int(row["total"])
        for row in user_rows
    })

    managed_entries = {LIST_BLACKLIST: 0, LIST_TRUSTED: 0}
    managed_entries.update({
        row["list_type"]: int(row["total"])
        for row in managed_rows
    })

    scopes = {SCOPE_DOMAIN: 0, SCOPE_URL: 0}
    scopes.update({
        row["scope"]: int(row["total"])
        for row in scope_rows
    })

    sources = {
        row["source"]: int(row["total"])
        for row in source_rows
    }

    verdicts = {
        row["verdict"]: int(row["total"])
        for row in verdict_rows
    }

    return {
        "db_path": str(get_db_path()),
        "active_entries": {
            **active_entries,
            "total": sum(active_entries.values()),
        },
        "user_entries": {
            **user_entries,
            "total": sum(user_entries.values()),
        },
        "managed_entries": {
            **managed_entries,
            "total": sum(managed_entries.values()),
        },
        "active_sources": sources,
        "active_scopes": {
            **scopes,
            "total": sum(scopes.values()),
        },
        "scan_events": {
            "total": int(total_events["total"] or 0),
            "page_domains": int(page_domains["total"] or 0),
            "last_seen": last_seen["value"] or "",
        },
        "verdicts": verdicts,
    }
