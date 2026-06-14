from datetime import timedelta

from core.local_db import (
    LIST_BLACKLIST,
    LIST_TRUSTED,
    SOURCE_CERT_POLSKA,
    SOURCE_TRUSTED_BRANDS,
    SCOPE_DOMAIN,
    SCOPE_URL,
    add_list_entry,
    database_status,
    deactivate_list_entry,
    find_list_match,
    list_entries,
    record_scan_event,
    sync_builtin_lists,
    summarize_page_domains,
    summarize_verdicts,
    utc_iso,
    utc_now,
)


def test_domain_entry_matches_exact_hostname_only() -> None:
    add_list_entry(LIST_TRUSTED, SCOPE_DOMAIN, "example.com")

    assert find_list_match("https://example.com/pay", LIST_TRUSTED)["value"] == "example.com"
    assert find_list_match("https://login.example.com/pay", LIST_TRUSTED) is None


def test_url_entry_matches_exact_normalized_url() -> None:
    add_list_entry(LIST_BLACKLIST, SCOPE_URL, "example.com/pay")

    assert find_list_match("https://example.com/pay", LIST_BLACKLIST)["scope"] == SCOPE_URL
    assert find_list_match("https://example.com/other", LIST_BLACKLIST) is None


def test_blacklist_takes_priority_over_trusted_entry() -> None:
    add_list_entry(LIST_TRUSTED, SCOPE_DOMAIN, "priority.example")
    add_list_entry(LIST_BLACKLIST, SCOPE_DOMAIN, "priority.example")

    match = find_list_match("https://priority.example/login")

    assert match["list_type"] == LIST_BLACKLIST


def test_user_lists_are_mutually_exclusive_for_same_target() -> None:
    blocked = add_list_entry(LIST_BLACKLIST, SCOPE_URL, "https://flip.example/pay")
    trusted = add_list_entry(LIST_TRUSTED, SCOPE_URL, "https://flip.example/pay")

    entries = list_entries(include_inactive=True)
    blocked_entry = next(entry for entry in entries if entry["id"] == blocked["id"])

    assert blocked_entry["active"] == 0
    assert trusted["active"] == 1
    assert find_list_match("https://flip.example/pay")["list_type"] == LIST_TRUSTED


def test_user_trusted_entry_wins_over_managed_blacklist() -> None:
    add_list_entry(
        LIST_BLACKLIST,
        SCOPE_DOMAIN,
        "managed-danger.example",
        source=SOURCE_CERT_POLSKA,
        managed=True,
    )
    add_list_entry(LIST_TRUSTED, SCOPE_DOMAIN, "managed-danger.example")

    match = find_list_match("https://managed-danger.example/pay")

    assert match["list_type"] == LIST_TRUSTED
    assert match["source"] == "user"


def test_scan_event_analytics_group_by_page_domain() -> None:
    record_scan_event(
        "https://evil-example.pl/pay",
        {"verdict": "DANGEROUS", "score": 100, "reasons": ["Demo risk."]},
        page_url="https://shop-example.pl/cart",
        source="test",
    )
    record_scan_event(
        "https://safe-example.pl/",
        {"verdict": "SAFE", "score": 0, "reasons": []},
        page_url="https://shop-example.pl/cart",
        source="test",
    )

    verdicts = summarize_verdicts("shop-example.pl")
    rows = summarize_page_domains()
    shop_row = next(row for row in rows if row["page_domain"] == "shop-example.pl")

    assert verdicts["DANGEROUS"] == 1
    assert verdicts["SAFE"] == 1
    assert shop_row["unique_links"] == 2


def test_list_entries_hide_expired_entries_by_default(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SIGNALSHIELD_DB_PATH", str(tmp_path / "expired.sqlite3"))
    expires_at = utc_iso(utc_now() - timedelta(minutes=1))

    add_list_entry(LIST_TRUSTED, SCOPE_URL, "https://expired.example/pay", expires_at=expires_at)

    assert list_entries() == []
    assert list_entries(include_expired=True)[0]["value"] == "https://expired.example/pay"


def test_database_status_reports_lists_and_scan_events(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SIGNALSHIELD_DB_PATH", str(tmp_path / "status.sqlite3"))
    trusted = add_list_entry(LIST_TRUSTED, SCOPE_URL, "https://trusted-status.example/")
    add_list_entry(LIST_BLACKLIST, SCOPE_DOMAIN, "blocked-status.example")
    record_scan_event(
        "https://blocked-status.example/pay",
        {"verdict": "DANGEROUS", "score": 90, "reasons": ["Blocked locally."]},
        page_url="https://status-page.example/cart",
        source="test",
    )

    status = database_status()

    assert status["db_path"].endswith("status.sqlite3")
    assert status["active_entries"][LIST_TRUSTED] == 1
    assert status["active_entries"][LIST_BLACKLIST] == 1
    assert status["active_scopes"][SCOPE_URL] == 1
    assert status["active_scopes"][SCOPE_DOMAIN] == 1
    assert status["scan_events"]["total"] == 1
    assert status["scan_events"]["page_domains"] == 1
    assert status["verdicts"]["DANGEROUS"] == 1

    assert deactivate_list_entry(trusted["id"]) is True
    assert database_status()["active_entries"][LIST_TRUSTED] == 0


def test_sync_builtin_lists_imports_managed_sources(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "sync.sqlite3"
    cert_path = tmp_path / "cert.csv"
    trusted_path = tmp_path / "trusted.json"
    cert_path.write_text("domain\nfresh-bad.example\n", encoding="utf-8")
    trusted_path.write_text('{"banks": ["fresh-bank.example"]}', encoding="utf-8")

    monkeypatch.setenv("SIGNALSHIELD_DB_PATH", str(db_path))
    monkeypatch.setattr("core.local_db.CERT_BLACKLIST_PATH", cert_path)
    monkeypatch.setattr("core.local_db.TRUSTED_BRANDS_PATH", trusted_path)

    summary = sync_builtin_lists(force=True)
    user_entries = list_entries()
    all_entries = list_entries(include_system=True)
    sources = {entry["source"] for entry in all_entries}

    assert summary[SOURCE_CERT_POLSKA]["available"] >= 1
    assert summary[SOURCE_TRUSTED_BRANDS]["available"] == 1
    assert user_entries == []
    assert SOURCE_CERT_POLSKA in sources
    assert SOURCE_TRUSTED_BRANDS in sources
