from core.local_db import (
    LIST_BLACKLIST,
    LIST_TRUSTED,
    SCOPE_DOMAIN,
    SCOPE_URL,
    add_list_entry,
    find_list_match,
    record_scan_event,
    summarize_page_domains,
    summarize_verdicts,
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
