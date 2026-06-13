from unittest.mock import patch

import pytest

from core.local_db import LIST_BLACKLIST, LIST_TRUSTED, SCOPE_DOMAIN, add_list_entry
from core.verdict import (
    VERDICT_DANGEROUS,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    VERDICT_TRUSTED_BY_USER,
    analyze_url,
)

TEST_CASES = [
    ("https://allegro.pl", VERDICT_SAFE),
    ("https://allegro-platnosc24.pl", VERDICT_DANGEROUS),
    ("https://mbank.pl", VERDICT_SAFE),
    ("https://mbank-logowanie.com", VERDICT_DANGEROUS),
    ("https://inpost.pl", VERDICT_SAFE),
    ("https://vasiapupkin.xyz/allegro.pl/pay/blik-secure", VERDICT_SUSPICIOUS),
    ("https://random-long-domain-name-test.pl/login", VERDICT_DANGEROUS),
]


@pytest.mark.parametrize("url,expected_verdict", TEST_CASES)
def test_analyze_url_cases(url: str, expected_verdict: str) -> None:
    with (
        patch("core.verdict.get_domain_age", return_value=None),
        patch("core.verdict.check_blacklist", return_value=False),
        patch(
            "core.verdict.check_page_existence",
            return_value={"status": "exists", "exists": True, "evidence": []},
        ),
        patch(
            "core.verdict.analyze_dns_infrastructure",
            return_value={"score": 0, "status": "mx_found"},
        ),
        patch(
            "core.verdict.analyze_html_crawling",
            return_value={"score": 0, "matched_rules": []},
        ),
        patch(
            "core.verdict.analyze_page_rules",
            return_value={"score": 0, "hard_block": False, "matched_rules": []},
        ),
    ):
        result = analyze_url(url)
    assert result["verdict"] == expected_verdict


def test_local_blacklist_overrides_analyzer() -> None:
    add_list_entry(LIST_BLACKLIST, SCOPE_DOMAIN, "local-danger.example")

    result = analyze_url("https://local-danger.example/pay")

    assert result["verdict"] == VERDICT_DANGEROUS
    assert result["score"] == 100
    assert result["details"]["local_list_match"]["list_type"] == LIST_BLACKLIST


def test_user_trusted_list_keeps_original_verdict() -> None:
    add_list_entry(LIST_TRUSTED, SCOPE_DOMAIN, "trusted-risk.example")

    with (
        patch("core.verdict.get_domain_age", return_value=None),
        patch("core.verdict.check_blacklist", return_value=False),
        patch(
            "core.verdict.check_page_existence",
            return_value={"status": "exists", "exists": True, "evidence": []},
        ),
        patch(
            "core.verdict.analyze_dns_infrastructure",
            return_value={"score": 0, "status": "mx_found"},
        ),
        patch(
            "core.verdict.analyze_html_crawling",
            return_value={"score": 0, "matched_rules": []},
        ),
        patch(
            "core.verdict.analyze_page_rules",
            return_value={"score": 0, "hard_block": False, "matched_rules": []},
        ),
    ):
        result = analyze_url("https://trusted-risk.example/allegro.pl/pay/blik-secure")

    assert result["verdict"] == VERDICT_TRUSTED_BY_USER
    assert result["details"]["original_verdict"] in {VERDICT_SUSPICIOUS, VERDICT_DANGEROUS}
    assert result["details"]["local_list_match"]["list_type"] == LIST_TRUSTED
