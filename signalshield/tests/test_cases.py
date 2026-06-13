from unittest.mock import patch

import pytest

from core.verdict import VERDICT_DANGEROUS, VERDICT_SAFE, VERDICT_SUSPICIOUS, analyze_url

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
