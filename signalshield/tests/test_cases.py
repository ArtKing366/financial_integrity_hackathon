from unittest.mock import patch

import pytest

from core.verdict import VERDICT_DANGEROUS, VERDICT_SAFE, analyze_url

TEST_CASES = [
    ("https://allegro.pl", VERDICT_SAFE),
    ("https://allegro-platnosc24.pl", VERDICT_DANGEROUS),
    ("https://mbank.pl", VERDICT_SAFE),
    ("https://mbank-logowanie.com", VERDICT_DANGEROUS),
    ("https://inpost.pl", VERDICT_SAFE),
]


@pytest.mark.parametrize("url,expected_verdict", TEST_CASES)
def test_analyze_url_cases(url: str, expected_verdict: str) -> None:
    with patch("core.verdict.get_domain_age", return_value=None):
        with patch("core.verdict.check_blacklist", return_value=False):
            result = analyze_url(url)
    assert result["verdict"] == expected_verdict
