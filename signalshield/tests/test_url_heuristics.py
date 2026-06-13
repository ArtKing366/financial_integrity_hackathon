from core.url_heuristics import (
    analyze_url_heuristics,
    check_domain_ugliness,
    check_path_keywords,
)
from core.verdict import load_trusted_brands


def test_path_keywords_on_untrusted_domain_are_detected() -> None:
    result = check_path_keywords(
        "https://vasiapupkin.xyz/allegro.pl/pay/blik-secure",
        load_trusted_brands(),
    )

    assert result["score"] >= 20
    assert "blik" in result["matched_keywords"]
    assert "allegro.pl" in result["matched_brands"]


def test_path_keywords_on_trusted_domain_are_ignored() -> None:
    result = check_path_keywords(
        "https://allegro.pl/pay/blik-secure",
        load_trusted_brands(),
    )

    assert result["score"] == 0


def test_domain_ugliness_is_detected() -> None:
    result = check_domain_ugliness("https://inpost-paczka-za-pobraniem-24.pl")

    assert result["score"] >= 20
    assert result["hyphen_count"] >= 3


def test_url_heuristics_accumulate_scores() -> None:
    result = analyze_url_heuristics(
        "https://vasiapupkin.xyz/allegro.pl/pay/blik-secure",
        load_trusted_brands(),
    )

    assert result["score"] >= 20
    assert result["matched_rules"]
