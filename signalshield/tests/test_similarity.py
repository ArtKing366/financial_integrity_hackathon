from core.similarity import check_similarity, load_trusted_brands, normalize_domain


def test_normalize_domain_strips_diacritics() -> None:
    assert normalize_domain("all\u0117gro.pl") == "allegro.pl"


def test_exact_trusted_domain_is_not_flagged() -> None:
    results = check_similarity("allegro.pl", load_trusted_brands())
    assert results == []


def test_trusted_google_country_domain_is_not_flagged() -> None:
    results = check_similarity("google.pl", load_trusted_brands())
    assert results == []


def test_exact_trusted_payment_domain_is_not_compared_to_other_payment_brand() -> None:
    results = check_similarity("tpay.com", load_trusted_brands())
    assert results == []


def test_typosquatting_is_detected() -> None:
    results = check_similarity("allegro-platnosc.pl", load_trusted_brands())
    assert results
    assert results[0][0] == "allegro.pl"


def test_google_digit_substitution_is_detected() -> None:
    results = check_similarity("go0gle.com", load_trusted_brands())
    assert results
    assert results[0][0] == "google.com"


def test_homograph_attack_is_detected() -> None:
    results = check_similarity("all\u0117gro.pl", load_trusted_brands())
    assert results
    assert results[0][0] == "allegro.pl"
    assert results[0][1] == 1.0


def test_brand_substring_is_detected() -> None:
    results = check_similarity("mbank-login24.pl", load_trusted_brands())
    assert results
    assert results[0][0] == "mbank.pl"
