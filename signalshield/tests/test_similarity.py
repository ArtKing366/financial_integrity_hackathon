from core.similarity import check_similarity, load_trusted_brands, normalize_domain


def test_normalize_domain_strips_diacritics() -> None:
    assert normalize_domain("allėgro.pl") == "allegro.pl"


def test_exact_trusted_domain_is_not_flagged() -> None:
    results = check_similarity("allegro.pl", load_trusted_brands())
    assert results == []


def test_typosquatting_is_detected() -> None:
    results = check_similarity("allegro-platnosc.pl", load_trusted_brands())
    assert results
    assert results[0][0] == "allegro.pl"


def test_homograph_attack_is_detected() -> None:
    results = check_similarity("allėgro.pl", load_trusted_brands())
    assert results
    assert results[0][0] == "allegro.pl"
    assert results[0][1] == 1.0


def test_brand_substring_is_detected() -> None:
    results = check_similarity("mbank-login24.pl", load_trusted_brands())
    assert results
    assert results[0][0] == "mbank.pl"
