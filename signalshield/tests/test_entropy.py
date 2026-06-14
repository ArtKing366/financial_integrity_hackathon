from core.entropy import (
    DEFAULT_ENTROPY_THRESHOLD,
    check_domain_entropy,
    extract_domain_core,
    shannon_entropy,
)


def test_shannon_entropy_zero_for_repeated_character() -> None:
    assert shannon_entropy("oooooo") == 0.0


def test_shannon_entropy_low_for_natural_word() -> None:
    assert shannon_entropy("allegro") < DEFAULT_ENTROPY_THRESHOLD


def test_shannon_entropy_high_for_random_suffix_domain() -> None:
    assert shannon_entropy("allegro-blik-3x9w1z") > DEFAULT_ENTROPY_THRESHOLD


def test_extract_domain_core_strips_protocol_and_path() -> None:
    assert extract_domain_core("https://www.allegro-blik-3x9w1z.top/pay") == "allegro-blik-3x9w1z"


def test_allegro_pl_is_not_flagged() -> None:
    result = check_domain_entropy("https://allegro.pl")
    assert result["flagged"] is False
    assert result["score"] == 0


def test_allegro_platnosc_is_not_flagged_by_entropy() -> None:
    result = check_domain_entropy("https://allegro-platnosc.com")
    assert result["flagged"] is False


def test_robot_generated_domain_is_flagged() -> None:
    result = check_domain_entropy("https://allegro-blik-3x9w1z.top")
    assert result["flagged"] is True
    assert result["score"] == 50


def test_mbank_secure_random_suffix_is_flagged() -> None:
    result = check_domain_entropy("https://mbank-secure-9x2w.top")
    assert result["flagged"] is True
