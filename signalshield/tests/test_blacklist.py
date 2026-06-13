from core.blacklist import check_blacklist, extract_domain


def test_extract_domain_from_url() -> None:
    assert extract_domain("https://www.mbank.pl/login") == "mbank.pl"


def test_fallback_blacklist_detects_known_phishing_domain() -> None:
    assert check_blacklist("mbank-login24.pl") is True


def test_safe_domain_not_on_blacklist() -> None:
    assert check_blacklist("google.com") is False
