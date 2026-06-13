from core import blacklist
from core.blacklist import check_blacklist, extract_domain


def test_extract_domain_from_url() -> None:
    assert extract_domain("https://www.mbank.pl/login") == "mbank.pl"


def test_fallback_blacklist_detects_known_phishing_domain() -> None:
    assert check_blacklist("mbank-login24.pl") is True


def test_safe_domain_not_on_blacklist() -> None:
    assert check_blacklist("google.com") is False


def test_downloaded_blacklist_keeps_offline_demo_fallback(monkeypatch, tmp_path) -> None:
    class FakeResponse:
        text = "fresh-phishing.example\n"

        def raise_for_status(self) -> None:
            return None

    class FakeRequests:
        @staticmethod
        def get(url: str, timeout: int):
            return FakeResponse()

    monkeypatch.setattr(blacklist, "requests", FakeRequests)
    monkeypatch.setattr(blacklist, "CACHE_PATH", tmp_path / "cert_blacklist.csv")

    domains = blacklist.download_blacklist()

    assert "fresh-phishing.example" in domains
    assert "mbank-login24.pl" in domains
