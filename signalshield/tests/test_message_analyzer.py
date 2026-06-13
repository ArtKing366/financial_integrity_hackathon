from core import message_analyzer
from core.message_analyzer import (
    VERDICT_DANGEROUS,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    analyze_message,
    characterize_link,
    extract_links,
)


def test_extract_links_finds_full_www_and_bare_urls() -> None:
    links = extract_links(
        "Pay at https://evil.example/pay, then check www.bank.pl and mbank-login24.pl."
    )

    urls = [link["url"] for link in links]

    assert "https://evil.example/pay" in urls
    assert "https://www.bank.pl" in urls
    assert "https://mbank-login24.pl" in urls


def test_characterize_link_flags_shortener_and_suspicious_tld() -> None:
    result = characterize_link("http://bit.ly/pay")

    assert result["score"] >= 20
    assert result["is_shortener"] is True
    assert result["uses_https"] is False


def test_analyze_message_combines_text_and_link_risk(monkeypatch) -> None:
    def fake_analyze_url(url: str) -> dict:
        return {
            "verdict": VERDICT_SUSPICIOUS,
            "score": 30,
            "reasons": ["Fake link risk."],
            "details": {"input_url": url, "domain": "evil.example"},
        }

    monkeypatch.setattr(message_analyzer, "analyze_url", fake_analyze_url)

    result = analyze_message("Pilne: dopłata do paczki https://evil.example/pay kod BLIK")

    assert result["verdict"] == VERDICT_DANGEROUS
    assert result["links"][0]["score"] == 30
    assert result["message_signals"]["score"] >= 20


def test_message_without_links_can_still_be_suspicious() -> None:
    result = analyze_message(
        "Pracownik banku prosi o kod SMS i instalację AnyDesk do weryfikacji."
    )

    assert result["verdict"] == VERDICT_DANGEROUS
    assert result["details"]["link_count"] == 0


def test_plain_message_without_links_is_safe() -> None:
    result = analyze_message("Dzień dobry, potwierdzam spotkanie jutro o 10.")

    assert result["verdict"] == VERDICT_SAFE
    assert result["score"] == 0
