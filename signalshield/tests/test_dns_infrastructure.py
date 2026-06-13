from core import dns_infrastructure
from core.dns_infrastructure import analyze_dns_infrastructure


def test_trusted_domain_skips_mx_check() -> None:
    result = analyze_dns_infrastructure("https://allegro.pl", ["allegro.pl"])

    assert result["score"] == 0
    assert result["status"] == "trusted_domain"


def test_missing_mx_records_add_risk(monkeypatch) -> None:
    monkeypatch.setattr(dns_infrastructure, "domain_resolves", lambda domain: True)
    monkeypatch.setattr(dns_infrastructure, "resolve_mx_records", lambda domain: [])

    result = analyze_dns_infrastructure("https://vasiapupkin.xyz", ["allegro.pl"])

    assert result["score"] == 10
    assert result["status"] == "no_mx"


def test_existing_mx_records_do_not_add_risk(monkeypatch) -> None:
    monkeypatch.setattr(dns_infrastructure, "domain_resolves", lambda domain: True)
    monkeypatch.setattr(
        dns_infrastructure,
        "resolve_mx_records",
        lambda domain: ["mail.example.com"],
    )

    result = analyze_dns_infrastructure("https://example.com", ["allegro.pl"])

    assert result["score"] == 0
    assert result["status"] == "mx_found"


def test_unresolved_domain_does_not_duplicate_missing_domain_risk(monkeypatch) -> None:
    monkeypatch.setattr(dns_infrastructure, "domain_resolves", lambda domain: False)

    result = analyze_dns_infrastructure("https://not-real-example.invalid", [])

    assert result["score"] == 0
    assert result["status"] == "domain_not_found"
