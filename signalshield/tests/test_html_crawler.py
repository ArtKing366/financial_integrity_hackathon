from core import html_crawler
from core.html_crawler import analyze_html_crawling


def test_password_field_on_untrusted_domain_adds_risk(monkeypatch) -> None:
    monkeypatch.setattr(
        html_crawler,
        "fetch_html",
        lambda url: ('<form><input type="password" name="pass"></form>', None),
    )

    result = analyze_html_crawling("https://vasiapupkin.xyz", ["allegro.pl"])

    assert result["score"] >= 15
    assert result["password_field_count"] == 1


def test_hidden_password_field_is_high_risk(monkeypatch) -> None:
    monkeypatch.setattr(
        html_crawler,
        "fetch_html",
        lambda url: ('<input type="password" style="display:none">', None),
    )

    result = analyze_html_crawling("https://vasiapupkin.xyz", ["allegro.pl"])

    assert result["score"] >= 35
    assert result["hidden_password_field_count"] == 1


def test_polish_payment_markers_on_untrusted_domain_add_risk(monkeypatch) -> None:
    monkeypatch.setattr(
        html_crawler,
        "fetch_html",
        lambda url: ("<html>Zaloguj sie i podaj kod BLIK oraz płatność</html>", None),
    )

    result = analyze_html_crawling("https://vasiapupkin.xyz", ["allegro.pl"])

    assert result["score"] == 10
    assert "blik" in result["matched_markers"]
    assert "platnosc" in result["matched_markers"]
    assert "zaloguj" in result["matched_markers"]


def test_trusted_domain_does_not_score_even_with_login_form(monkeypatch) -> None:
    monkeypatch.setattr(
        html_crawler,
        "fetch_html",
        lambda url: ('<form><input type="password">Zaloguj BLIK</form>', None),
    )

    result = analyze_html_crawling("https://allegro.pl/login", ["allegro.pl"])

    assert result["score"] == 0
    assert result["password_field_count"] == 1
    assert result["matched_markers"]
