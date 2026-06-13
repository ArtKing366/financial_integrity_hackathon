import pytest

from core import page_rules
from core.page_rules import analyze_page_rules


def test_non_microsoft_password_form_is_not_scored_by_microsoft_rules(monkeypatch) -> None:
    if page_rules.BeautifulSoup is None:
        pytest.skip("beautifulsoup4 is not installed")

    html = """
    <html>
      <body>
        <form action="/login">
          <input type="password" name="password">
        </form>
      </body>
    </html>
    """

    monkeypatch.setattr(page_rules, "fetch_page", lambda url: (html, None))

    result = analyze_page_rules("https://bank-example.pl/login")

    assert result["score"] == 0
    assert result["hard_block"] is False
    assert result["matched_rules"] == []


def test_microsoft_like_password_form_still_scores(monkeypatch) -> None:
    if page_rules.BeautifulSoup is None:
        pytest.skip("beautifulsoup4 is not installed")

    html = """
    <html>
      <body>
        Microsoft 365
        <form action="/collect">
          <input type="email" name="login">
          <input type="password" name="password">
        </form>
      </body>
    </html>
    """

    monkeypatch.setattr(page_rules, "fetch_page", lambda url: (html, None))

    result = analyze_page_rules("https://secure-microsoft-login.example")

    assert result["score"] >= 50
    assert result["hard_block"] is True
