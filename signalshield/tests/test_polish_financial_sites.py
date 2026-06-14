import json
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

from core import page_rules
from core.page_rules import analyze_page_rules


TRUSTED_BRANDS_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "trusted_brands.json"
)


def load_financial_domains(category: str) -> list[str]:
    with TRUSTED_BRANDS_PATH.open(encoding="utf-8") as file:
        trusted_brands = json.load(file)

    return trusted_brands[category]


PAYMENT_GATEWAYS = load_financial_domains("payments")
POLISH_BANKS = load_financial_domains("banks")

RANDOM_TUNNEL_LABEL_RE = re.compile(
    r"^[a-z0-9]+(?:-[a-z0-9]+)+$"
)

FAKE_FINANCIAL_PAGES = [
    pytest.param(
        (
            "https://emerald-howto-fathers-arab.trycloudflare.com/"
            "login/[0-9]/verify/.well-known/%27session%27"
        ),
        "tpay.com",
        "credential_form_on_tunnel",
        id="random-words-trycloudflare-tpay",
    ),
    pytest.param(
        (
            "https://bank-login-482901.ngrok-free.app/"
            "auth/[0-9]/konto/%27secure%27"
        ),
        "mbank.pl",
        "credential_form_on_tunnel",
        id="digits-ngrok-mbank",
    ),
    pytest.param(
        (
            "https://secure-auth-09.pages.dev/"
            "logowanie/[0-9]/./%27token%27"
        ),
        "pko-bp.pl",
        "credential_form_on_public_hosting",
        id="digits-cloudflare-pages-pko",
    ),
    pytest.param(
        (
            "https://payments-7f3a9c.workers.dev/"
            "payment/[0-9]/verify/%27blik%27"
        ),
        "przelewy24.pl",
        "credential_form_on_public_hosting",
        id="hex-cloudflare-workers-przelewy24",
    ),
]


def same_site_credential_form(domain: str) -> str:
    return f"""
    <html>
      <body>
        <form action="https://api.{domain}/session">
          <input type="email" name="email">
          <input type="password" name="password">
        </form>
      </body>
    </html>
    """


def reverse_proxy_clone(domain: str) -> str:
    return f"""
    <html>
      <head>
        <title>{domain} secure login</title>
        <link rel="stylesheet" href="https://static.{domain}/login.css">
      </head>
      <body>
        <img src="https://static.{domain}/logo.svg" alt="{domain}">
        <form action="/session">
          <input type="text" name="username">
          <input type="password" name="password">
        </form>
      </body>
    </html>
    """


@pytest.mark.parametrize("domain", PAYMENT_GATEWAYS)
def test_legitimate_payment_gateway_subdomain_is_not_blocked(domain: str) -> None:
    if page_rules.BeautifulSoup is None:
        pytest.skip("beautifulsoup4 is not installed")

    result = analyze_page_rules(
        f"https://secure.{domain}/payment",
        html=same_site_credential_form(domain),
        trusted_domains=PAYMENT_GATEWAYS,
    )

    assert result["score"] == 0
    assert result["hard_block"] is False
    assert result["matched_rules"] == []


@pytest.mark.parametrize("domain", PAYMENT_GATEWAYS)
def test_payment_gateway_clone_on_ngrok_is_blocked(domain: str) -> None:
    if page_rules.BeautifulSoup is None:
        pytest.skip("beautifulsoup4 is not installed")

    result = analyze_page_rules(
        f"https://secure-payment-{domain.replace('.', '-')}.ngrok-free.app/login",
        html=reverse_proxy_clone(domain),
        trusted_domains=PAYMENT_GATEWAYS,
    )

    matched_rule_ids = {rule["id"] for rule in result["matched_rules"]}

    assert result["score"] >= 70
    assert result["hard_block"] is True
    assert "credential_form_on_tunnel" in matched_rule_ids
    assert "trusted_brand_credential_form_on_external_domain" in matched_rule_ids


@pytest.mark.parametrize("domain", POLISH_BANKS)
def test_legitimate_polish_bank_subdomain_is_not_blocked(domain: str) -> None:
    if page_rules.BeautifulSoup is None:
        pytest.skip("beautifulsoup4 is not installed")

    result = analyze_page_rules(
        f"https://login.{domain}/session",
        html=same_site_credential_form(domain),
        trusted_domains=POLISH_BANKS,
    )

    assert result["score"] == 0
    assert result["hard_block"] is False
    assert result["matched_rules"] == []


@pytest.mark.parametrize("domain", POLISH_BANKS)
def test_polish_bank_clone_on_ngrok_is_blocked(domain: str) -> None:
    if page_rules.BeautifulSoup is None:
        pytest.skip("beautifulsoup4 is not installed")

    result = analyze_page_rules(
        f"https://bank-login-{domain.replace('.', '-')}.ngrok-free.app/login",
        html=reverse_proxy_clone(domain),
        trusted_domains=POLISH_BANKS,
    )

    matched_rule_ids = {rule["id"] for rule in result["matched_rules"]}

    assert result["score"] >= 70
    assert result["hard_block"] is True
    assert "credential_form_on_tunnel" in matched_rule_ids
    assert "trusted_brand_credential_form_on_external_domain" in matched_rule_ids


@pytest.mark.parametrize(
    ("fake_url", "impersonated_domain", "infrastructure_rule"),
    FAKE_FINANCIAL_PAGES,
)
def test_randomized_fake_financial_pages_are_blocked(
    fake_url: str,
    impersonated_domain: str,
    infrastructure_rule: str,
) -> None:
    if page_rules.BeautifulSoup is None:
        pytest.skip("beautifulsoup4 is not installed")

    hostname = urlparse(fake_url).hostname
    assert hostname is not None
    assert RANDOM_TUNNEL_LABEL_RE.fullmatch(hostname.split(".", maxsplit=1)[0])

    result = analyze_page_rules(
        fake_url,
        html=reverse_proxy_clone(impersonated_domain),
        trusted_domains=PAYMENT_GATEWAYS + POLISH_BANKS,
    )

    matched_rule_ids = {rule["id"] for rule in result["matched_rules"]}

    assert result["score"] >= 70
    assert result["hard_block"] is True
    assert infrastructure_rule in matched_rule_ids
    assert "trusted_brand_credential_form_on_external_domain" in matched_rule_ids
