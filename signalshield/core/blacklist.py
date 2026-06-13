from datetime import datetime, timedelta
from pathlib import Path

import requests
import tldextract

BLACKLIST_URL = "https://hole.cert.pl/domains/domains.txt"
CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "cert_blacklist.csv"
CACHE_MAX_AGE_HOURS = 6

FALLBACK_DOMAINS = {
    "allegro-platnosc24.pl",
    "allegro-platnosc.pl",
    "mbank-logowanie.com",
    "mbank-login24.pl",
    "mbank-secure.pl",
    "pko-bp-login.pl",
    "ing-bank.pl",
    "olx-payment.pl",
    "inpost-delivery.pl",
    "vinted-pay.pl",
}


def extract_domain(url: str) -> str:
    extracted = tldextract.extract(url)
    if not extracted.domain or not extracted.suffix:
        return url.lower().strip()
    return f"{extracted.domain}.{extracted.suffix}".lower()


def _load_cached_domains() -> set[str]:
    if not CACHE_PATH.exists():
        return set()

    domains: set[str] = set()
    with CACHE_PATH.open(encoding="utf-8") as file:
        for line in file:
            domain = line.strip().lower()
            if domain and domain != "domain":
                domains.add(domain)
    return domains


def _cache_is_fresh() -> bool:
    if not CACHE_PATH.exists():
        return False
    modified = datetime.fromtimestamp(CACHE_PATH.stat().st_mtime)
    return datetime.now() - modified < timedelta(hours=CACHE_MAX_AGE_HOURS)


def download_blacklist() -> set[str]:
    try:
        response = requests.get(BLACKLIST_URL, timeout=10)
        response.raise_for_status()
        domains = {
            line.strip().lower()
            for line in response.text.splitlines()
            if line.strip()
        }
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CACHE_PATH.open("w", encoding="utf-8") as file:
            file.write("domain\n")
            file.write("\n".join(sorted(domains)))
        return domains
    except Exception:
        cached = _load_cached_domains()
        return cached if cached else set(FALLBACK_DOMAINS)


def _get_blacklist_domains() -> set[str]:
    if not _cache_is_fresh():
        return download_blacklist()
    cached = _load_cached_domains()
    return cached if cached else set(FALLBACK_DOMAINS)


def check_blacklist(domain: str) -> bool:
    return domain.lower() in _get_blacklist_domains()
