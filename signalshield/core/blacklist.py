from datetime import datetime, timedelta
from pathlib import Path

from core.domain_utils import extract_registered_domain

try:
    import requests
except Exception:
    requests = None


BLACKLIST_URL = "https://hole.cert.pl/domains/domains.txt"
CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "cert_blacklist.csv"
CACHE_MAX_AGE_HOURS = 6
_BLACKLIST_MEMORY_CACHE: set[str] | None = None
_BLACKLIST_MEMORY_CACHE_TIME: datetime | None = None

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


def extract_domain(url_or_domain: str) -> str:
    return extract_registered_domain(url_or_domain).lower().strip()


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
    if requests is None:
        cached = _load_cached_domains()
        return cached | set(FALLBACK_DOMAINS)

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
        return domains | set(FALLBACK_DOMAINS)
    except Exception:
        cached = _load_cached_domains()
        return cached | set(FALLBACK_DOMAINS)


def _get_blacklist_domains() -> set[str]:
    global _BLACKLIST_MEMORY_CACHE, _BLACKLIST_MEMORY_CACHE_TIME

    if (
        _BLACKLIST_MEMORY_CACHE is not None
        and _BLACKLIST_MEMORY_CACHE_TIME is not None
        and datetime.now() - _BLACKLIST_MEMORY_CACHE_TIME < timedelta(hours=CACHE_MAX_AGE_HOURS)
    ):
        return _BLACKLIST_MEMORY_CACHE

    if not _cache_is_fresh():
        domains = download_blacklist()
    else:
        cached = _load_cached_domains()
        domains = cached | set(FALLBACK_DOMAINS)

    _BLACKLIST_MEMORY_CACHE = domains
    _BLACKLIST_MEMORY_CACHE_TIME = datetime.now()
    return domains


def check_blacklist(url_or_domain: str) -> bool:
    value = url_or_domain.lower().strip()
    domain = extract_domain(value)
    blacklist = _get_blacklist_domains()
    return value in blacklist or domain in blacklist
