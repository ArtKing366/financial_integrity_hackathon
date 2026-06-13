"""Этап 1: проверка по чёрному списку CERT Polska."""

from datetime import datetime, timedelta
from pathlib import Path

import requests
import tldextract

BLACKLIST_URL = "https://hole.cert.pl/domains/domains.txt"
CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "cert_blacklist.csv"
CACHE_MAX_AGE_HOURS = 6


def extract_domain(url: str) -> str:
    """Извлекает зарегистрированный домен из URL."""
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
    """Скачивает список CERT и кэширует в data/cert_blacklist.csv."""
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
        return _load_cached_domains()


def check_blacklist(domain: str) -> bool:
    """Проверяет домен по кэшированному чёрному списку."""
    if not _cache_is_fresh():
        domains = download_blacklist()
    else:
        domains = _load_cached_domains()

    return domain.lower() in domains
