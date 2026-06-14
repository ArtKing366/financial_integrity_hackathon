from pathlib import Path
from urllib.parse import urlparse
import csv
import time

import requests
import tldextract


CERT_BLACKLIST_URL = "https://hole.cert.pl/domains/v2/domains.txt"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CACHE_PATH = PROJECT_ROOT / "data" / "cert_blacklist.csv"

# Для демо можно 6 часов.
# Для реальной интеграции CERT рекомендует обновлять список чаще.
CACHE_TTL_SECONDS = 6 * 60 * 60

REQUEST_TIMEOUT = 10


def is_cache_fresh() -> bool:
    """
    Проверяет, существует ли локальный кэш и не устарел ли он.
    """
    if not CACHE_PATH.exists():
        return False

    cache_age = time.time() - CACHE_PATH.stat().st_mtime
    return cache_age < CACHE_TTL_SECONDS


def save_cache(domains: set[str]) -> None:
    """
    Сохраняет домены в локальный CSV-файл.
    Один домен = одна строка.
    """
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with CACHE_PATH.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        for domain in sorted(domains):
            writer.writerow([domain])


def load_cache() -> set[str]:
    """
    Загружает домены из локального кэша.
    Если кэша нет — возвращает пустой set.
    """
    if not CACHE_PATH.exists():
        return set()

    domains = set()

    with CACHE_PATH.open("r", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if row:
                domains.add(row[0].strip().lower())

    return domains


def download_blacklist(force: bool = False) -> set[str]:
    """
    Скачивает список CERT Polska и кэширует его.
    Если кэш свежий, использует кэш.
    Если CERT недоступен, использует старый локальный кэш.
    """
    if not force and is_cache_fresh():
        return load_cache()

    try:
        response = requests.get(CERT_BLACKLIST_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        domains = set()

        for line in response.text.splitlines():
            domain = line.strip().lower()

            if domain and not domain.startswith("#"):
                domains.add(domain)

        save_cache(domains)
        return domains

    except requests.RequestException:
        # Если CERT недоступен — не ломаем приложение.
        # Просто используем локальный кэш.
        return load_cache()


def extract_hostname(url_or_domain: str) -> str:
    """
    Извлекает hostname из URL или домена.

    Примеры:
    https://example.com/path -> example.com
    example.com -> example.com
    https://login.mbank.pl:443/test -> login.mbank.pl
    """
    value = url_or_domain.strip().lower()

    if not value:
        return ""

    if "://" not in value:
        value = "http://" + value

    parsed = urlparse(value)
    hostname = parsed.hostname

    if not hostname:
        return ""

    hostname = hostname.strip(".").lower()

    # Используем tldextract, чтобы аккуратно разобрать домен.
    extracted = tldextract.extract(hostname)

    if not extracted.domain or not extracted.suffix:
        return hostname

    parts = []

    if extracted.subdomain:
        parts.append(extracted.subdomain)

    parts.append(extracted.domain)
    parts.append(extracted.suffix)

    return ".".join(parts)


def generate_domain_candidates(hostname: str) -> list[str]:
    """
    Генерирует варианты домена для проверки.

    Например:
    b.a.example.com ->
    [
        "b.a.example.com",
        "a.example.com",
        "example.com"
    ]

    Это нужно, потому что если CERT заблокировал a.example.com,
    то b.a.example.com тоже должен считаться опасным.
    """
    parts = hostname.split(".")

    candidates = []

    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        candidates.append(candidate)

    return candidates


def check_blacklist(url_or_domain: str) -> bool:
    """
    Проверяет, находится ли домен или его родительский поддомен
    в чёрном списке CERT Polska.

    Возвращает:
    True  — домен найден в blacklist
    False — домен не найден
    """
    hostname = extract_hostname(url_or_domain)

    if not hostname:
        return False

    blacklist = download_blacklist()
    candidates = generate_domain_candidates(hostname)

    for candidate in candidates:
        if candidate in blacklist:
            return True

    return False