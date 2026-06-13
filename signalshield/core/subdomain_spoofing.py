import json
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

import tldextract


DEFAULT_BRAND_KEYWORDS = [
    "mbank",
    "allegro",
    "olx",
    "vinted",
    "inpost",
    "pko-bp",
    "pkobp",
    "santander",
    "ing",
    "millennium",
    "pekao",
    "aliorbank",
    "dpd",
    "dhl",
    "poczta-polska",
    "pocztapolska",
    "blik",
]


def normalize_text(value: str) -> str:
    """
    Нормализует текст:
    - lowercase
    - убирает диакритику
    - оставляет удобный для сравнения формат
    """
    value = value.lower().strip()

    nfkd = unicodedata.normalize("NFKD", value)
    value = "".join(char for char in nfkd if not unicodedata.combining(char))

    return value


def compact_text(value: str) -> str:
    """
    Убирает все символы кроме букв и цифр.

    pko-bp -> pkobp
    poczta-polska -> pocztapolska
    """
    value = normalize_text(value)
    return re.sub(r"[^a-z0-9]", "", value)


def tokenize(value: str) -> list[str]:
    """
    Делит строку на токены.

    mbank.pl.secure -> ["mbank", "pl", "secure"]
    secure-pay -> ["secure", "pay"]
    """
    value = normalize_text(value)
    return [token for token in re.split(r"[^a-z0-9]+", value) if token]


def normalize_url(url_or_domain: str) -> str:
    value = url_or_domain.strip()

    if not value:
        return ""

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    return value


def extract_hostname(url_or_domain: str) -> str:
    url = normalize_url(url_or_domain)

    if not url:
        return ""

    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else ""


def load_brand_keywords() -> list[str]:
    """
    Загружает бренды из data/trusted_brands.json.

    Если файла нет, использует DEFAULT_BRAND_KEYWORDS.
    """
    project_root = Path(__file__).resolve().parents[1]
    brands_path = project_root / "data" / "trusted_brands.json"

    brands = set(DEFAULT_BRAND_KEYWORDS)

    if not brands_path.exists():
        return sorted(brands, key=len, reverse=True)

    try:
        with brands_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        trusted_domains = []

        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    trusted_domains.extend(value)

        elif isinstance(data, list):
            trusted_domains = data

        for trusted_domain in trusted_domains:
            extracted = tldextract.extract(trusted_domain)

            if extracted.domain:
                brand = extracted.domain.lower()
                brands.add(brand)
                brands.add(compact_text(brand))

    except Exception:
        pass

    return sorted(brands, key=len, reverse=True)


def contains_brand(value: str, brand: str) -> bool:
    """
    Проверяет, есть ли бренд в строке.

    Для коротких брендов типа ING используем осторожную проверку по токенам,
    чтобы случайно не поймать слово shopping.
    """
    value_normalized = normalize_text(value)
    value_tokens = tokenize(value_normalized)

    brand_normalized = normalize_text(brand)
    brand_compact = compact_text(brand_normalized)
    value_compact = compact_text(value_normalized)

    # Точное совпадение по токену
    if brand_normalized in value_tokens:
        return True

    # Для брендов с дефисами: pko-bp -> pkobp
    if brand_compact in value_tokens:
        return True

    # Для коротких брендов substring опасен.
    # Например, ing есть в shopping.
    if len(brand_compact) <= 3:
        return False

    # Для длинных брендов разрешаем substring.
    # Например, securembank всё равно подозрительно.
    if brand_compact in value_compact:
        return True

    return False


def find_brands_in_value(value: str, brand_keywords: list[str]) -> list[str]:
    matched = []

    for brand in brand_keywords:
        if contains_brand(value, brand):
            matched.append(brand)

    return matched


def check_subdomain_spoofing(url_or_domain: str) -> dict:
    """
    Проверяет трюк с поддоменом.

    Пример фишинга:
    https://mbank.pl.secure-pay.com

    Здесь:
    subdomain = mbank.pl
    domain = secure-pay
    suffix = com

    Бренд mbank находится в subdomain,
    но не находится в основном domain.
    Значит это подозрительно.
    """
    hostname = extract_hostname(url_or_domain)

    result = {
        "is_spoofed": False,
        "matched_brands": [],
        "hostname": hostname,
        "subdomain": "",
        "domain": "",
        "suffix": "",
        "registered_domain": "",
        "reason": "",
    }

    if not hostname:
        result["reason"] = "Invalid hostname."
        return result

    extracted = tldextract.extract(hostname)

    subdomain = extracted.subdomain or ""
    domain = extracted.domain or ""
    suffix = extracted.suffix or ""
    registered_domain = f"{domain}.{suffix}" if domain and suffix else domain

    result["subdomain"] = subdomain
    result["domain"] = domain
    result["suffix"] = suffix
    result["registered_domain"] = registered_domain

    # Если поддомена нет — проверять нечего
    if not subdomain:
        result["reason"] = "No subdomain detected."
        return result

    brand_keywords = load_brand_keywords()

    brands_in_subdomain = find_brands_in_value(subdomain, brand_keywords)
    brands_in_domain = find_brands_in_value(domain, brand_keywords)

    if brands_in_subdomain and not brands_in_domain:
        result["is_spoofed"] = True
        result["matched_brands"] = brands_in_subdomain
        result["reason"] = (
            "Brand name appears in subdomain, but the registered domain "
            "does not belong to that brand."
        )
        return result

    result["reason"] = "No subdomain spoofing detected."
    return result