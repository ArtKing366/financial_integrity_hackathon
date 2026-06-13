import json
import re
import unicodedata
from pathlib import Path

from core.domain_utils import extract_hostname, split_domain


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
    value = value.lower().strip()
    nfkd = unicodedata.normalize("NFKD", value)
    return "".join(char for char in nfkd if not unicodedata.combining(char))


def compact_text(value: str) -> str:
    value = normalize_text(value)
    return re.sub(r"[^a-z0-9]", "", value)


def tokenize(value: str) -> list[str]:
    value = normalize_text(value)
    return [token for token in re.split(r"[^a-z0-9]+", value) if token]


def load_brand_keywords() -> list[str]:
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
            split = split_domain(trusted_domain)
            brand = split["domain"].lower()

            if brand:
                brands.add(brand)
                brands.add(compact_text(brand))

    except Exception:
        pass

    return sorted(brands, key=len, reverse=True)


def contains_brand(value: str, brand: str) -> bool:
    value_normalized = normalize_text(value)
    value_tokens = tokenize(value_normalized)

    brand_normalized = normalize_text(brand)
    brand_compact = compact_text(brand_normalized)
    value_compact = compact_text(value_normalized)

    if brand_normalized in value_tokens:
        return True

    if brand_compact in value_tokens:
        return True

    if len(brand_compact) <= 3:
        return False

    return brand_compact in value_compact


def find_brands_in_value(value: str, brand_keywords: list[str]) -> list[str]:
    return [brand for brand in brand_keywords if contains_brand(value, brand)]


def check_subdomain_spoofing(url_or_domain: str) -> dict:
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

    split = split_domain(hostname)
    subdomain = split["subdomain"]
    domain = split["domain"]

    result.update({
        "subdomain": subdomain,
        "domain": domain,
        "suffix": split["suffix"],
        "registered_domain": split["registered_domain"],
    })

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
