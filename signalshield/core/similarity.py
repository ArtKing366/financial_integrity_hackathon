import json
import unicodedata
from pathlib import Path

import Levenshtein

TRUSTED_BRANDS_PATH = Path(__file__).resolve().parent.parent / "data" / "trusted_brands.json"
DEFAULT_THRESHOLD = 0.85
MIN_BRAND_LENGTH = 4


def load_trusted_brands() -> list[str]:
    with TRUSTED_BRANDS_PATH.open(encoding="utf-8") as file:
        data = json.load(file)
    brands: list[str] = []
    for group in data.values():
        brands.extend(group)
    return brands


def normalize_domain(domain: str) -> str:
    nfkd = unicodedata.normalize("NFKD", domain)
    return "".join(char for char in nfkd if not unicodedata.combining(char)).lower()


def _brand_token(trusted_domain: str) -> str:
    return trusted_domain.lower().split(".")[0]


def check_similarity(
    domain: str,
    trusted_list: list[str],
    threshold: float = DEFAULT_THRESHOLD,
) -> list[tuple[str, float]]:
    normalized = normalize_domain(domain.lower())
    results: dict[str, float] = {}

    for trusted in trusted_list:
        trusted_lower = trusted.lower()
        trusted_normalized = normalize_domain(trusted_lower)

        if normalized == trusted_normalized:
            if domain.lower() != trusted_lower:
                results[trusted] = max(results.get(trusted, 0.0), 1.0)
            continue

        ratio = Levenshtein.ratio(normalized, trusted_normalized)
        if ratio >= threshold:
            results[trusted] = max(results.get(trusted, 0.0), ratio)

        brand = _brand_token(trusted_lower)
        if len(brand) >= MIN_BRAND_LENGTH and brand in normalized:
            results[trusted] = max(results.get(trusted, 0.0), 0.95)

    return sorted(results.items(), key=lambda item: -item[1])
