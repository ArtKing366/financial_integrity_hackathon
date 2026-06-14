import json
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path

try:
    import Levenshtein
except Exception:
    Levenshtein = None


TRUSTED_BRANDS_PATH = Path(__file__).resolve().parent.parent / "data" / "trusted_brands.json"
DEFAULT_THRESHOLD = 0.85
MIN_BRAND_LENGTH = 4


def load_trusted_brands() -> list[str]:
    with TRUSTED_BRANDS_PATH.open(encoding="utf-8") as file:
        data = json.load(file)

    brands: list[str] = []
    if isinstance(data, dict):
        for group in data.values():
            if isinstance(group, list):
                brands.extend(group)
    elif isinstance(data, list):
        brands.extend(data)

    return [brand.lower().strip() for brand in brands if brand]


def normalize_domain(domain: str) -> str:
    nfkd = unicodedata.normalize("NFKD", domain)
    return "".join(char for char in nfkd if not unicodedata.combining(char)).lower()


def _ratio(left: str, right: str) -> float:
    if Levenshtein is not None:
        return Levenshtein.ratio(left, right)
    return SequenceMatcher(None, left, right).ratio()


def _brand_token(trusted_domain: str) -> str:
    return trusted_domain.lower().split(".")[0]


def check_similarity(
    domain: str,
    trusted_list: list[str],
    threshold: float = DEFAULT_THRESHOLD,
) -> list[tuple[str, float]]:
    domain_lower = domain.lower()
    normalized = normalize_domain(domain_lower)
    trusted_normalized_map = {
        normalize_domain(trusted.lower()): trusted.lower()
        for trusted in trusted_list
    }

    exact_trusted = trusted_normalized_map.get(normalized)
    if exact_trusted == domain_lower:
        return []

    results: dict[str, float] = {}

    for trusted in trusted_list:
        trusted_lower = trusted.lower()
        trusted_normalized = normalize_domain(trusted_lower)

        if normalized == trusted_normalized:
            if domain_lower != trusted_lower:
                results[trusted] = max(results.get(trusted, 0.0), 1.0)
            continue

        ratio = _ratio(normalized, trusted_normalized)
        if ratio >= threshold:
            results[trusted] = max(results.get(trusted, 0.0), ratio)

        brand = _brand_token(trusted_lower)
        if len(brand) >= MIN_BRAND_LENGTH and brand in normalized:
            results[trusted] = max(results.get(trusted, 0.0), 0.95)

    return sorted(results.items(), key=lambda item: -item[1])
