"""Этап 3: проверка схожести домена с доверенными брендами."""

import json
import unicodedata
from pathlib import Path

import Levenshtein

TRUSTED_BRANDS_PATH = Path(__file__).resolve().parent.parent / "data" / "trusted_brands.json"
DEFAULT_THRESHOLD = 0.85


def load_trusted_brands() -> list[str]:
    """Загружает плоский список доверенных доменов из JSON."""
    with TRUSTED_BRANDS_PATH.open(encoding="utf-8") as file:
        data = json.load(file)
    brands: list[str] = []
    for group in data.values():
        brands.extend(group)
    return brands


def normalize_domain(domain: str) -> str:
    """Нормализует unicode-домен для сравнения."""
    nfkd = unicodedata.normalize("NFKD", domain)
    return "".join(char for char in nfkd if not unicodedata.combining(char)).lower()


def check_similarity(
    domain: str,
    trusted_list: list[str],
    threshold: float = DEFAULT_THRESHOLD,
) -> list[tuple[str, float]]:
    """Возвращает список похожих доверенных доменов с коэффициентом схожести."""
    normalized = normalize_domain(domain)
    results: list[tuple[str, float]] = []

    for trusted in trusted_list:
        trusted_normalized = normalize_domain(trusted)
        if normalized == trusted_normalized:
            continue
        ratio = Levenshtein.ratio(normalized, trusted_normalized)
        if ratio >= threshold:
            results.append((trusted, ratio))

    return sorted(results, key=lambda item: -item[1])
