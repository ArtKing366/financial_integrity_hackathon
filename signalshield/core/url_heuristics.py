import re
import unicodedata
from urllib.parse import unquote, urlparse

from core.domain_utils import extract_registered_domain, normalize_url, split_domain


PATH_KEYWORDS = {
    "blik",
    "platnosc",
    "payment",
    "pay",
    "logowanie",
    "login",
    "secure",
    "bezpieczny",
    "weryfikacja",
    "verify",
    "konto",
    "paczka",
}

PATH_BRAND_REFERENCE_SCORE = 30
PATH_KEYWORD_SCORE = 20
UGLY_DOMAIN_SCORE = 20
VERY_UGLY_DOMAIN_SCORE = 30
MAX_RULE_SCORE = 45


def normalize_text(value: str) -> str:
    value = unquote(value).lower()
    nfkd = unicodedata.normalize("NFKD", value)
    return "".join(char for char in nfkd if not unicodedata.combining(char))


def _brand_tokens(trusted_domains: list[str]) -> set[str]:
    tokens = set()

    for trusted_domain in trusted_domains:
        split = split_domain(trusted_domain)
        registered_domain = split["registered_domain"]
        domain = split["domain"]

        if registered_domain:
            tokens.add(registered_domain)
        if domain and len(domain) >= 3:
            tokens.add(domain)

    return tokens


def _matches_brand_token(path_tail: str, token: str) -> bool:
    if "." in token:
        return token in path_tail
    return re.search(rf"\b{re.escape(token)}\b", path_tail) is not None


def _path_tail(url: str) -> str:
    parsed = urlparse(url)
    return normalize_text(f"{parsed.path} {parsed.params} {parsed.query} {parsed.fragment}")


def _is_trusted_domain(registered_domain: str, trusted_domains: list[str]) -> bool:
    trusted_set = {domain.lower().strip() for domain in trusted_domains if domain}
    return registered_domain.lower() in trusted_set


def check_path_keywords(url: str, trusted_domains: list[str]) -> dict:
    url = normalize_url(url)
    registered_domain = extract_registered_domain(url)
    path_tail = _path_tail(url)

    result = {
        "id": "path_keywords",
        "score": 0,
        "matched_keywords": [],
        "matched_brands": [],
        "description": "",
    }

    if not path_tail or _is_trusted_domain(registered_domain, trusted_domains):
        return result

    matched_keywords = sorted(
        keyword for keyword in PATH_KEYWORDS if re.search(rf"\b{re.escape(keyword)}\b", path_tail)
    )
    matched_brands = sorted(
        token for token in _brand_tokens(trusted_domains) if token and _matches_brand_token(path_tail, token)
    )

    if matched_brands:
        result["score"] += PATH_BRAND_REFERENCE_SCORE
        result["matched_brands"] = matched_brands

    if matched_keywords:
        result["score"] += PATH_KEYWORD_SCORE
        result["matched_keywords"] = matched_keywords

    if result["score"]:
        result["score"] = min(result["score"], MAX_RULE_SCORE)
        result["description"] = (
            "URL path contains payment, login, or brand-like keywords while "
            f"the registered domain is not trusted ({registered_domain})."
        )

    return result


def check_domain_ugliness(url_or_domain: str) -> dict:
    split = split_domain(url_or_domain)
    domain = split["domain"]
    registered_domain = split["registered_domain"]
    hyphen_count = domain.count("-")
    domain_length = len(domain)

    result = {
        "id": "domain_ugliness",
        "score": 0,
        "hyphen_count": hyphen_count,
        "domain_length": domain_length,
        "description": "",
    }

    if not domain:
        return result

    if hyphen_count >= 4 or domain_length >= 30:
        result["score"] = VERY_UGLY_DOMAIN_SCORE
    elif hyphen_count >= 3 or domain_length >= 25:
        result["score"] = UGLY_DOMAIN_SCORE

    if result["score"]:
        result["description"] = (
            f"Registered domain {registered_domain} is unusually long or overloaded "
            f"with hyphens ({domain_length} characters, {hyphen_count} hyphens)."
        )

    return result


def analyze_url_heuristics(url: str, trusted_domains: list[str]) -> dict:
    rules = [
        check_path_keywords(url, trusted_domains),
        check_domain_ugliness(url),
    ]
    matched_rules = [rule for rule in rules if rule["score"] > 0]

    return {
        "score": min(sum(rule["score"] for rule in matched_rules), 100),
        "matched_rules": matched_rules,
    }
