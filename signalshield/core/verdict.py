from pathlib import Path
from urllib.parse import urlparse
import json


VERDICT_DANGEROUS = "DANGEROUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_SAFE = "SAFE"


# Optional imports — приложение не упадёт, если какой-то модуль ещё не готов
try:
    from core.blacklist import check_blacklist
except Exception:
    check_blacklist = None


try:
    from core.whois_check import get_domain_age
except Exception:
    get_domain_age = None


try:
    from core.similarity import check_similarity
except Exception:
    check_similarity = None


try:
    from core.page_rules import analyze_page_rules
except Exception:
    analyze_page_rules = None


def normalize_url(url: str) -> str:
    """
    Делает URL пригодным для анализа.
    Если пользователь ввёл example.pl, превращаем в https://example.pl
    """
    url = url.strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def extract_hostname(url: str) -> str:
    """
    Извлекает hostname из URL.

    https://example.pl/test -> example.pl
    """
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else ""


def extract_registered_domain(url: str) -> str:
    """
    Возвращает основной домен.

    https://login.example.pl/test -> example.pl

    Если tldextract не установлен, используем простой fallback.
    """
    hostname = extract_hostname(url)

    if not hostname:
        return ""

    try:
        import tldextract

        extracted = tldextract.extract(hostname)

        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"

        return hostname

    except Exception:
        parts = hostname.split(".")

        if len(parts) >= 2:
            return ".".join(parts[-2:])

        return hostname


def load_trusted_brands() -> list[str]:
    """
    Загружает список доверенных доменов из data/trusted_brands.json.

    Поддерживает формат:
    {
      "banks": ["mbank.pl", "ing.pl"],
      "shopping": ["allegro.pl"]
    }
    """
    project_root = Path(__file__).resolve().parents[1]
    trusted_path = project_root / "data" / "trusted_brands.json"

    if not trusted_path.exists():
        return []

    try:
        with trusted_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        trusted_domains = []

        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    trusted_domains.extend(value)

        elif isinstance(data, list):
            trusted_domains = data

        return [domain.lower().strip() for domain in trusted_domains if domain]

    except Exception:
        return []


def run_similarity_check(domain: str) -> list:
    """
    Запускает similarity-модуль.

    Сделано гибко, потому что у check_similarity могут быть разные сигнатуры:
    1. check_similarity(domain, trusted_list)
    2. check_similarity(domain)
    """
    if check_similarity is None:
        return []

    trusted_brands = load_trusted_brands()

    try:
        return check_similarity(domain, trusted_brands)
    except TypeError:
        try:
            return check_similarity(domain)
        except Exception:
            return []
    except Exception:
        return []


def format_similarity_reason(similarity_results: list) -> str:
    """
    Формирует понятную причину для UI.
    """
    if not similarity_results:
        return ""

    best_match = similarity_results[0]

    if isinstance(best_match, tuple) and len(best_match) >= 2:
        trusted_domain = best_match[0]
        ratio = best_match[1]

        try:
            percent = round(float(ratio) * 100)
            return f"Domain is similar to trusted brand {trusted_domain} ({percent}% similarity)."
        except Exception:
            return f"Domain is similar to trusted brand {trusted_domain}."

    if isinstance(best_match, dict):
        trusted_domain = (
            best_match.get("trusted")
            or best_match.get("domain")
            or best_match.get("brand")
            or "trusted brand"
        )

        ratio = best_match.get("ratio") or best_match.get("similarity")

        if ratio is not None:
            try:
                percent = round(float(ratio) * 100)
                return f"Domain is similar to trusted brand {trusted_domain} ({percent}% similarity)."
            except Exception:
                pass

        return f"Domain is similar to trusted brand {trusted_domain}."

    return f"Domain is similar to a trusted brand: {best_match}."


def analyze_url(url: str) -> dict:
    """
    Главная функция анализа URL.

    Она возвращает словарь, который ожидает app.py:

    {
        "verdict": "...",
        "score": 0-100,
        "reasons": [...],
        "details": {...}
    }
    """
    url = normalize_url(url)
    hostname = extract_hostname(url)
    domain = extract_registered_domain(url)

    risk_score = 0
    reasons = []

    details = {
        "input_url": url,
        "hostname": hostname,
        "domain": domain,
        "blacklist_match": False,
        "domain_age_days": None,
        "similarity_results": [],
    }

    if not url or not hostname:
        return {
            "verdict": VERDICT_SUSPICIOUS,
            "score": 20,
            "reasons": ["Invalid or empty URL."],
            "details": details,
        }

    # ============================================================
    # Stage 1: CERT Polska blacklist
    # ============================================================

    if check_blacklist is not None:
        try:
            is_blacklisted = check_blacklist(url)
        except Exception:
            try:
                is_blacklisted = check_blacklist(domain)
            except Exception:
                is_blacklisted = False

        details["blacklist_match"] = is_blacklisted

        if is_blacklisted:
            return {
                "verdict": VERDICT_DANGEROUS,
                "score": 100,
                "reasons": [
                    "Domain is listed in CERT Polska blacklist — confirmed phishing."
                ],
                "details": details,
            }
    else:
        details["blacklist_status"] = "Blacklist module is not available."

    # ============================================================
    # Stage 2: WHOIS domain age
    # ============================================================

    if get_domain_age is not None:
        try:
            age_days = get_domain_age(domain)
        except Exception:
            age_days = None

        details["domain_age_days"] = age_days

        if age_days is None:
            details["whois_status"] = "Domain age could not be determined."
        elif age_days < 14:
            risk_score += 40
            reasons.append("Domain was created less than 14 days ago.")
        elif age_days < 90:
            risk_score += 15
            reasons.append("Domain is relatively new — less than 90 days old.")
    else:
        details["whois_status"] = "WHOIS module is not available."

    # ============================================================
    # Stage 3: Levenshtein similarity / typosquatting
    # ============================================================

    similarity_results = run_similarity_check(domain)
    details["similarity_results"] = similarity_results

    if similarity_results:
        risk_score += 60
        reason = format_similarity_reason(similarity_results)

        if reason:
            reasons.append(reason)
        else:
            reasons.append("Domain is similar to a trusted brand.")

    # ============================================================
    # Optional Stage 4: Page content rules
    # Если core/page_rules.py существует, подключаем его автоматически.
    # Если нет — приложение всё равно работает.
    # ============================================================

    if analyze_page_rules is not None:
        try:
            page_result = analyze_page_rules(url)
        except Exception as error:
            page_result = {
                "score": 0,
                "hard_block": False,
                "matched_rules": [],
                "fetch_error": str(error),
            }

        details["page_rules"] = page_result

        page_score = int(page_result.get("score", 0) or 0)
        risk_score += page_score

        for rule in page_result.get("matched_rules", []):
            severity = rule.get("severity", "")
            description = rule.get("description", "")

            if severity in ["critical", "high", "medium"] and description:
                reasons.append(description)

        if page_result.get("hard_block"):
            risk_score = max(risk_score, 80)

    # ============================================================
    # Final verdict
    # ============================================================

    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        verdict = VERDICT_DANGEROUS
    elif risk_score >= 20:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_SAFE

    if not reasons:
        reasons.append("No strong phishing indicators were detected.")

    return {
        "verdict": verdict,
        "score": risk_score,
        "reasons": reasons,
        "details": details,
    }