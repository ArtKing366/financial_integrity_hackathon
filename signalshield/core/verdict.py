"""Сборка финального вердикта по результатам всех этапов."""

from core.blacklist import check_blacklist, extract_domain
from core.similarity import check_similarity, load_trusted_brands
from core.whois_check import get_domain_age


def analyze_url(url: str) -> dict:
    """Анализирует URL и возвращает итоговый вердикт."""
    domain = extract_domain(url)

    if check_blacklist(domain):
        return {
            "verdict": "ОПАСНО",
            "score": 100,
            "reasons": ["Домен в чёрном списке CERT Polska — подтверждённый фишинг."],
            "domain": domain,
            "domain_age_days": None,
            "similar_to": [],
        }

    similarity_results = check_similarity(domain, load_trusted_brands())
    age_days = get_domain_age(domain)

    risk_score = 0
    reasons: list[str] = []

    if similarity_results:
        trusted, ratio = similarity_results[0]
        risk_score += 60
        reasons.append(f"Домен похож на {trusted} ({ratio:.0%})")

    if age_days is not None:
        if age_days < 14:
            risk_score += 40
            reasons.append("Домен создан менее 2 недель назад")
        elif age_days < 90:
            risk_score += 15
            reasons.append("Домен относительно новый")

    if risk_score >= 50:
        verdict = "ОПАСНО"
    elif risk_score >= 20:
        verdict = "ПОДОЗРИТЕЛЬНО"
    else:
        verdict = "БЕЗОПАСНО"

    return {
        "verdict": verdict,
        "score": risk_score,
        "reasons": reasons,
        "domain": domain,
        "domain_age_days": age_days,
        "similar_to": similarity_results,
    }
