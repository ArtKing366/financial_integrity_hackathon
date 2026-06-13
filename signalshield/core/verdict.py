import validators

from core.blacklist import check_blacklist, extract_domain
from core.similarity import check_similarity, load_trusted_brands
from core.whois_check import get_domain_age

VERDICT_DANGEROUS = "DANGEROUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_SAFE = "SAFE"


def analyze_url(url: str) -> dict:
    if not validators.url(url):
        return {
            "verdict": VERDICT_SUSPICIOUS,
            "score": 20,
            "reasons": ["Invalid or malformed URL."],
            "domain": None,
            "domain_age_days": None,
            "similar_to": [],
        }

    domain = extract_domain(url)

    if check_blacklist(domain):
        return {
            "verdict": VERDICT_DANGEROUS,
            "score": 100,
            "reasons": ["Domain is on the CERT Polska blacklist — confirmed phishing."],
            "domain": domain,
            "domain_age_days": None,
            "similar_to": [],
            "details": {"blacklisted": True},
        }

    similarity_results = check_similarity(domain, load_trusted_brands())
    age_days = get_domain_age(domain)

    risk_score = 0
    reasons: list[str] = []

    if similarity_results:
        trusted, ratio = similarity_results[0]
        risk_score += 60
        reasons.append(f"Domain resembles {trusted} ({ratio:.0%} similarity)")

    if age_days is not None:
        if age_days < 14:
            risk_score += 40
            reasons.append("Domain was registered less than 2 weeks ago")
        elif age_days < 90:
            risk_score += 15
            reasons.append("Domain is relatively new")

    if risk_score >= 50:
        verdict = VERDICT_DANGEROUS
    elif risk_score >= 20:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_SAFE

    return {
        "verdict": verdict,
        "score": risk_score,
        "reasons": reasons,
        "domain": domain,
        "domain_age_days": age_days,
        "similar_to": similarity_results,
    }
