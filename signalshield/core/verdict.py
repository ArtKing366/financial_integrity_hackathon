import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from core.analysis_cache import TtlCache
from core.domain_utils import extract_hostname, extract_registered_domain, normalize_url


VERDICT_DANGEROUS = "DANGEROUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_SAFE = "SAFE"
VERDICT_NOT_FOUND = "NOT_FOUND"
VERDICT_TRUSTED_BY_USER = "TRUSTED_BY_USER"
DNS_INFRASTRUCTURE_TTL_SECONDS = 10 * 60
DOMAIN_AGE_TTL_SECONDS = 30 * 60
PAGE_EXISTENCE_TTL_SECONDS = 90
HTML_FETCH_TTL_SECONDS = 60


try:
    from core.local_db import LIST_BLACKLIST, LIST_TRUSTED, SOURCE_USER, find_list_match
except Exception:
    LIST_BLACKLIST = "blacklist"
    LIST_TRUSTED = "trusted"
    SOURCE_USER = "user"
    find_list_match = None


try:
    from core.blacklist import check_blacklist
except Exception:
    check_blacklist = None

try:
    from core.subdomain_spoofing import check_subdomain_spoofing
except Exception:
    check_subdomain_spoofing = None

try:
    from core.page_existence import check_page_existence
except Exception:
    check_page_existence = None

try:
    from core.dns_infrastructure import analyze_dns_infrastructure
except Exception:
    analyze_dns_infrastructure = None

try:
    from core.whois_check import get_domain_age
except Exception:
    get_domain_age = None

try:
    from core.similarity import check_similarity
except Exception:
    check_similarity = None

try:
    from core.page_rules import analyze_page_rules, fetch_page as fetch_page_for_rules
except Exception:
    analyze_page_rules = None
    fetch_page_for_rules = None

try:
    from core.html_crawler import analyze_html_crawling, fetch_html as fetch_html_for_crawler
except Exception:
    analyze_html_crawling = None
    fetch_html_for_crawler = None

try:
    from core.url_heuristics import analyze_url_heuristics
except Exception:
    analyze_url_heuristics = None

try:
    from core.entropy import check_domain_entropy
except Exception:
    check_domain_entropy = None

@lru_cache(maxsize=1)
def load_trusted_brands() -> list[str]:
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


def new_analysis_context(shared_cache: TtlCache | None = None) -> dict[str, Any]:
    return {
        "trusted_brands": load_trusted_brands(),
        "cache": {},
        "shared_cache": shared_cache,
    }


def cache_get(
    context: dict[str, Any],
    cache_name: str,
    key: str,
    factory: Callable[[], Any],
    ttl_seconds: int | None = None,
) -> Any:
    cache = context.setdefault("cache", {}).setdefault(cache_name, {})

    if key in cache:
        return cache[key]

    shared_cache = context.get("shared_cache")

    if ttl_seconds is not None and shared_cache is not None:
        value = shared_cache.get_or_set(cache_name, key, ttl_seconds, factory)
    else:
        value = factory()

    cache[key] = value
    return value


def run_similarity_check(domain: str, trusted_brands: list[str] | None = None) -> list:
    if check_similarity is None:
        return []

    trusted_brands = trusted_brands if trusted_brands is not None else load_trusted_brands()

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


def fetch_html_for_content_rules(url: str, context: dict[str, Any]) -> tuple[str | None, str | None]:
    fetcher = fetch_page_for_rules or fetch_html_for_crawler

    if fetcher is None:
        return None, "Page fetch module is not available."

    return cache_get(
        context,
        "html_fetch",
        url,
        lambda: fetcher(url),
        ttl_seconds=HTML_FETCH_TTL_SECONDS,
    )


def call_html_crawling(
    url: str,
    trusted_brands: list[str],
    html: str | None,
    fetch_error: str | None,
) -> dict:
    try:
        return analyze_html_crawling(
            url,
            trusted_brands,
            html=html,
            fetch_error=fetch_error,
        )
    except TypeError:
        return analyze_html_crawling(url, trusted_brands)


def call_page_rules(
    url: str,
    html: str | None,
    fetch_error: str | None,
) -> dict:
    try:
        return analyze_page_rules(url, html=html, fetch_error=fetch_error)
    except TypeError:
        return analyze_page_rules(url)


def _details(url: str, hostname: str, domain: str) -> dict:
    return {
        "input_url": url,
        "hostname": hostname,
        "domain": domain,
        "local_list_match": None,
        "original_verdict": None,
        "blacklist_match": False,
        "subdomain_spoofing": None,
        "page_existence": None,
        "dns_infrastructure": None,
        "domain_age_days": None,
        "html_crawling": None,
        "similarity_results": [],
        "url_heuristics": None,
        "domain_entropy": None,
    }


def analyze_url(url: str, context: dict[str, Any] | None = None) -> dict:
    context = context or new_analysis_context()
    trusted_brands = context["trusted_brands"]
    url = normalize_url(url)
    hostname = extract_hostname(url)
    domain = extract_registered_domain(url)
    details = _details(url, hostname, domain)

    if not url or not hostname:
        return {
            "verdict": VERDICT_NOT_FOUND,
            "score": 0,
            "reasons": ["URL is empty or invalid."],
            "details": details,
        }

    risk_score = 0
    reasons = []
    not_found_reasons = []
    trusted_match = None

    if find_list_match is not None:
        try:
            local_match = find_list_match(url)
        except Exception:
            local_match = None

        details["local_list_match"] = local_match

        if local_match and local_match.get("list_type") == LIST_BLACKLIST:
            blacklist_reason = "URL or domain is on the local SignalShield blacklist."

            if local_match.get("source") == "cert_polska":
                blacklist_reason = "Domain is listed in CERT Polska blacklist - confirmed phishing."

            return {
                "verdict": VERDICT_DANGEROUS,
                "score": 100,
                "reasons": [blacklist_reason],
                "details": details,
            }

        if (
            local_match
            and local_match.get("list_type") == LIST_TRUSTED
            and local_match.get("source", SOURCE_USER) == SOURCE_USER
        ):
            trusted_match = local_match
        elif local_match and local_match.get("list_type") == LIST_TRUSTED:
            details["system_trusted_match"] = local_match

    if check_blacklist is not None and trusted_match is None:
        try:
            is_blacklisted = cache_get(
                context,
                "blacklist",
                domain or url,
                lambda: check_blacklist(url),
            )
        except Exception:
            is_blacklisted = False

        details["blacklist_match"] = is_blacklisted

        if is_blacklisted:
            return {
                "verdict": VERDICT_DANGEROUS,
                "score": 100,
                "reasons": [
                    "Domain is listed in CERT Polska blacklist - confirmed phishing."
                ],
                "details": details,
            }
    else:
        if trusted_match is not None:
            details["blacklist_status"] = "Skipped because the user trusted this exact target."
        else:
            details["blacklist_status"] = "Blacklist module is not available."

    if check_subdomain_spoofing is not None:
        try:
            subdomain_result = cache_get(
                context,
                "subdomain_spoofing",
                hostname,
                lambda: check_subdomain_spoofing(url),
            )
        except Exception as error:
            subdomain_result = {"is_spoofed": False, "error": str(error)}

        details["subdomain_spoofing"] = subdomain_result

        if subdomain_result.get("is_spoofed"):
            risk_score += 80
            matched_brands = ", ".join(subdomain_result.get("matched_brands", []))
            reasons.append(
                f"Brand name detected in subdomain ({matched_brands}), "
                f"but the real registered domain is {subdomain_result.get('registered_domain')}."
            )
    else:
        details["subdomain_spoofing"] = "Subdomain spoofing module is not available."

    if check_page_existence is not None:
        try:
            existence_result = cache_get(
                context,
                "page_existence",
                url,
                lambda: check_page_existence(url),
                ttl_seconds=PAGE_EXISTENCE_TTL_SECONDS,
            )
        except Exception as error:
            existence_result = {
                "status": "unknown",
                "exists": None,
                "evidence": ["Page existence check failed because of an internal error."],
                "error": str(error),
            }

        details["page_existence"] = existence_result
        existence_status = existence_result.get("status")

        if existence_status in {"domain_not_found", "not_found"}:
            not_found_reasons.append("The page or domain does not appear to exist.")
            not_found_reasons.extend(existence_result.get("evidence", []))
        elif existence_status == "unreachable":
            risk_score += 10
            reasons.extend(existence_result.get("evidence", []))
    else:
        details["page_existence"] = "Page existence module is not available."

    if analyze_dns_infrastructure is not None:
        try:
            dns_result = cache_get(
                context,
                "dns_infrastructure",
                domain or hostname or url,
                lambda: analyze_dns_infrastructure(domain, trusted_brands),
                ttl_seconds=DNS_INFRASTRUCTURE_TTL_SECONDS,
            )
        except Exception as error:
            dns_result = {
                "score": 0,
                "status": "error",
                "description": "",
                "error": str(error),
            }

        details["dns_infrastructure"] = dns_result
        risk_score += int(dns_result.get("score", 0) or 0)

        description = dns_result.get("description", "")
        if description and dns_result.get("score", 0) > 0:
            reasons.append(description)
    else:
        details["dns_infrastructure"] = "DNS infrastructure module is not available."

    if get_domain_age is not None:
        try:
            age_days = cache_get(
                context,
                "domain_age",
                domain or hostname or url,
                lambda: get_domain_age(domain),
                ttl_seconds=DOMAIN_AGE_TTL_SECONDS,
            )
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
            reasons.append("Domain is relatively new - less than 90 days old.")
    else:
        details["whois_status"] = "WHOIS module is not available."

    if check_domain_entropy is not None:
        try:
            entropy_result = cache_get(
                context,
                "domain_entropy",
                domain,
                lambda: check_domain_entropy(url),
            )
        except Exception as error:
            entropy_result = {
                "flagged": False,
                "score": 0,
                "error": str(error),
            }

        details["domain_entropy"] = entropy_result
        risk_score += int(entropy_result.get("score", 0) or 0)

        if entropy_result.get("description"):
            reasons.append(entropy_result["description"])
    else:
        details["domain_entropy"] = "Domain entropy module is not available."

    content_html = None
    content_fetch_error = None

    if (
        (analyze_html_crawling is not None or analyze_page_rules is not None)
        and not_found_reasons
        and details.get("page_existence", {}).get("status") == "domain_not_found"
    ):
        content_fetch_error = "Skipped page content checks because DNS lookup failed."
    elif analyze_html_crawling is not None or analyze_page_rules is not None:
        content_html, content_fetch_error = fetch_html_for_content_rules(url, context)

    if analyze_html_crawling is not None:
        try:
            html_result = cache_get(
                context,
                "html_crawling",
                url,
                lambda: call_html_crawling(
                    url,
                    trusted_brands,
                    content_html,
                    content_fetch_error,
                ),
            )
        except Exception as error:
            html_result = {
                "score": 0,
                "matched_rules": [],
                "fetch_error": str(error),
            }

        details["html_crawling"] = html_result
        risk_score += int(html_result.get("score", 0) or 0)

        for rule in html_result.get("matched_rules", []):
            description = rule.get("description", "")
            if description:
                reasons.append(description)
    else:
        details["html_crawling"] = "HTML crawler module is not available."

    if analyze_url_heuristics is not None:
        try:
            heuristic_result = cache_get(
                context,
                "url_heuristics",
                url,
                lambda: analyze_url_heuristics(url, trusted_brands),
            )
        except Exception as error:
            heuristic_result = {
                "score": 0,
                "matched_rules": [],
                "error": str(error),
            }

        details["url_heuristics"] = heuristic_result
        risk_score += int(heuristic_result.get("score", 0) or 0)

        for rule in heuristic_result.get("matched_rules", []):
            description = rule.get("description", "")
            if description:
                reasons.append(description)
    else:
        details["url_heuristics"] = "URL heuristic module is not available."

    similarity_results = cache_get(
        context,
        "similarity",
        domain,
        lambda: run_similarity_check(domain, trusted_brands),
    )
    details["similarity_results"] = similarity_results

    if similarity_results:
        risk_score += 60
        reason = format_similarity_reason(similarity_results)
        reasons.append(reason or "Domain is similar to a trusted brand.")

    if analyze_page_rules is not None:
        try:
            page_result = cache_get(
                context,
                "page_rules",
                url,
                lambda: call_page_rules(url, content_html, content_fetch_error),
            )
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

            if severity in {"critical", "high", "medium"} and description:
                reasons.append(description)

        if page_result.get("hard_block"):
            risk_score = max(risk_score, 80)

    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        verdict = VERDICT_DANGEROUS
    elif risk_score >= 20:
        verdict = VERDICT_SUSPICIOUS
    elif not_found_reasons:
        verdict = VERDICT_NOT_FOUND
    else:
        verdict = VERDICT_SAFE

    if not reasons:
        if not_found_reasons:
            reasons.extend(not_found_reasons)
        else:
            reasons.append("No strong phishing indicators were detected.")
    elif not_found_reasons:
        details["not_found_evidence"] = not_found_reasons

    result = {
        "verdict": verdict,
        "score": risk_score,
        "reasons": reasons,
        "details": details,
    }

    if trusted_match:
        details["original_verdict"] = verdict
        result["verdict"] = VERDICT_TRUSTED_BY_USER
        result["reasons"] = [
            (
                "User trusted list matched "
                f"{trusted_match.get('scope')} {trusted_match.get('value')}."
            ),
            f"Original analyzer verdict was {verdict} with {risk_score}% risk.",
            *reasons,
        ]

    return result
