import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

from core.domain_utils import extract_hostname, extract_registered_domain, normalize_url
from core.market_manipulation import detect_market_manipulation
from core.verdict import (
    VERDICT_DANGEROUS,
    VERDICT_NOT_FOUND,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    analyze_url,
    new_analysis_context,
)


TRAILING_URL_PUNCTUATION = ".,;:!?)]}>'\""

SCHEME_URL_RE = re.compile(r"\bhttps?://[^\s<>()\"']+", flags=re.IGNORECASE)
WWW_URL_RE = re.compile(r"\bwww\.[^\s<>()\"']+", flags=re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])"
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,}(?:/[^\s<>()\"']*)?)",
    flags=re.IGNORECASE,
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "cutt.ly",
    "rebrand.ly",
    "is.gd",
    "buff.ly",
    "tiny.cc",
    "shorturl.at",
    "lnkd.in",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "icu",
    "monster",
    "quest",
    "shop",
    "support",
    "rest",
    "cam",
}

POLISH_CHAR_MAP = str.maketrans(
    "\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017c\u017a",
    "acelnoszz",
)

MESSAGE_RULES = [
    {
        "id": "urgency_or_account_threat",
        "score": 10,
        "terms": [
            "pilne",
            "natychmiast",
            "dzisiaj",
            "wygasa",
            "zablokowane",
            "blokada",
            "ostatnia szansa",
            "ograniczone",
            "urgent",
        ],
        "description": "Message uses urgency, deadline, or account-blocking pressure.",
    },
    {
        "id": "payment_or_delivery_context",
        "score": 10,
        "terms": [
            "blik",
            "platnosc",
            "doplata",
            "oplata",
            "przelew",
            "paczka",
            "kurier",
            "faktura",
        ],
        "description": "Message mentions payment, BLIK, transfer, invoice, or delivery context.",
    },
    {
        "id": "sensitive_data_request",
        "score": 20,
        "terms": [
            "haslo",
            "pin",
            "pesel",
            "kod sms",
            "kod blik",
            "dane karty",
            "cvv",
            "login",
        ],
        "description": "Message asks for or references sensitive credentials or verification codes.",
    },
    {
        "id": "remote_access_request",
        "score": 35,
        "terms": [
            "anydesk",
            "teamviewer",
            "quicksupport",
            "pulpit zdalny",
            "zdalny dostep",
            "zainstaluj aplikacje",
        ],
        "description": "Message asks the user to install or use remote access software.",
    },
]

def normalize_text(value: str) -> str:
    value = value.lower()
    nfkd = unicodedata.normalize("NFKD", value)
    value = "".join(char for char in nfkd if not unicodedata.combining(char))
    return value.translate(POLISH_CHAR_MAP)


def _clean_url(value: str) -> str:
    return value.strip().rstrip(TRAILING_URL_PUNCTUATION)


def _overlaps(span: tuple[int, int], spans: list[tuple[int, int]]) -> bool:
    start, end = span
    return any(start < existing_end and end > existing_start for existing_start, existing_end in spans)


def extract_links(message: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    spans: list[tuple[int, int]] = []
    seen = set()

    for pattern in (SCHEME_URL_RE, WWW_URL_RE):
        for match in pattern.finditer(message):
            original = _clean_url(match.group(0))
            normalized = normalize_url(original)
            key = normalized.lower()

            if key in seen:
                continue

            found.append({"original": original, "url": normalized})
            spans.append(match.span())
            seen.add(key)

    for match in BARE_DOMAIN_RE.finditer(message):
        if _overlaps(match.span(), spans):
            continue

        original = _clean_url(match.group(1))
        normalized = normalize_url(original)
        key = normalized.lower()

        if key in seen:
            continue

        found.append({"original": original, "url": normalized})
        spans.append(match.span())
        seen.add(key)

    return found


def _is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def characterize_link(url: str) -> dict:
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = extract_hostname(url)
    registered_domain = extract_registered_domain(url)
    tld = registered_domain.rsplit(".", 1)[-1] if "." in registered_domain else ""

    rules = []

    def add_rule(rule_id: str, score: int, description: str) -> None:
        rules.append({
            "id": rule_id,
            "score": score,
            "description": description,
        })

    if parsed.scheme != "https":
        add_rule("plain_http", 10, "Link does not use HTTPS.")

    if "@" in parsed.netloc:
        add_rule("userinfo_trick", 30, "Link contains '@' in the host part, which can hide the real domain.")

    if _is_ip_hostname(hostname):
        add_rule("ip_address_host", 25, "Link uses a raw IP address instead of a domain name.")

    if registered_domain in SHORTENER_DOMAINS:
        add_rule("link_shortener", 15, "Link uses a URL shortener, hiding the final destination.")

    if tld in SUSPICIOUS_TLDS:
        add_rule("suspicious_tld", 10, f"Link uses a commonly abused TLD: .{tld}.")

    if len(url) >= 120:
        add_rule("very_long_url", 10, "Link is unusually long.")

    if hostname.count(".") >= 3:
        add_rule("many_subdomains", 10, "Link has many subdomain levels.")

    score = min(sum(rule["score"] for rule in rules), 35)

    return {
        "url": url,
        "hostname": hostname,
        "registered_domain": registered_domain,
        "uses_https": parsed.scheme == "https",
        "is_shortener": registered_domain in SHORTENER_DOMAINS,
        "is_ip_host": _is_ip_hostname(hostname),
        "has_userinfo_trick": "@" in parsed.netloc,
        "tld": tld,
        "score": score,
        "matched_rules": rules,
    }


def analyze_message_signals(message: str) -> dict:
    normalized = normalize_text(message)
    matched_rules = []

    for rule in MESSAGE_RULES:
        matches = sorted(term for term in rule["terms"] if term in normalized)

        if not matches:
            continue

        matched_rules.append({
            "id": rule["id"],
            "score": rule["score"],
            "description": rule["description"],
            "matches": matches,
        })

    return {
        "score": min(sum(rule["score"] for rule in matched_rules), 60),
        "matched_rules": matched_rules,
    }


def _message_verdict(
    score: int,
    has_only_not_found_links: bool,
    market_status: str = "SAFE",
    non_market_score: int = 0,
) -> str:
    if market_status == "MARKET_MANIPULATION_RISK":
        return VERDICT_DANGEROUS
    if score >= 70 or non_market_score >= 50:
        return VERDICT_DANGEROUS
    if market_status == "SUSPICIOUS" or score >= 20:
        return VERDICT_SUSPICIOUS
    if has_only_not_found_links:
        return VERDICT_NOT_FOUND
    return VERDICT_SAFE


def analyze_message(message: str, context: dict | None = None) -> dict:
    message = message.strip()

    if not message:
        return {
            "verdict": VERDICT_NOT_FOUND,
            "score": 0,
            "reasons": ["Message is empty."],
            "links": [],
            "message_signals": {"score": 0, "matched_rules": []},
            "details": {"message_length": 0, "link_count": 0, "unique_domains": []},
        }

    extracted_links = extract_links(message)
    analyzed_links = []
    context = context or new_analysis_context()

    for link in extracted_links:
        characteristics = characterize_link(link["url"])

        try:
            link_result = analyze_url(link["url"], context=context)
        except Exception as error:
            link_result = {
                "verdict": VERDICT_NOT_FOUND,
                "score": 0,
                "reasons": [f"Link analysis failed: {error}"],
                "details": {"input_url": link["url"]},
            }

        analyzed_links.append({
            "original": link["original"],
            "url": link["url"],
            "characteristics": characteristics,
            "analysis": link_result,
            "verdict": link_result.get("verdict", VERDICT_NOT_FOUND),
            "score": int(link_result.get("score", 0) or 0),
            "reasons": link_result.get("reasons", []),
        })

    message_signals = analyze_message_signals(message)
    market_manipulation = detect_market_manipulation(message)
    market_score = int(market_manipulation.get("score", 0) or 0)
    link_characteristic_score = min(
        sum(link["characteristics"]["score"] for link in analyzed_links),
        35,
    )
    max_link_score = max((link["score"] for link in analyzed_links), default=0)
    non_market_score = max_link_score + message_signals["score"] + link_characteristic_score
    total_score = min(non_market_score + market_score, 100)

    has_links = bool(analyzed_links)
    has_only_not_found_links = has_links and all(
        link["verdict"] == VERDICT_NOT_FOUND for link in analyzed_links
    )
    verdict = _message_verdict(
        total_score,
        has_only_not_found_links,
        market_manipulation.get("status", "SAFE"),
        non_market_score,
    )

    reasons = []

    for rule in message_signals["matched_rules"]:
        reasons.append(rule["description"])

    if market_manipulation.get("matched_rules"):
        reasons.extend(market_manipulation.get("reasons", []))

    for link in analyzed_links:
        if link["verdict"] in {VERDICT_DANGEROUS, VERDICT_SUSPICIOUS}:
            reasons.append(
                f"Link {link['url']} was classified as {link['verdict']} "
                f"(risk: {link['score']}%)."
            )

        for rule in link["characteristics"]["matched_rules"]:
            reasons.append(f"Link {link['url']}: {rule['description']}")

    if not reasons:
        if analyzed_links:
            reasons.append("No strong phishing indicators were detected in the message or its links.")
        else:
            reasons.append("No links or strong financial scam indicators were detected.")

    unique_domains = sorted({
        link["characteristics"]["registered_domain"]
        for link in analyzed_links
        if link["characteristics"]["registered_domain"]
    })

    return {
        "verdict": verdict,
        "score": total_score,
        "reasons": reasons,
        "links": analyzed_links,
        "message_signals": message_signals,
        "market_manipulation": market_manipulation,
        "details": {
            "message_length": len(message),
            "link_count": len(analyzed_links),
            "unique_domains": unique_domains,
            "max_link_score": max_link_score,
            "message_signal_score": message_signals["score"],
            "market_manipulation_score": market_score,
            "link_characteristic_score": link_characteristic_score,
        },
    }
