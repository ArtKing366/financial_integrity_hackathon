import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

from core.domain_utils import extract_hostname, extract_registered_domain, normalize_url
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

POLISH_CHAR_MAP = str.maketrans({
    "ą": "a",
    "ć": "c",
    "ę": "e",
    "ł": "l",
    "ń": "n",
    "ó": "o",
    "ś": "s",
    "ż": "z",
    "ź": "z",
})

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
    {
        "id": "investment_manipulation_language",
        "score": 15,
        "terms": [
            "gwarantowany zysk",
            "bez ryzyka",
            "krypto",
            "crypto",
            "inwestycja",
            "pomnoz",
            "zarobek",
            "okazja inwestycyjna",
        ],
        "description": "Message contains investment-scam or market-manipulation language.",
    },
]
MARKET_MANIPULATION_RULES = [
    {
        "id": "guaranteed_or_risk_free_profit",
        "score": 25,
        "patterns": [
            r"gwarantowan[yae]?\s+zysk",
            r"pewny\s+zysk",
            r"bez\s+ryzyka",
            r"risk[-\s]?free",
            r"guaranteed\s+profit",
            r"gwarancja\s+zysku",
            r"100%\s+pewne",
            r"gwarantowany\s+zarobek",
        ],
        "description": "Message promises guaranteed or risk-free investment profit.",
    },
    {
        "id": "unrealistic_returns",
        "score": 25,
        "patterns": [
            r"\b\d{2,4}\s?%\b",
            r"\b\d+x\b",
            r"\bx\d+\b",
            r"10x",
            r"100x",
            r"1000x",
            r"to\s+the\s+moon",
            r"moonshot",
            r"rakieta",
            r"wystrzeli",
            r"eksplozja\s+ceny",
        ],
        "description": "Message promises unrealistic returns or extreme price growth.",
    },
    {
        "id": "investment_time_pressure",
        "score": 20,
        "patterns": [
            r"kup\s+teraz",
            r"buy\s+now",
            r"wchodzimy\s+teraz",
            r"ostatnia\s+szansa",
            r"last\s+chance",
            r"tylko\s+dzisiaj",
            r"teraz\s+albo\s+nigdy",
            r"w\s+ciagu\s+\d+\s*(minut|godzin|h)",
            r"za\s+\d+\s*(minut|godzin|h)",
        ],
        "description": "Message uses time pressure to force a quick investment decision.",
    },
    {
        "id": "pump_or_coordination_language",
        "score": 30,
        "patterns": [
            r"\bpump\b",
            r"pumpujemy",
            r"pompujemy",
            r"pompka",
            r"wszyscy\s+kupujemy",
            r"wchodzimy\s+razem",
            r"grupa\s+sygnalowa",
            r"signal\s+group",
            r"vip\s+group",
            r"grupa\s+vip",
            r"telegram",
            r"discord",
            r"zamknieta\s+grupa",
            r"private\s+group",
        ],
        "description": "Message suggests coordinated buying, pump activity, or signal-group manipulation.",
    },
    {
        "id": "inside_or_secret_information",
        "score": 35,
        "patterns": [
            r"inside\s+info",
            r"insider",
            r"tajna\s+informacja",
            r"poufna\s+informacja",
            r"niepubliczna\s+informacja",
            r"wiemy\s+cos",
            r"informacja\s+tylko\s+dla\s+wybranych",
            r"sekretny\s+sygnal",
        ],
        "description": "Message claims to rely on secret, insider, or non-public information.",
    },
    {
        "id": "direct_trading_instruction",
        "score": 20,
        "patterns": [
            r"kupuj",
            r"kup\s+teraz",
            r"sprzedaj",
            r"sell\s+now",
            r"buy\s+signal",
            r"sygnal\s+kupna",
            r"otwieramy\s+pozycje",
            r"wejscie\s+na\s+pozycje",
            r"\bentry\b",
            r"\blong\b",
            r"\bshort\b",
            r"take\s+profit",
            r"\btp\s*[:=]?\s*\d",
            r"\bsl\s*[:=]?\s*\d",
        ],
        "description": "Message gives direct trading instructions or buy/sell signals.",
    },
    {
        "id": "low_liquidity_or_easy_to_manipulate_asset",
        "score": 15,
        "patterns": [
            r"low\s+cap",
            r"niska\s+kapitalizacja",
            r"penny\s+stock",
            r"meme\s+coin",
            r"shitcoin",
            r"mala\s+spolka",
            r"small\s+cap",
            r"nowy\s+token",
            r"nowa\s+moneta",
        ],
        "description": "Message refers to low-liquidity assets often used in manipulation schemes.",
    },
    {
        "id": "financial_market_context",
        "score": 10,
        "patterns": [
            r"\bakcje\b",
            r"\bstock\b",
            r"\bshares\b",
            r"\bkrypto\b",
            r"\bcrypto\b",
            r"\btoken\b",
            r"\bcoin\b",
            r"\bforex\b",
            r"\bgielda\b",
            r"\btrading\b",
            r"\bexchange\b",
            r"\bbroker\b",
            r"\bwallet\b",
            r"\binwestycja\b",
            r"\binwestuj\b",
        ],
        "description": "Message contains financial-market or trading context.",
    },
    {
        "id": "ticker_or_trading_pair",
        "score": 10,
        "patterns": [
            r"\$[A-Z]{2,8}\b",
            r"\b[A-Z]{2,8}/USDT\b",
            r"\b[A-Z]{2,8}/USD\b",
            r"\b[A-Z]{2,8}/EUR\b",
        ],
        "description": "Message contains ticker symbols or trading pairs.",
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


def _match_text_terms(normalized: str, terms: list[str]) -> list[str]:
    return sorted(term for term in terms if term in normalized)


def _match_regex_patterns(normalized: str, patterns: list[str]) -> list[str]:
    matches = []

    for pattern in patterns:
        if re.search(pattern, normalized, flags=re.IGNORECASE):
            matches.append(pattern)

    return matches


def analyze_message_signals(message: str) -> dict:
    normalized = normalize_text(message)

    phishing_rules = []
    market_rules = []

    # Old phishing / scam rules — старую логику не ломаем
    for rule in MESSAGE_RULES:
        matches = _match_text_terms(normalized, rule["terms"])

        if not matches:
            continue

        phishing_rules.append({
            "id": rule["id"],
            "category": "phishing_or_scam",
            "score": rule["score"],
            "description": rule["description"],
            "matches": matches,
        })

    # New market manipulation rules
    for rule in MARKET_MANIPULATION_RULES:
        matches = _match_regex_patterns(normalized, rule["patterns"])

        if not matches:
            continue

        market_rules.append({
            "id": rule["id"],
            "category": "market_manipulation",
            "score": rule["score"],
            "description": rule["description"],
            "matches": matches,
        })

    market_rule_ids = {rule["id"] for rule in market_rules}

    has_market_context = bool({
        "financial_market_context",
        "ticker_or_trading_pair",
    } & market_rule_ids)

    has_profit_promise = bool({
        "guaranteed_or_risk_free_profit",
        "unrealistic_returns",
    } & market_rule_ids)

    has_pressure = bool({
        "investment_time_pressure",
        "direct_trading_instruction",
    } & market_rule_ids)

    has_coordination = bool({
        "pump_or_coordination_language",
    } & market_rule_ids)

    has_inside_info = "inside_or_secret_information" in market_rule_ids

    # Combination bonuses — ловим не отдельные слова, а схему поведения
    if has_market_context and has_profit_promise and has_pressure:
        market_rules.append({
            "id": "combo_profit_pressure_market_context",
            "category": "market_manipulation",
            "score": 25,
            "description": (
                "Combination of market context, profit promise, and time pressure "
                "indicates possible investment manipulation."
            ),
            "matches": [],
        })

    if has_market_context and has_coordination:
        market_rules.append({
            "id": "combo_market_coordination",
            "category": "market_manipulation",
            "score": 20,
            "description": (
                "Trading context combined with coordinated group activity "
                "indicates possible pump-and-dump behavior."
            ),
            "matches": [],
        })

    if has_market_context and has_inside_info:
        market_rules.append({
            "id": "combo_inside_info_market_context",
            "category": "market_manipulation",
            "score": 25,
            "description": (
                "Trading recommendation based on alleged inside or secret information "
                "is a strong market manipulation indicator."
            ),
            "matches": [],
        })

    phishing_score = min(sum(rule["score"] for rule in phishing_rules), 60)
    market_manipulation_score = min(sum(rule["score"] for rule in market_rules), 85)

    total_score = min(phishing_score + market_manipulation_score, 100)

    matched_rules = phishing_rules + market_rules

    return {
        "score": total_score,
        "phishing_score": phishing_score,
        "market_manipulation_score": market_manipulation_score,
        "matched_rules": matched_rules,
    }

def _message_verdict(score: int, has_only_not_found_links: bool) -> str:
    if score >= 50:
        return VERDICT_DANGEROUS
    if score >= 20:
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
    link_characteristic_score = min(
        sum(link["characteristics"]["score"] for link in analyzed_links),
        35,
    )
    max_link_score = max((link["score"] for link in analyzed_links), default=0)
    total_score = min(max_link_score + message_signals["score"] + link_characteristic_score, 100)

    has_links = bool(analyzed_links)
    has_only_not_found_links = has_links and all(
        link["verdict"] == VERDICT_NOT_FOUND for link in analyzed_links
    )
    verdict = _message_verdict(total_score, has_only_not_found_links)

    reasons = []

    for rule in message_signals["matched_rules"]:
        reasons.append(rule["description"])

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
        "details": {
            "details": {
                "message_length": len(message),
                "link_count": len(analyzed_links),
                "unique_domains": unique_domains,
                "max_link_score": max_link_score,
                "message_signal_score": message_signals["score"],
                "phishing_score": message_signals.get("phishing_score", 0),
                "market_manipulation_score": message_signals.get("market_manipulation_score", 0),
                "link_characteristic_score": link_characteristic_score,
            },
        },
    }
