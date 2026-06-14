import re
import unicodedata
from urllib.parse import unquote

from core.domain_utils import extract_registered_domain, normalize_url

try:
    import requests
except Exception:
    requests = None


REQUEST_TIMEOUT = 5
MAX_HTML_BYTES = 500_000
PASSWORD_FIELD_SCORE = 15
HIDDEN_PASSWORD_FIELD_SCORE = 35
BRAND_MARKER_SCORE = 10
MAX_HTML_CRAWLER_SCORE = 40

SENSITIVE_TEXT_MARKERS = {
    "blik": r"\bblik\b",
    "zaloguj": r"\bzaloguj\b",
    "logowanie": r"\blogowanie\b",
    "platnosc": r"\bplatnosc\b",
    "haslo": r"\bhaslo\b",
    "konto": r"\bkonto\b",
    "kod sms": r"\bkod\s+sms\b",
}

POLISH_CHAR_MAP = str.maketrans(
    "\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017c\u017a",
    "acelnoszz",
)


def normalize_text(value: str) -> str:
    value = unquote(value).lower()
    nfkd = unicodedata.normalize("NFKD", value)
    value = "".join(char for char in nfkd if not unicodedata.combining(char))
    return value.translate(POLISH_CHAR_MAP)


def is_trusted_domain(registered_domain: str, trusted_domains: list[str]) -> bool:
    trusted_set = {domain.lower().strip() for domain in trusted_domains if domain}
    return registered_domain.lower() in trusted_set


def fetch_html(url: str) -> tuple[str | None, str | None]:
    if requests is None:
        return None, "requests is not installed."

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 SignalShieldPL/1.0 "
                    "(lightweight link safety crawler)"
                )
            },
        )
        content_type = response.headers.get("content-type", "").lower()

        if "text/html" not in content_type:
            return None, f"Content-Type is not HTML: {content_type}"

        html = response.text

        if len(html) > MAX_HTML_BYTES:
            html = html[:MAX_HTML_BYTES]

        return html, None

    except Exception as error:
        return None, str(error)


def extract_input_tags(html: str) -> list[str]:
    return re.findall(r"<input\b[^>]*>", html, flags=re.IGNORECASE)


def has_password_type(input_tag: str) -> bool:
    return re.search(r"\btype\s*=\s*['\"]?password['\"]?", input_tag, flags=re.IGNORECASE) is not None


def is_hidden_input(input_tag: str) -> bool:
    hidden_patterns = [
        r"\bhidden\b",
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
        r"opacity\s*:\s*0",
        r"class\s*=\s*['\"][^'\"]*\bhidden\b",
    ]
    return any(re.search(pattern, input_tag, flags=re.IGNORECASE) for pattern in hidden_patterns)


def detect_password_fields(html: str) -> dict:
    password_inputs = [
        input_tag for input_tag in extract_input_tags(html) if has_password_type(input_tag)
    ]
    hidden_password_inputs = [
        input_tag for input_tag in password_inputs if is_hidden_input(input_tag)
    ]

    return {
        "password_field_count": len(password_inputs),
        "hidden_password_field_count": len(hidden_password_inputs),
    }


def detect_sensitive_markers(html: str) -> list[str]:
    normalized = normalize_text(re.sub(r"<[^>]+>", " ", html))
    matched = []

    for marker, pattern in SENSITIVE_TEXT_MARKERS.items():
        normalized_marker = normalize_text(marker)
        normalized_pattern = normalize_text(pattern)
        if re.search(normalized_pattern, normalized, flags=re.IGNORECASE):
            matched.append(normalized_marker)

    return sorted(set(matched))


def analyze_html_crawling(
    url: str,
    trusted_domains: list[str],
    html: str | None = None,
    fetch_error: str | None = None,
) -> dict:
    url = normalize_url(url)
    registered_domain = extract_registered_domain(url)

    result = {
        "score": 0,
        "registered_domain": registered_domain,
        "trusted_domain": is_trusted_domain(registered_domain, trusted_domains),
        "password_field_count": 0,
        "hidden_password_field_count": 0,
        "matched_markers": [],
        "matched_rules": [],
        "fetch_error": None,
    }

    error = fetch_error

    if html is None and error is None:
        html, error = fetch_html(url)

    if error:
        result["fetch_error"] = error
        return result

    if not html:
        result["fetch_error"] = "Empty HTML"
        return result

    password_result = detect_password_fields(html)
    result.update(password_result)
    result["matched_markers"] = detect_sensitive_markers(html)

    if result["trusted_domain"]:
        return result

    if result["hidden_password_field_count"] > 0:
        result["score"] += HIDDEN_PASSWORD_FIELD_SCORE
        result["matched_rules"].append({
            "id": "hidden_password_field",
            "severity": "critical",
            "description": "Page contains hidden password input fields on an untrusted domain.",
            "score": HIDDEN_PASSWORD_FIELD_SCORE,
        })
    elif result["password_field_count"] > 0:
        result["score"] += PASSWORD_FIELD_SCORE
        result["matched_rules"].append({
            "id": "password_field_on_untrusted_domain",
            "severity": "high",
            "description": "Page contains password input fields on an untrusted domain.",
            "score": PASSWORD_FIELD_SCORE,
        })

    if result["matched_markers"]:
        result["score"] += BRAND_MARKER_SCORE
        result["matched_rules"].append({
            "id": "sensitive_text_markers_on_untrusted_domain",
            "severity": "medium",
            "description": "Page contains Polish login or payment markers on an untrusted domain.",
            "matches": result["matched_markers"],
            "score": BRAND_MARKER_SCORE,
        })

    result["score"] = min(result["score"], MAX_HTML_CRAWLER_SCORE)
    return result
