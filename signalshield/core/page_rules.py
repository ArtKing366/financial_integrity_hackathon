import re
from urllib.parse import parse_qs, urljoin, urlparse

from core.domain_utils import extract_registered_domain

try:
    import requests
except Exception:
    requests = None

try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None


TRUSTED_MICROSOFT_LOGIN_HOSTS = {
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.microsoft.com",
    "login.microsoft.net",
    "login.windows.net",
    "login.partner.microsoftonline.cn",
    "login.live.com",
}


MICROSOFT_BRAND_PATTERNS = [
    r"microsoft",
    r"office\s*365",
    r"microsoft\s*365",
    r"azure\s*ad",
    r"entra\s*id",
    r"outlook",
]


AAD_PRIMARY_PATTERNS = {
    "loginfmt": r"loginfmt",
    "i0116": r"i0116",
    "idSIButton9": r"idSIButton9",
    "idPartnerPL": r"idPartnerPL",
    "urlMsaSignUp": r"urlMsaSignUp",
    "flowToken": r"flowToken",
    "aadcdn_msauth": r"aadcdn\.msauth\.net",
}


SUSPICIOUS_TEXT_PATTERNS = {
    "verify_now": r"verify\s+now",
    "click_here": r"click\s+here",
    "urgent_action": r"urgent\s+action",
    "suspended_account": r"suspended\s+account",
    "security_alert": r"security\s+alert",
    "immediate_attention": r"immediate\s+attention",
    "limited_time": r"limited\s+time",
}


SUSPICIOUS_DOMAIN_PATTERNS = [
    r"secure-?(microsoft|office|365|outlook)",
    r"(microsoft|office|outlook|365)-?(login|verify|secure|auth)",
    r"(login|verify|secure|auth)-?(microsoft|office|outlook|365)",
]

TUNNEL_DOMAIN_SUFFIXES = {
    "ngrok-free.app",
    "trycloudflare.com",
}

PUBLIC_HOSTING_SUFFIXES = {
    "pages.dev",
    "workers.dev",
}


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else ""


def hostname_matches_suffix(hostname: str, suffixes: set[str]) -> bool:
    return any(hostname == suffix or hostname.endswith(f".{suffix}") for suffix in suffixes)


def trusted_domain_set(trusted_domains: list[str] | None) -> set[str]:
    return {domain.lower().strip() for domain in trusted_domains or [] if domain}


def referenced_trusted_domains(text: str, trusted_domains: list[str] | None) -> list[str]:
    normalized_text = text.lower()
    return sorted(
        domain
        for domain in trusted_domain_set(trusted_domains)
        if domain and domain in normalized_text
    )


def is_trusted_microsoft_login(hostname: str) -> bool:
    return hostname in TRUSTED_MICROSOFT_LOGIN_HOSTS


def fetch_page(url: str) -> tuple[str | None, str | None]:
    """
    Return the fetched HTML and an error message.

    If the page cannot be fetched, html is None and error contains the reason.
    """
    if requests is None:
        return None, "requests is not installed."

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 SafeLinkBot/1.0 "
                    "(security research; phishing detection)"
                )
            },
        )

        content_type = response.headers.get("content-type", "").lower()

        if "text/html" not in content_type:
            return None, f"Content-Type is not HTML: {content_type}"

        html = response.text

        if len(html) > 2_000_000:
            html = html[:2_000_000]

        return html, None

    except requests.RequestException as e:
        return None, str(e)


def has_microsoft_branding(text: str) -> bool:
    return any(
        re.search(pattern, text, flags=re.IGNORECASE)
        for pattern in MICROSOFT_BRAND_PATTERNS
    )


def detect_aad_fingerprint(html: str) -> list[str]:
    matched = []

    for rule_id, pattern in AAD_PRIMARY_PATTERNS.items():
        if re.search(pattern, html, flags=re.IGNORECASE):
            matched.append(rule_id)

    return matched


def detect_suspicious_text(text: str) -> list[str]:
    matched = []

    for rule_id, pattern in SUSPICIOUS_TEXT_PATTERNS.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            matched.append(rule_id)

    return matched


def detect_suspicious_domain(hostname: str) -> list[str]:
    matched = []

    for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
        if re.search(pattern, hostname, flags=re.IGNORECASE):
            matched.append(pattern)

    return matched


def has_password_field(soup: BeautifulSoup) -> bool:
    return soup.select_one("input[type='password']") is not None


def has_login_field(soup: BeautifulSoup) -> bool:
    selectors = [
        "input[name='loginfmt']",
        "#i0116",
        "input[type='email']",
        "input[type='text']",
        "input[type='tel']",
    ]

    return any(soup.select_one(selector) is not None for selector in selectors)


def form_action_is_suspicious(soup: BeautifulSoup, page_url: str) -> bool:
    """
    Check page forms for suspicious credential submission targets.

    A password form that does not submit to an official Microsoft login domain
    is a strong phishing indicator.
    """
    forms = soup.find_all("form")

    for form in forms:
        password_inside_form = form.select_one("input[type='password']") is not None

        if not password_inside_form:
            continue

        action = form.get("action", "").strip()

        if not action:
            return True

        absolute_action = urljoin(page_url, action)
        action_host = get_hostname(absolute_action)

        if not is_trusted_microsoft_login(action_host):
            return True

    return False


def detect_js_form_action_modification(html: str) -> bool:
    """
    Detect JavaScript that changes form.action during form submission.
    """
    patterns = [
        r"addEventListener\s*\(\s*['\"]submit['\"]",
        r"\.action\s*=\s*['\"]https?://(?!login\.microsoftonline)",
        r"form\.setAttribute\s*\(\s*['\"]action['\"]",
    ]

    matches = 0

    for pattern in patterns:
        if re.search(pattern, html, flags=re.IGNORECASE):
            matches += 1

    return matches >= 2


def has_long_query_parameter(url: str) -> bool:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    for values in query.values():
        for value in values:
            if len(value) >= 30:
                return True

    return False


def analyze_page_rules(
    url: str,
    html: str | None = None,
    fetch_error: str | None = None,
    trusted_domains: list[str] | None = None,
) -> dict:
    """
    Analyze page content with rules inspired by CyberDrain/Check.

    Returns:
    {
        "score": int,
        "hard_block": bool,
        "matched_rules": list,
        "fetch_error": str | None
    }
    """
    url = normalize_url(url)
    hostname = get_hostname(url)
    registered_domain = extract_registered_domain(url)
    trusted_domains_normalized = trusted_domain_set(trusted_domains)

    result = {
        "score": 0,
        "hard_block": False,
        "matched_rules": [],
        "fetch_error": None,
    }

    if not hostname:
        result["fetch_error"] = "Invalid URL"
        return result

    if is_trusted_microsoft_login(hostname):
        result["matched_rules"].append({
            "id": "trusted_microsoft_login",
            "severity": "info",
            "description": "Official Microsoft login domain",
            "score": 0,
        })
        return result

    if registered_domain in trusted_domains_normalized:
        return result

    suspicious_domain_matches = detect_suspicious_domain(hostname)

    if suspicious_domain_matches:
        result["score"] += 25
        result["matched_rules"].append({
            "id": "suspicious_microsoft_like_domain",
            "severity": "high",
            "description": "Domain name imitates Microsoft / Office / Outlook",
            "matches": suspicious_domain_matches,
            "score": 25,
        })

    if url.lower().startswith("data:text/html"):
        result["score"] += 60
        result["hard_block"] = True
        result["matched_rules"].append({
            "id": "data_uri_login_page",
            "severity": "critical",
            "description": "Data URI can hide fake login page content",
            "score": 60,
        })
        return result

    error = fetch_error

    if html is None and error is None:
        html, error = fetch_page(url)

    if error:
        result["fetch_error"] = error
        return result

    if not html:
        result["fetch_error"] = "Empty HTML"
        return result

    if BeautifulSoup is None:
        result["fetch_error"] = "beautifulsoup4 is not installed."
        return result

    soup = BeautifulSoup(html, "html.parser")
    page_text = soup.get_text(" ", strip=True)
    combined_text = f"{html} {page_text}"
    trusted_references = referenced_trusted_domains(combined_text, trusted_domains)

    microsoft_branding = has_microsoft_branding(combined_text)
    password_field = has_password_field(soup)
    login_field = has_login_field(soup)
    aad_matches = detect_aad_fingerprint(html)
    suspicious_text_matches = detect_suspicious_text(page_text)
    microsoft_context = bool(
        suspicious_domain_matches or microsoft_branding or aad_matches
    )

    if password_field and trusted_references:
        if hostname_matches_suffix(hostname, TUNNEL_DOMAIN_SUFFIXES):
            result["score"] += 35
            result["matched_rules"].append({
                "id": "credential_form_on_tunnel",
                "severity": "critical",
                "description": "Credential form is hosted on a public tunnel domain.",
                "matches": [hostname],
                "score": 35,
            })
        elif hostname_matches_suffix(hostname, PUBLIC_HOSTING_SUFFIXES):
            result["score"] += 35
            result["matched_rules"].append({
                "id": "credential_form_on_public_hosting",
                "severity": "critical",
                "description": "Credential form is hosted on public static or worker infrastructure.",
                "matches": [hostname],
                "score": 35,
            })

        if registered_domain not in trusted_domains_normalized:
            result["score"] += 45
            result["hard_block"] = True
            result["matched_rules"].append({
                "id": "trusted_brand_credential_form_on_external_domain",
                "severity": "critical",
                "description": "Credential form references a trusted financial brand from an external domain.",
                "matches": trusted_references[:5],
                "score": 45,
            })

    if len(aad_matches) >= 2:
        result["score"] += 35
        result["matched_rules"].append({
            "id": "aad_fingerprint_on_non_microsoft_domain",
            "severity": "critical",
            "description": "Page contains Azure AD / Microsoft login fingerprints on non-Microsoft domain",
            "matches": aad_matches,
            "score": 35,
        })

    if microsoft_branding and password_field and login_field:
        result["score"] += 30
        result["matched_rules"].append({
            "id": "microsoft_branded_credential_form",
            "severity": "high",
            "description": "Page uses Microsoft branding and contains credential fields",
            "score": 30,
        })

    if microsoft_context and form_action_is_suspicious(soup, url):
        result["score"] += 45
        result["hard_block"] = True
        result["matched_rules"].append({
            "id": "form_action_not_microsoft",
            "severity": "critical",
            "description": "Password form submits credentials to a non-Microsoft domain",
            "score": 45,
        })

    if microsoft_context and detect_js_form_action_modification(html):
        result["score"] += 35
        result["matched_rules"].append({
            "id": "js_modifies_form_action",
            "severity": "high",
            "description": "JavaScript modifies form action during submit",
            "score": 35,
        })

    if has_long_query_parameter(url) and microsoft_branding and (password_field or login_field):
        result["score"] += 20
        result["matched_rules"].append({
            "id": "long_query_with_microsoft_login_context",
            "severity": "medium",
            "description": "Long query parameter combined with Microsoft branding and login fields",
            "score": 20,
        })

    if microsoft_branding and suspicious_text_matches:
        result["score"] += 15
        result["matched_rules"].append({
            "id": "microsoft_urgency_social_engineering",
            "severity": "medium",
            "description": "Urgency / pressure language targeting Microsoft users",
            "matches": suspicious_text_matches,
            "score": 15,
        })

    result["score"] = min(result["score"], 100)

    if result["score"] >= 70:
        result["hard_block"] = True

    return result
