import socket
from urllib.parse import urlparse

import requests


REQUEST_TIMEOUT = 8


def normalize_url(url: str) -> str:
    url = url.strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def extract_hostname(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else ""


def check_dns_exists(hostname: str) -> tuple[bool, str | None]:
    """
    Check whether the domain exists at the DNS level.

    Returns:
    (True, None) when DNS resolution succeeds.
    (False, error) when DNS resolution fails.
    """
    try:
        socket.getaddrinfo(hostname, None)
        return True, None

    except socket.gaierror as error:
        return False, str(error)


def check_page_existence(url: str) -> dict:
    """
    Check whether a page appears to exist.

    Possible statuses:
    - exists: the page exists
    - not_found: the page returned 404 or 410
    - domain_not_found: the domain could not be resolved through DNS
    - unreachable: the domain exists, but the server could not be reached
    - unknown: there is not enough evidence to decide
    - invalid_url: the URL is invalid
    """
    url = normalize_url(url)
    hostname = extract_hostname(url)

    result = {
        "status": "unknown",
        "exists": None,
        "domain_exists": None,
        "url": url,
        "hostname": hostname,
        "final_url": None,
        "http_status": None,
        "redirected": False,
        "evidence": [],
        "confidence": "low",
        "error": None,
    }

    if not url or not hostname:
        result["status"] = "invalid_url"
        result["exists"] = False
        result["confidence"] = "high"
        result["evidence"].append("URL is empty or invalid.")
        return result

    # 1. DNS check
    dns_exists, dns_error = check_dns_exists(hostname)
    result["domain_exists"] = dns_exists

    if not dns_exists:
        result["status"] = "domain_not_found"
        result["exists"] = False
        result["confidence"] = "high"
        result["error"] = dns_error
        result["evidence"].append(
            "DNS lookup failed: domain does not resolve to any IP address."
        )
        return result

    result["evidence"].append("DNS lookup succeeded: domain resolves to an IP address.")

    # 2. HTTP check
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 SignalShieldPL/1.0 "
                    "(link safety checker)"
                )
            },
        )

        result["final_url"] = response.url
        result["http_status"] = response.status_code
        result["redirected"] = response.url != url

        status = response.status_code

        response.close()

        if result["redirected"]:
            result["evidence"].append(
                f"URL redirected to final URL: {result['final_url']}."
            )

        # Page does not exist
        if status == 404:
            result["status"] = "not_found"
            result["exists"] = False
            result["confidence"] = "high"
            result["evidence"].append("HTTP status 404: page was not found.")
            return result

        if status == 410:
            result["status"] = "not_found"
            result["exists"] = False
            result["confidence"] = "high"
            result["evidence"].append("HTTP status 410: page is gone.")
            return result

        # Page exists
        if 200 <= status < 400:
            result["status"] = "exists"
            result["exists"] = True
            result["confidence"] = "high"
            result["evidence"].append(
                f"HTTP status {status}: page responded successfully."
            )
            return result

        # Page exists, but access is restricted
        if status in [401, 403, 429]:
            result["status"] = "exists"
            result["exists"] = True
            result["confidence"] = "medium"
            result["evidence"].append(
                f"HTTP status {status}: page exists, but access is restricted or rate-limited."
            )
            return result

        # Other 4xx errors
        if 400 <= status < 500:
            result["status"] = "unknown"
            result["exists"] = None
            result["confidence"] = "medium"
            result["evidence"].append(
                f"HTTP status {status}: client error, but not enough evidence to say the page does not exist."
            )
            return result

        # Server errors
        if 500 <= status < 600:
            result["status"] = "unknown"
            result["exists"] = None
            result["confidence"] = "low"
            result["evidence"].append(
                f"HTTP status {status}: server error, page existence cannot be confirmed."
            )
            return result

        result["status"] = "unknown"
        result["exists"] = None
        result["confidence"] = "low"
        result["evidence"].append(
            f"Unexpected HTTP status {status}: page existence cannot be confirmed."
        )
        return result

    except requests.exceptions.SSLError as error:
        result["status"] = "unknown"
        result["exists"] = None
        result["confidence"] = "low"
        result["error"] = str(error)
        result["evidence"].append(
            "SSL error: domain exists, but HTTPS connection could not be verified."
        )
        return result

    except requests.exceptions.Timeout as error:
        result["status"] = "unreachable"
        result["exists"] = None
        result["confidence"] = "medium"
        result["error"] = str(error)
        result["evidence"].append(
            "Request timed out: server did not respond in time."
        )
        return result

    except requests.exceptions.ConnectionError as error:
        result["status"] = "unreachable"
        result["exists"] = None
        result["confidence"] = "medium"
        result["error"] = str(error)
        result["evidence"].append(
            "Connection error: domain exists, but server could not be reached."
        )
        return result

    except requests.RequestException as error:
        result["status"] = "unknown"
        result["exists"] = None
        result["confidence"] = "low"
        result["error"] = str(error)
        result["evidence"].append(
            "Unexpected request error: page existence cannot be confirmed."
        )
        return result
