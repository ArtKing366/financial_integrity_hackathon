import socket

from core.domain_utils import extract_registered_domain

try:
    import dns.resolver
except Exception:
    dns = None


NO_MX_SCORE = 10


def is_trusted_domain(registered_domain: str, trusted_domains: list[str]) -> bool:
    trusted_set = {domain.lower().strip() for domain in trusted_domains if domain}
    return registered_domain.lower() in trusted_set


def resolve_mx_records(domain: str) -> list[str]:
    if dns is None:
        raise RuntimeError("dnspython is not installed.")

    answers = dns.resolver.resolve(domain, "MX", lifetime=4)
    return sorted(str(answer.exchange).rstrip(".").lower() for answer in answers)


def domain_resolves(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False


def analyze_dns_infrastructure(url_or_domain: str, trusted_domains: list[str]) -> dict:
    registered_domain = extract_registered_domain(url_or_domain)

    result = {
        "score": 0,
        "registered_domain": registered_domain,
        "domain_resolves": None,
        "mx_records": [],
        "status": "unknown",
        "description": "",
    }

    if not registered_domain:
        result["status"] = "invalid_domain"
        return result

    if is_trusted_domain(registered_domain, trusted_domains):
        result["status"] = "trusted_domain"
        return result

    result["domain_resolves"] = domain_resolves(registered_domain)

    if not result["domain_resolves"]:
        result["status"] = "domain_not_found"
        return result

    try:
        mx_records = resolve_mx_records(registered_domain)
    except RuntimeError as error:
        result["status"] = "mx_check_unavailable"
        result["description"] = str(error)
        return result
    except Exception as error:
        result["status"] = "no_mx"
        result["score"] = NO_MX_SCORE
        result["description"] = (
            f"Registered domain {registered_domain} has no visible MX records; "
            "this is a weak infrastructure signal, not proof of phishing."
        )
        result["error"] = str(error)
        return result

    result["mx_records"] = mx_records

    if mx_records:
        result["status"] = "mx_found"
    else:
        result["status"] = "no_mx"
        result["score"] = NO_MX_SCORE
        result["description"] = (
            f"Registered domain {registered_domain} has no visible MX records; "
            "this is a weak infrastructure signal, not proof of phishing."
        )

    return result
