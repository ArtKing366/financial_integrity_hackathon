from urllib.parse import urlparse


COMMON_TWO_PART_SUFFIXES = {
    "com.pl",
    "org.pl",
    "net.pl",
    "edu.pl",
    "gov.pl",
    "co.uk",
    "com.au",
    "co.nz",
    "co.jp",
    "com.br",
    "org.uk",
    "me.uk",
    "net.au",
    "com.mx",
}

_NON_HTTP_SCHEMES = {
    "mailto",
    "ftp",
    "ftps",
    "sftp",
    "tel",
    "sms",
    "data",
    "javascript",
    "blob",
    "file",
}


def normalize_url(value: str) -> str:
    """Normalize web URLs and reject non-web schemes."""
    value = value.strip()

    if not value:
        return ""

    lower = value.lower()
    for scheme in _NON_HTTP_SCHEMES:
        if lower.startswith(f"{scheme}:"):
            return ""

    if not lower.startswith(("http://", "https://")):
        value = "https://" + value

    return value


def extract_hostname(url_or_domain: str) -> str:
    url = normalize_url(url_or_domain)

    if not url:
        return ""

    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else ""


def split_domain(url_or_domain: str) -> dict[str, str]:
    hostname = extract_hostname(url_or_domain)

    result = {
        "hostname": hostname,
        "subdomain": "",
        "domain": "",
        "suffix": "",
        "registered_domain": "",
    }

    if not hostname:
        return result

    try:
        import tldextract

        extracted = tldextract.extract(hostname)
        result["subdomain"] = extracted.subdomain or ""
        result["domain"] = extracted.domain or ""
        result["suffix"] = extracted.suffix or ""
    except Exception:
        parts = [part for part in hostname.split(".") if part]

        if len(parts) == 1:
            result["domain"] = parts[0]
        elif len(parts) >= 3 and ".".join(parts[-2:]) in COMMON_TWO_PART_SUFFIXES:
            result["subdomain"] = ".".join(parts[:-3])
            result["domain"] = parts[-3]
            result["suffix"] = ".".join(parts[-2:])
        elif len(parts) >= 2:
            result["subdomain"] = ".".join(parts[:-2])
            result["domain"] = parts[-2]
            result["suffix"] = parts[-1]

    if result["domain"] and result["suffix"]:
        result["registered_domain"] = f"{result['domain']}.{result['suffix']}"
    else:
        result["registered_domain"] = result["domain"] or hostname

    return result


def extract_registered_domain(url_or_domain: str) -> str:
    return split_domain(url_or_domain)["registered_domain"]
