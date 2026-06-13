import socket
from datetime import date, datetime
from typing import Optional

from core.domain_utils import extract_registered_domain

try:
    import whois
except Exception:
    whois = None


socket.setdefaulttimeout(5)


def extract_domain(url_or_domain: str) -> Optional[str]:
    domain = extract_registered_domain(url_or_domain)
    return domain or None


def normalize_creation_date(creation):
    if creation is None:
        return None

    if isinstance(creation, list):
        creation = [item for item in creation if item is not None]

        if not creation:
            return None

        creation = min(creation)

    if isinstance(creation, date) and not isinstance(creation, datetime):
        creation = datetime.combine(creation, datetime.min.time())

    if not isinstance(creation, datetime):
        return None

    return creation


def get_domain_age(domain_or_url: str) -> Optional[int]:
    domain = extract_domain(domain_or_url)

    if not domain or whois is None:
        return None

    try:
        record = whois.whois(domain)
        creation = normalize_creation_date(record.creation_date)

        if creation is None:
            return None

        if creation.tzinfo is not None:
            now = datetime.now(creation.tzinfo)
        else:
            now = datetime.now()

        age_days = (now - creation).days

        if age_days < 0:
            return None

        return age_days

    except Exception:
        return None
