from datetime import date, datetime
from typing import Optional

from core.domain_utils import extract_registered_domain

try:
    import whois
except Exception:
    whois = None

# REMOVED: socket.setdefaulttimeout(5) — this was a global side effect that
# changed the default timeout for ALL sockets in the process (including
# requests, DNS lookups, and any other network I/O).  The timeout is now
# applied locally inside get_domain_age() via socket.create_default_context()
# is not needed here; whois library calls are wrapped in try/except instead.
import socket


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


def get_domain_age(domain_or_url: str, timeout: int = 5) -> Optional[int]:
    """
    Return the age of the domain in days, or None if it cannot be determined.

    The ``timeout`` argument sets the socket timeout only for the duration of
    the WHOIS look-up, avoiding the global side-effect of the previous
    ``socket.setdefaulttimeout()`` call at module level.
    """
    domain = extract_domain(domain_or_url)

    if not domain or whois is None:
        return None

    # Apply timeout locally so we don't affect any other sockets in the process.
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        record = whois.whois(domain)
    except Exception:
        return None
    finally:
        # Always restore the previous global default, even on error.
        socket.setdefaulttimeout(old_timeout)

    try:
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