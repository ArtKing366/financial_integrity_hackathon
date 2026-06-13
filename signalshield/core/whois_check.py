"""Этап 2: WHOIS-анализ возраста домена."""

from datetime import datetime
from typing import Optional

import whois


def get_domain_age(domain: str) -> Optional[int]:
    """Возвращает возраст домена в днях или None, если дата недоступна."""
    try:
        record = whois.whois(domain)
        creation = record.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None
        return (datetime.now() - creation).days
    except Exception:
        return None
