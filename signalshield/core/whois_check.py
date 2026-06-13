import socket
from datetime import datetime
from typing import Optional

import whois

socket.setdefaulttimeout(5)


def get_domain_age(domain: str) -> Optional[int]:
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
