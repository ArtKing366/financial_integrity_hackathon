"""Quick browser-extension rules sourced from Python data files."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from core.blacklist import FALLBACK_DOMAINS
from core.local_db import read_trusted_brand_domains, utc_iso

RULES_VERSION = 1
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_PATH = PROJECT_ROOT / "browser_extension" / "rules.json"


def sanitize_domain(value: str) -> str | None:
    domain = value.strip().lower().rstrip(".")

    if not domain or "://" in domain or "/" in domain or "@" in domain:
        return None

    if not DOMAIN_PATTERN.fullmatch(domain):
        return None

    return domain


def sanitize_domain_list(values: set[str] | list[str]) -> list[str]:
    sanitized = {
        domain
        for raw_value in values
        for domain in [sanitize_domain(str(raw_value))]
        if domain
    }
    return sorted(sanitized)


def build_quick_rules_config() -> dict[str, Any]:
    trusted_domains = sanitize_domain_list(read_trusted_brand_domains())
    fallback_blacklist = sanitize_domain_list(FALLBACK_DOMAINS)

    return {
        "version": RULES_VERSION,
        "generated_at": utc_iso(),
        "trusted_domains": trusted_domains,
        "fallback_blacklist": fallback_blacklist,
    }


def write_extension_rules_json(path: Path | None = None) -> dict[str, Any]:
    rules = build_quick_rules_config()
    output_path = path or DEFAULT_RULES_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(rules, file, ensure_ascii=False, indent=2)
        file.write("\n")

    return rules
