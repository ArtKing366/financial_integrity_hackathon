from pathlib import Path

from core.blacklist import FALLBACK_DOMAINS
from core.extension_rules import (
    build_quick_rules_config,
    sanitize_domain,
    sanitize_domain_list,
    write_extension_rules_json,
)
from core.local_db import read_trusted_brand_domains


def test_sanitize_domain_rejects_invalid_values() -> None:
    assert sanitize_domain("mbank.pl") == "mbank.pl"
    assert sanitize_domain("HTTPS://evil.com/path") is None
    assert sanitize_domain("not a domain") is None
    assert sanitize_domain("") is None


def test_build_quick_rules_config_matches_python_sources() -> None:
    rules = build_quick_rules_config()

    assert rules["version"] == 1
    assert rules["trusted_domains"] == sanitize_domain_list(read_trusted_brand_domains())
    assert rules["fallback_blacklist"] == sanitize_domain_list(FALLBACK_DOMAINS)
    assert "generated_at" in rules


def test_write_extension_rules_json(tmp_path: Path) -> None:
    output_path = tmp_path / "rules.json"
    rules = write_extension_rules_json(output_path)

    assert output_path.exists()
    assert rules["trusted_domains"]
    assert rules["fallback_blacklist"]
