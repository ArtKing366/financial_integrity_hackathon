"""Generate browser_extension/rules.json from Python data sources."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.extension_rules import DEFAULT_RULES_PATH, write_extension_rules_json


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate browser_extension/rules.json from trusted_brands.json and FALLBACK_DOMAINS."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_RULES_PATH,
        help="Output path for rules.json",
    )
    args = parser.parse_args()

    rules = write_extension_rules_json(args.output)
    print(
        f"Wrote {args.output} "
        f"({len(rules['trusted_domains'])} trusted, "
        f"{len(rules['fallback_blacklist'])} fallback blacklist)."
    )


if __name__ == "__main__":
    main()
