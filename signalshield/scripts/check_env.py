"""Validate the local development environment for SignalShield."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PYTHON_MODULES = {
    "streamlit": "streamlit",
    "pytest": "pytest",
    "requests": "requests",
    "tldextract": "tldextract",
    "validators": "validators",
    "bs4": "beautifulsoup4",
    "dns": "dnspython",
    "whois": "python-whois",
    "Levenshtein": "python-Levenshtein",
}

REQUIRED_FILES = [
    "app.py",
    "requirements.txt",
    "browser_extension/manifest.json",
    "browser_extension/content.js",
    "browser_extension/popup.js",
    "fixtures/extension_test_page.html",
]


def module_available(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def main() -> int:
    missing_modules = [
        package_name
        for module_name, package_name in PYTHON_MODULES.items()
        if not module_available(module_name)
    ]
    missing_files = [
        path
        for path in REQUIRED_FILES
        if not (PROJECT_ROOT / path).exists()
    ]
    node_path = shutil.which("node")

    if missing_modules:
        print("Missing Python packages:")
        for package_name in missing_modules:
            print(f"  - {package_name}")
        print("Install them with: python -m pip install -r requirements-dev.txt")

    if missing_files:
        print("Missing project files:")
        for path in missing_files:
            print(f"  - {path}")

    if node_path is None:
        print("Node.js was not found in PATH. JS syntax checks will be skipped.")
    else:
        print(f"Node.js found: {node_path}")

    if missing_modules or missing_files:
        return 1

    print("Environment looks ready for local checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
