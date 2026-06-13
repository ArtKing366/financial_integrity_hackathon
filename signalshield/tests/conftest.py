"""Shared pytest bootstrap for local and CI runs."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_DB_DIR = tempfile.TemporaryDirectory()
TEST_DB_PATH = Path(TEST_DB_DIR.name) / "signalshield-test.sqlite3"

os.environ.setdefault("SIGNALSHIELD_DB_PATH", str(TEST_DB_PATH))

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
