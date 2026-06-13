from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from time import sleep

import pytest

from core.analysis_cache import TtlCache


def test_ttl_cache_reuses_value_before_expiry() -> None:
    now = [100.0]
    cache = TtlCache(clock=lambda: now[0])
    calls = {"count": 0}

    def factory() -> str:
        calls["count"] += 1
        return f"value-{calls['count']}"

    assert cache.get_or_set("dns", "example.pl", 10, factory) == "value-1"
    now[0] = 105.0
    assert cache.get_or_set("dns", "example.pl", 10, factory) == "value-1"
    assert calls["count"] == 1


def test_ttl_cache_refreshes_after_expiry() -> None:
    now = [100.0]
    cache = TtlCache(clock=lambda: now[0])
    calls = {"count": 0}

    def factory() -> str:
        calls["count"] += 1
        return f"value-{calls['count']}"

    assert cache.get_or_set("whois", "example.pl", 10, factory) == "value-1"
    now[0] = 111.0
    assert cache.get_or_set("whois", "example.pl", 10, factory) == "value-2"
    assert calls["count"] == 2


def test_ttl_cache_does_not_store_factory_exceptions() -> None:
    cache = TtlCache()
    calls = {"count": 0}

    def factory() -> str:
        calls["count"] += 1

        if calls["count"] == 1:
            raise RuntimeError("temporary failure")

        return "recovered"

    with pytest.raises(RuntimeError):
        cache.get_or_set("html", "https://example.pl", 10, factory)

    assert cache.get_or_set("html", "https://example.pl", 10, factory) == "recovered"
    assert calls["count"] == 2


def test_ttl_cache_shares_concurrent_factory_for_same_key() -> None:
    cache = TtlCache()
    lock = Lock()
    calls = {"count": 0}

    def factory() -> str:
        with lock:
            calls["count"] += 1

        sleep(0.05)
        return "shared-value"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda _index: cache.get_or_set("dns", "example.pl", 10, factory),
                range(8),
            )
        )

    assert results == ["shared-value"] * 8
    assert calls["count"] == 1
