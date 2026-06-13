"""Thread-safe TTL cache for short-lived analyzer primitives."""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Event, RLock
from typing import Any, Callable


@dataclass
class CacheEntry:
    value: Any
    expires_at: float


@dataclass
class InFlightEntry:
    event: Event
    value: Any = None
    error: BaseException | None = None
    has_value: bool = False


class TtlCache:
    def __init__(
        self,
        max_entries: int = 2048,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.max_entries = max_entries
        self.clock = clock or time.monotonic
        self._entries: dict[tuple[str, str], CacheEntry] = {}
        self._inflight: dict[tuple[str, str], InFlightEntry] = {}
        self._lock = RLock()

    def get_or_set(
        self,
        namespace: str,
        key: str,
        ttl_seconds: float,
        factory: Callable[[], Any],
    ) -> Any:
        cache_key = (namespace, key)

        while True:
            now = self.clock()

            with self._lock:
                entry = self._entries.get(cache_key)

                if entry is not None and entry.expires_at > now:
                    return entry.value

                inflight = self._inflight.get(cache_key)

                if inflight is None:
                    inflight = InFlightEntry(event=Event())
                    self._inflight[cache_key] = inflight
                    break

            inflight.event.wait()

            if inflight.error is not None:
                raise inflight.error

            if inflight.has_value:
                return inflight.value

        try:
            value = factory()
        except BaseException as error:
            with self._lock:
                current = self._inflight.get(cache_key)

                if current is inflight:
                    self._inflight.pop(cache_key, None)

                inflight.error = error
                inflight.event.set()

            raise

        expires_at = self.clock() + ttl_seconds

        with self._lock:
            self._entries[cache_key] = CacheEntry(value=value, expires_at=expires_at)
            self._trim_locked()
            self._inflight.pop(cache_key, None)
            inflight.value = value
            inflight.has_value = True
            inflight.event.set()

        return value

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        with self._lock:
            self._drop_expired_locked()
            return len(self._entries)

    def _trim_locked(self) -> None:
        self._drop_expired_locked()

        if len(self._entries) <= self.max_entries:
            return

        overflow = len(self._entries) - self.max_entries
        oldest_keys = sorted(
            self._entries,
            key=lambda item: self._entries[item].expires_at,
        )[:overflow]

        for key in oldest_keys:
            self._entries.pop(key, None)

    def _drop_expired_locked(self) -> None:
        now = self.clock()

        for key, entry in list(self._entries.items()):
            if entry.expires_at <= now:
                self._entries.pop(key, None)
