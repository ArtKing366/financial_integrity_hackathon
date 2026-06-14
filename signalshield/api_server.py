"""Local HTTP API for SignalShield browser extension integration."""

from __future__ import annotations

import argparse
import json
import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from core.analysis_cache import TtlCache
from core.domain_utils import extract_registered_domain, normalize_url
from core.local_db import (
    add_list_entry,
    database_status,
    deactivate_list_entry,
    expiry_from_choice,
    list_entries,
    recent_scan_events,
    record_scan_event,
    summarize_page_domains,
    summarize_verdicts,
    sync_builtin_lists,
)
from core.extension_rules import build_quick_rules_config
from core.verdict import analyze_url, new_analysis_context

MAX_BATCH_LINKS = 100
MAX_BATCH_WORKERS = 6
CLIENT_DISCONNECT_WINERRORS = {10053, 10054}
SHARED_ANALYSIS_CACHE = TtlCache(max_entries=4096)


def get_or_create_api_token() -> str:
    """Получает существующий или генерирует новый секретный токен для API."""
    token_path = Path.home() / ".signalshield" / "api_token"
    if token_path.exists():
        return token_path.read_text().strip()

    token_path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32)  # Генерируем безопасный 256-битный ключ
    token_path.write_text(token)

    # Ограничиваем права доступа к файлу (для Linux и macOS)
    if os.name != "nt":
        token_path.chmod(0o600)

    return token


# Инициализируем локальный токен при старте сервера
API_TOKEN = get_or_create_api_token()


def json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def is_client_disconnect(error: BaseException) -> bool:
    return (
        isinstance(error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError))
        or getattr(error, "winerror", None) in CLIENT_DISCONNECT_WINERRORS
    )


def normalize_unique_links(links: list[Any], limit: int = MAX_BATCH_LINKS) -> list[str]:
    normalized_links = []
    seen_links = set()

    for target_url in links[:limit]:
        normalized = normalize_url(str(target_url))

        if not normalized or normalized in seen_links:
            continue

        seen_links.add(normalized)
        normalized_links.append(normalized)

    return normalized_links


def group_links_by_domain(links: list[str]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}

    for target_url in links:
        domain = extract_registered_domain(target_url) or target_url
        groups.setdefault(domain, []).append(target_url)

    return list(groups.values())


def query_flag(params: dict[str, list[str]], key: str) -> bool:
    value = (params.get(key) or [""])[0].strip().lower()
    return value in {"1", "true", "yes", "on"}


def analyze_link_group(links: list[str]) -> list[dict[str, Any]]:
    context = new_analysis_context(shared_cache=SHARED_ANALYSIS_CACHE)
    return [
        {"url": target_url, "result": analyze_url(target_url, context=context)}
        for target_url in links
    ]


def analyze_links_batch(
    links: list[Any],
    max_workers: int = MAX_BATCH_WORKERS,
) -> list[dict[str, Any]]:
    normalized_links = normalize_unique_links(links)
    groups = group_links_by_domain(normalized_links)

    if len(groups) <= 1 or max_workers <= 1:
        unordered_results = [
            item
            for group in groups
            for item in analyze_link_group(group)
        ]
    else:
        worker_count = min(max_workers, len(groups))
        unordered_results = []

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            for group_results in executor.map(analyze_link_group, groups):
                unordered_results.extend(group_results)

    result_by_url = {
        item["url"]: item
        for item in unordered_results
    }

    return [
        result_by_url[target_url]
        for target_url in normalized_links
        if target_url in result_by_url
    ]


class SignalShieldHandler(BaseHTTPRequestHandler):
    server_version = "SignalShieldAPI/0.2"

    def end_headers(self) -> None:
        origin = self.headers.get("Origin")
        allowed_schemes = ("chrome-extension://", "moz-extension://", "safari-web-extension://")

        # Разрешаем CORS динамически только для расширений браузера
        if origin and origin.startswith(allowed_schemes):
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            # Делфолтный безопасный fallback для локальных запросов без Origin
            self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1:8766")

        # Разрешаем передачу заголовка авторизации
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        super().end_headers()

    def is_authenticated(self) -> bool:
        """Проверяет заголовок Authorization на соответствие секретному токену."""
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            return secrets.compare_digest(token, API_TOKEN)
        return False

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        # Публичный и безопасный эндпоинт для проверки работоспособности
        if parsed.path == "/health":
            self.send_json({"ok": True, "service": "signalshield-api", "auth_required": False})
            return

        # Публичный read-only конфиг для quick-check расширения (только домены из data/)
        if parsed.path == "/quick-rules":
            self.send_json({
                "ok": True,
                "rules": build_quick_rules_config(),
                "auth_required": False,
            })
            return

        # Защита всех остальных GET эндпоинтов
        if not self.is_authenticated():
            self.send_json({"ok": False, "error": "Unauthorized"}, status=401)
            return

        if parsed.path == "/analytics":
            params = parse_qs(parsed.query)
            page_domain = (params.get("page_domain") or [""])[0]
            self.send_json({
                "ok": True,
                "page_domains": summarize_page_domains(),
                "verdicts": summarize_verdicts(page_domain or None),
                "recent": recent_scan_events(50),
            })
            return

        if parsed.path == "/list-entries":
            params = parse_qs(parsed.query)
            self.send_json({
                "ok": True,
                "entries": list_entries(
                    include_inactive=query_flag(params, "include_inactive"),
                    include_expired=query_flag(params, "include_expired"),
                    include_system=query_flag(params, "include_system"),
                ),
            })
            return

        if parsed.path == "/database/status":
            self.send_json({
                "ok": True,
                "status": database_status(),
            })
            return

        self.send_json({"ok": False, "error": "Not found"}, status=404)

    def do_POST(self) -> None:
        # Полный запрет любых мутаций и анализов без авторизации
        if not self.is_authenticated():
            self.send_json({"ok": False, "error": "Unauthorized"}, status=401)
            return

        parsed = urlparse(self.path)

        if parsed.path == "/analyze-url":
            self.handle_analyze_url()
            return

        if parsed.path == "/analyze-batch":
            self.handle_analyze_batch()
            return

        if parsed.path == "/list-entry":
            self.handle_list_entry()
            return

        if parsed.path == "/list-entry/deactivate":
            self.handle_deactivate_list_entry_body()
            return

        if parsed.path == "/database/sync":
            self.handle_database_sync()
            return

        self.send_json({"ok": False, "error": "Not found"}, status=404)

    def do_DELETE(self) -> None:
        # Защита деструктивных методов удаления/деактивации
        if not self.is_authenticated():
            self.send_json({"ok": False, "error": "Unauthorized"}, status=401)
            return

        parsed = urlparse(self.path)

        if parsed.path == "/list-entry":
            self.handle_deactivate_list_entry_query(parsed)
            return

        self.send_json({"ok": False, "error": "Not found"}, status=404)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)

        if length <= 0:
            return {}

        raw_body = self.rfile.read(length).decode("utf-8")
        return json.loads(raw_body or "{}")

    def send_json(self, payload: Any, status: int = 200) -> bool:
        body = json_bytes(payload)

        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return True
        except OSError as error:
            if is_client_disconnect(error):
                return False
            raise

    def handle_analyze_url(self) -> None:
        try:
            payload = self.read_json()
            target_url = str(payload.get("url", ""))
            page_url = str(payload.get("page_url", ""))
            source = str(payload.get("source", "api"))

            context = new_analysis_context(shared_cache=SHARED_ANALYSIS_CACHE)
            result = analyze_url(target_url, context=context)
            record_scan_event(target_url, result, page_url=page_url, source=source)
            self.send_json({"ok": True, "result": result})
        except Exception as error:
            if is_client_disconnect(error):
                return
            self.send_json({"ok": False, "error": str(error)}, status=400)

    def handle_analyze_batch(self) -> None:
        try:
            payload = self.read_json()
            page_url = str(payload.get("page_url", ""))
            source = str(payload.get("source", "extension"))
            links = payload.get("links", [])

            if not isinstance(links, list):
                raise ValueError("links must be a list")

            results = analyze_links_batch(links)

            for item in results:
                record_scan_event(
                    item["url"],
                    item["result"],
                    page_url=page_url,
                    source=source,
                )

            self.send_json({
                "ok": True,
                "results": results,
                "verdicts": summarize_verdicts(),
            })
        except Exception as error:
            if is_client_disconnect(error):
                return
            self.send_json({"ok": False, "error": str(error)}, status=400)

    def handle_list_entry(self) -> None:
        try:
            payload = self.read_json()
            entry = add_list_entry(
                list_type=str(payload.get("list_type", "")),
                scope=str(payload.get("scope", "")),
                value=str(payload.get("value", "")),
                label=str(payload.get("label", "")),
                note=str(payload.get("note", "")),
                expires_at=payload.get("expires_at") or expiry_from_choice(
                    str(payload.get("expires_in", "Never"))
                ),
            )
            self.send_json({"ok": True, "entry": entry})
        except Exception as error:
            if is_client_disconnect(error):
                return
            self.send_json({"ok": False, "error": str(error)}, status=400)

    def handle_database_sync(self) -> None:
        try:
            payload = self.read_json()
            result = sync_builtin_lists(force=bool(payload.get("force", False)))
            self.send_json({"ok": True, "sync": result})
        except Exception as error:
            if is_client_disconnect(error):
                return
            self.send_json({"ok": False, "error": str(error)}, status=400)

    def deactivate_entry(self, entry_id: int) -> None:
        if entry_id <= 0:
            raise ValueError("entry_id must be a positive integer")

        removed = deactivate_list_entry(entry_id)
        self.send_json({"ok": True, "removed": removed})

    def handle_deactivate_list_entry_query(self, parsed) -> None:
        try:
            params = parse_qs(parsed.query)
            self.deactivate_entry(int((params.get("id") or ["0"])[0]))
        except Exception as error:
            if is_client_disconnect(error):
                return
            self.send_json({"ok": False, "error": str(error)}, status=400)

    def handle_deactivate_list_entry_body(self) -> None:
        try:
            payload = self.read_json()
            self.deactivate_entry(int(payload.get("id", 0) or 0))
        except Exception as error:
            if is_client_disconnect(error):
                return
            self.send_json({"ok": False, "error": str(error)}, status=400)

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local SignalShield API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8766, type=int)
    args = parser.parse_args()

    sync_builtin_lists()
    server = ThreadingHTTPServer((args.host, args.port), SignalShieldHandler)
    
    print(f"SignalShield API listening on http://{args.host}:{args.port}")
    print("API Security Status: ENABLED")
    print(f"  Token File: {Path.home() / '.signalshield' / 'api_token'}")
    print(f"  Current Authorization Header: Bearer {API_TOKEN}")
    
    server.serve_forever()


if __name__ == "__main__":
    main()