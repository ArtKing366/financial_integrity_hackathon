"""Local HTTP API for SignalShield browser extension integration."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from core.local_db import (
    add_list_entry,
    expiry_from_choice,
    recent_scan_events,
    record_scan_event,
    summarize_page_domains,
    summarize_verdicts,
)
from core.domain_utils import normalize_url
from core.verdict import analyze_url, new_analysis_context


MAX_BATCH_LINKS = 100
CLIENT_DISCONNECT_WINERRORS = {10053, 10054}


def json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def is_client_disconnect(error: BaseException) -> bool:
    return (
        isinstance(error, (BrokenPipeError, ConnectionAbortedError, ConnectionResetError))
        or getattr(error, "winerror", None) in CLIENT_DISCONNECT_WINERRORS
    )


class SignalShieldHandler(BaseHTTPRequestHandler):
    server_version = "SignalShieldAPI/0.1"

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self.send_json({"ok": True, "service": "signalshield-api"})
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

        self.send_json({"ok": False, "error": "Not found"}, status=404)

    def do_POST(self) -> None:
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

            result = analyze_url(target_url)
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

            normalized_links = []
            seen_links = set()

            for target_url in links[:MAX_BATCH_LINKS]:
                normalized = normalize_url(str(target_url))

                if not normalized or normalized in seen_links:
                    continue

                seen_links.add(normalized)
                normalized_links.append(normalized)

            context = new_analysis_context()
            results = []

            for target_url in normalized_links:
                result = analyze_url(target_url, context=context)
                record_scan_event(target_url, result, page_url=page_url, source=source)
                results.append({"url": target_url, "result": result})

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

    def log_message(self, format: str, *args: Any) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local SignalShield API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8766, type=int)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), SignalShieldHandler)
    print(f"SignalShield API listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
