import json
import threading
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

import api_server

from core.analysis_cache import TtlCache


def test_normalize_unique_links_preserves_order_and_deduplicates() -> None:
    links = [
        "example-one.pl/path",
        "https://example-two.pl",
        "example-one.pl/path",
        "",
    ]

    assert api_server.normalize_unique_links(links) == [
        "https://example-one.pl/path",
        "https://example-two.pl",
    ]


def test_analyze_links_batch_preserves_input_order(monkeypatch) -> None:
    def fake_analyze_url(url: str, context: dict) -> dict:
        return {"verdict": "SAFE", "score": 0, "reasons": [url], "details": {}}

    monkeypatch.setattr(api_server, "analyze_url", fake_analyze_url)
    monkeypatch.setattr(api_server, "new_analysis_context", lambda shared_cache=None: {})

    results = api_server.analyze_links_batch(
        [
            "https://b-example.pl/two",
            "https://a-example.pl/one",
            "https://b-example.pl/two",
        ],
        max_workers=3,
    )

    assert [item["url"] for item in results] == [
        "https://b-example.pl/two",
        "https://a-example.pl/one",
    ]


def test_analyze_links_batch_reuses_context_inside_domain_group(monkeypatch) -> None:
    contexts_by_url = {}
    markers = iter(range(100))

    def fake_context(shared_cache=None) -> dict:
        return {"marker": next(markers)}

    def fake_analyze_url(url: str, context: dict) -> dict:
        contexts_by_url[url] = context["marker"]
        return {"verdict": "SAFE", "score": 0, "reasons": [], "details": {}}

    monkeypatch.setattr(api_server, "new_analysis_context", fake_context)
    monkeypatch.setattr(api_server, "analyze_url", fake_analyze_url)

    api_server.analyze_links_batch(
        [
            "https://same-example.pl/first",
            "https://same-example.pl/second",
            "https://other-example.pl/item",
        ],
        max_workers=3,
    )

    assert contexts_by_url["https://same-example.pl/first"] == contexts_by_url[
        "https://same-example.pl/second"
    ]
    assert contexts_by_url["https://same-example.pl/first"] != contexts_by_url[
        "https://other-example.pl/item"
    ]


def test_analyze_links_batch_passes_shared_cache_to_each_context(monkeypatch) -> None:
    shared_cache = TtlCache()
    observed_caches = []

    def fake_context(shared_cache=None) -> dict:
        observed_caches.append(shared_cache)
        return {"shared_cache": shared_cache}

    def fake_analyze_url(url: str, context: dict) -> dict:
        assert context["shared_cache"] is shared_cache
        return {"verdict": "SAFE", "score": 0, "reasons": [], "details": {}}

    monkeypatch.setattr(api_server, "SHARED_ANALYSIS_CACHE", shared_cache)
    monkeypatch.setattr(api_server, "new_analysis_context", fake_context)
    monkeypatch.setattr(api_server, "analyze_url", fake_analyze_url)

    api_server.analyze_links_batch(
        [
            "https://first-domain-example.pl/a",
            "https://second-domain-example.pl/b",
        ],
        max_workers=1,
    )
    api_server.analyze_links_batch(
        ["https://third-domain-example.pl/c"],
        max_workers=1,
    )

    assert observed_caches == [shared_cache, shared_cache, shared_cache]


def request_json(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    authenticated: bool = False,
) -> dict:
    data = None
    headers = {}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if authenticated:
        headers["Authorization"] = f"Bearer {api_server.API_TOKEN}"

    request = Request(url, data=data, headers=headers, method=method)

    with urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def test_api_exposes_database_lists_and_status(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SIGNALSHIELD_DB_PATH", str(tmp_path / "api.sqlite3"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), api_server.SignalShieldHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"

    try:
        created = request_json(
            f"{base_url}/list-entry",
            method="POST",
            authenticated=True,
            payload={
                "list_type": "trusted",
                "scope": "url",
                "value": "https://api-status.example/pay",
                "label": "test",
            },
        )
        entries = request_json(f"{base_url}/list-entries", authenticated=True)
        status = request_json(f"{base_url}/database/status", authenticated=True)
        removed = request_json(
            f"{base_url}/list-entry?id={created['entry']['id']}",
            method="DELETE",
            authenticated=True,
        )
        entries_after_delete = request_json(f"{base_url}/list-entries", authenticated=True)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert created["ok"] is True
    assert entries["entries"][0]["value"] == "https://api-status.example/pay"
    assert status["status"]["active_entries"]["trusted"] == 1
    assert removed == {"ok": True, "removed": True}
    assert entries_after_delete["entries"] == []


def test_api_analyze_messages_is_public_and_returns_message_results(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SIGNALSHIELD_DB_PATH", str(tmp_path / "api.sqlite3"))

    def fake_analyze_message(message: str, context=None) -> dict:
        return {
            "verdict": "SUSPICIOUS",
            "score": 25,
            "reasons": [f"checked: {message[:8]}"],
            "links": [],
            "details": {"link_count": 0},
        }

    monkeypatch.setattr(api_server, "analyze_message", fake_analyze_message)

    server = ThreadingHTTPServer(("127.0.0.1", 0), api_server.SignalShieldHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"

    try:
        response = request_json(
            f"{base_url}/analyze-messages",
            method="POST",
            payload={
                "page_url": "https://mail.example/inbox",
                "messages": [{"id": "one", "text": "Pilne: payment check"}],
            },
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert response["ok"] is True
    assert response["results"][0]["id"] == "one"
    assert response["results"][0]["result"]["verdict"] == "SUSPICIOUS"
