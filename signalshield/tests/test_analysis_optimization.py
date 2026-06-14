from core import verdict
from core.analysis_cache import TtlCache
from core.verdict import analyze_url, new_analysis_context


def install_fast_mocks(monkeypatch) -> None:
    monkeypatch.setattr(verdict, "find_list_match", lambda url: None)
    monkeypatch.setattr(verdict, "check_blacklist", lambda url: False)
    monkeypatch.setattr(
        verdict,
        "check_subdomain_spoofing",
        lambda url: {"is_spoofed": False, "reason": "clear"},
    )
    monkeypatch.setattr(
        verdict,
        "check_page_existence",
        lambda url: {"status": "exists", "exists": True, "evidence": []},
    )
    monkeypatch.setattr(
        verdict,
        "check_domain_entropy",
        lambda url: {"score": 0, "flagged": False},
    )
    monkeypatch.setattr(
        verdict,
        "analyze_url_heuristics",
        lambda url, trusted: {"score": 0, "matched_rules": []},
    )
    monkeypatch.setattr(verdict, "run_similarity_check", lambda domain, trusted: [])


def test_shared_context_reuses_domain_level_checks(monkeypatch) -> None:
    install_fast_mocks(monkeypatch)
    calls = {"dns": 0, "age": 0}

    def fake_dns(domain: str, trusted_domains: list[str]) -> dict:
        calls["dns"] += 1
        return {"score": 0, "status": "mx_found"}

    def fake_age(domain: str) -> None:
        calls["age"] += 1
        return None

    monkeypatch.setattr(verdict, "analyze_dns_infrastructure", fake_dns)
    monkeypatch.setattr(verdict, "get_domain_age", fake_age)
    monkeypatch.setattr(
        verdict,
        "analyze_html_crawling",
        lambda url, trusted, html=None, fetch_error=None: {"score": 0, "matched_rules": []},
    )
    monkeypatch.setattr(
        verdict,
        "analyze_page_rules",
        lambda url, html=None, fetch_error=None: {
            "score": 0,
            "hard_block": False,
            "matched_rules": [],
        },
    )
    monkeypatch.setattr(verdict, "fetch_page_for_rules", lambda url: ("<html></html>", None))

    context = new_analysis_context()
    analyze_url("https://repeat-example.pl/first", context=context)
    analyze_url("https://repeat-example.pl/second", context=context)

    assert calls["dns"] == 1
    assert calls["age"] == 1


def test_html_fetch_is_shared_by_content_analyzers(monkeypatch) -> None:
    install_fast_mocks(monkeypatch)
    calls = {"fetch": 0, "crawler": 0, "page_rules": 0}

    monkeypatch.setattr(
        verdict,
        "analyze_dns_infrastructure",
        lambda domain, trusted: {"score": 0, "status": "mx_found"},
    )
    monkeypatch.setattr(verdict, "get_domain_age", lambda domain: None)

    def fake_fetch(url: str) -> tuple[str, None]:
        calls["fetch"] += 1
        return "<html><body>hello</body></html>", None

    def fake_crawler(url: str, trusted: list[str], html=None, fetch_error=None) -> dict:
        calls["crawler"] += 1
        assert html == "<html><body>hello</body></html>"
        assert fetch_error is None
        return {"score": 0, "matched_rules": []}

    def fake_page_rules(url: str, html=None, fetch_error=None) -> dict:
        calls["page_rules"] += 1
        assert html == "<html><body>hello</body></html>"
        assert fetch_error is None
        return {"score": 0, "hard_block": False, "matched_rules": []}

    monkeypatch.setattr(verdict, "fetch_page_for_rules", fake_fetch)
    monkeypatch.setattr(verdict, "analyze_html_crawling", fake_crawler)
    monkeypatch.setattr(verdict, "analyze_page_rules", fake_page_rules)

    analyze_url("https://single-fetch-example.pl/login", context=new_analysis_context())

    assert calls == {"fetch": 1, "crawler": 1, "page_rules": 1}


def test_shared_cache_reuses_dns_between_contexts(monkeypatch) -> None:
    install_fast_mocks(monkeypatch)
    shared_cache = TtlCache()
    calls = {"dns": 0}

    def fake_dns(domain: str, trusted_domains: list[str]) -> dict:
        calls["dns"] += 1
        return {"score": 0, "status": "mx_found"}

    monkeypatch.setattr(verdict, "analyze_dns_infrastructure", fake_dns)
    monkeypatch.setattr(verdict, "get_domain_age", lambda domain: None)
    monkeypatch.setattr(verdict, "analyze_html_crawling", None)
    monkeypatch.setattr(verdict, "analyze_page_rules", None)

    analyze_url(
        "https://shared-cache-example.pl/first",
        context=new_analysis_context(shared_cache=shared_cache),
    )
    analyze_url(
        "https://shared-cache-example.pl/second",
        context=new_analysis_context(shared_cache=shared_cache),
    )

    assert calls["dns"] == 1


def test_shared_cache_reuses_html_fetch_between_contexts(monkeypatch) -> None:
    install_fast_mocks(monkeypatch)
    shared_cache = TtlCache()
    calls = {"fetch": 0, "crawler": 0, "page_rules": 0}

    monkeypatch.setattr(
        verdict,
        "analyze_dns_infrastructure",
        lambda domain, trusted: {"score": 0, "status": "mx_found"},
    )
    monkeypatch.setattr(verdict, "get_domain_age", lambda domain: None)

    def fake_fetch(url: str) -> tuple[str, None]:
        calls["fetch"] += 1
        return "<html><body>hello</body></html>", None

    def fake_crawler(url: str, trusted: list[str], html=None, fetch_error=None) -> dict:
        calls["crawler"] += 1
        assert html == "<html><body>hello</body></html>"
        assert fetch_error is None
        return {"score": 0, "matched_rules": []}

    def fake_page_rules(url: str, html=None, fetch_error=None) -> dict:
        calls["page_rules"] += 1
        assert html == "<html><body>hello</body></html>"
        assert fetch_error is None
        return {"score": 0, "hard_block": False, "matched_rules": []}

    monkeypatch.setattr(verdict, "fetch_page_for_rules", fake_fetch)
    monkeypatch.setattr(verdict, "analyze_html_crawling", fake_crawler)
    monkeypatch.setattr(verdict, "analyze_page_rules", fake_page_rules)

    for _ in range(2):
        analyze_url(
            "https://shared-html-example.pl/login",
            context=new_analysis_context(shared_cache=shared_cache),
        )

    assert calls == {"fetch": 1, "crawler": 2, "page_rules": 2}


def test_local_list_match_is_not_shared_cached(monkeypatch) -> None:
    install_fast_mocks(monkeypatch)
    shared_cache = TtlCache()
    calls = {"local_list": 0}

    monkeypatch.setattr(
        verdict,
        "analyze_dns_infrastructure",
        lambda domain, trusted: {"score": 0, "status": "mx_found"},
    )
    monkeypatch.setattr(verdict, "get_domain_age", lambda domain: None)
    monkeypatch.setattr(verdict, "analyze_html_crawling", None)
    monkeypatch.setattr(verdict, "analyze_page_rules", None)

    def fake_list_match(url: str) -> dict | None:
        calls["local_list"] += 1

        if calls["local_list"] == 2:
            return {
                "list_type": verdict.LIST_TRUSTED,
                "scope": "url",
                "value": url,
            }

        return None

    monkeypatch.setattr(verdict, "find_list_match", fake_list_match)

    first = analyze_url(
        "https://fresh-local-list-example.pl/login",
        context=new_analysis_context(shared_cache=shared_cache),
    )
    second = analyze_url(
        "https://fresh-local-list-example.pl/login",
        context=new_analysis_context(shared_cache=shared_cache),
    )

    assert calls["local_list"] == 2
    assert first["verdict"] == verdict.VERDICT_SAFE
    assert second["verdict"] == verdict.VERDICT_TRUSTED_BY_USER
