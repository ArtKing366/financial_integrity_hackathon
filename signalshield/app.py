import html as html_lib

import streamlit as st

from core.analysis_cache import TtlCache
from core.local_db import (
    LIST_BLACKLIST,
    LIST_TRUSTED,
    SCOPE_DOMAIN,
    SCOPE_URL,
    add_list_entry,
    database_status,
    deactivate_list_entry,
    expiry_from_choice,
    list_entries,
    recent_scan_events,
    record_scan_event,
    sync_builtin_lists,
    summarize_page_domains,
    summarize_verdicts,
)
from core.message_analyzer import analyze_message
from core.verdict import (
    VERDICT_DANGEROUS,
    VERDICT_NOT_FOUND,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    analyze_url,
    new_analysis_context,
)


VERDICT_TRUSTED_BY_USER = "TRUSTED_BY_USER"
VERDICT_LABELS = {
    VERDICT_DANGEROUS: "Dangerous",
    VERDICT_SUSPICIOUS: "Suspicious",
    VERDICT_SAFE: "Safe",
    VERDICT_NOT_FOUND: "This link does not appear to exist",
    VERDICT_TRUSTED_BY_USER: "Trusted by user",
}


def get_analysis_cache() -> TtlCache:
    if "analysis_cache" not in st.session_state:
        st.session_state["analysis_cache"] = TtlCache(max_entries=4096)

    return st.session_state["analysis_cache"]


def make_analysis_context() -> dict:
    return new_analysis_context(shared_cache=get_analysis_cache())


@st.cache_resource
def ensure_builtin_lists_synced() -> dict:
    return sync_builtin_lists()


def format_value(value) -> str:
    if value is None:
        return "Not available"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float):
        return f"{value:.2f}"
    if isinstance(value, list):
        return ", ".join(format_value(item) for item in value) if value else "None"
    if isinstance(value, dict):
        return ", ".join(f"{key}: {format_value(item)}" for key, item in value.items())
    return str(value)


def verdict_label(verdict: str) -> str:
    return VERDICT_LABELS.get(str(verdict or "").upper(), str(verdict or "Unknown").replace("_", " ").title())


def table_rows(data: dict) -> list[dict[str, str]]:
    return [
        {"Field": key.replace("_", " ").title(), "Value": format_value(value)}
        for key, value in data.items()
        if value not in (None, "", [], {})
    ]


def risk_label(score: int | float | None) -> str:
    if not score:
        return "+0"
    return f"+{int(score)}"


def stage_state(score: int | float | None, default: str = "Clear") -> str:
    return "Signal found" if score else default


def whois_age_status(age_days: int | None) -> tuple[str, int]:
    if age_days is None:
        return "Unknown", 0
    if age_days < 14:
        return "Very new", 40
    if age_days < 90:
        return "New", 15
    return "Established", 0


def render_rule_list(rules: list[dict]) -> None:
    if not rules:
        return

    st.markdown("**Matched rules**")
    for rule in rules:
        rule_id = rule.get("id", "rule")
        score = risk_label(rule.get("score", 0))
        description = rule.get("description", "")
        severity = rule.get("severity")
        label = f"`{rule_id}` ({score})"
        if severity:
            label += f" - {severity}"
        st.markdown(f"- **{label}**: {description}")

        matches = rule.get("matches")
        if matches:
            st.caption(f"Matches: {format_value(matches)}")


def render_evidence_list(title: str, evidence: list[str] | None) -> None:
    if not evidence:
        return

    st.markdown(f"**{title}**")
    for item in evidence:
        st.markdown(f"- {item}")


def render_stage_section(
    title: str,
    status: str,
    score: int | float | None,
    summary: str,
    facts: dict | None = None,
    rules: list[dict] | None = None,
    evidence: list[str] | None = None,
) -> None:
    st.markdown(f"#### {title}")
    status_col, risk_col = st.columns(2)
    status_col.metric("Status", status)
    risk_col.metric("Risk added", risk_label(score))

    if summary:
        st.caption(summary)

    rows = table_rows(facts or {})
    if rows:
        st.table(rows)

    render_rule_list(rules or [])
    render_evidence_list("Evidence", evidence)
    st.divider()


def build_overview_rows(result: dict) -> list[dict[str, str]]:
    details = result.get("details", {})
    rows = []

    local_match = details.get("local_list_match")
    if isinstance(local_match, dict):
        rows.append({
            "Check": "Local list",
            "Status": local_match.get("list_type", "matched"),
            "Risk": "+100" if local_match.get("list_type") == LIST_BLACKLIST else "+0",
            "Meaning": (
                f"{local_match.get('scope')} match: {local_match.get('value')}. "
                f"Original verdict: {format_value(details.get('original_verdict'))}."
            ),
        })

    blacklist_match = details.get("blacklist_match")
    rows.append({
        "Check": "CERT blacklist",
        "Status": "Listed" if blacklist_match else "Clear",
        "Risk": "+100" if blacklist_match else "+0",
        "Meaning": "Known phishing domain match." if blacklist_match else "No blacklist match.",
    })

    subdomain = details.get("subdomain_spoofing")
    if isinstance(subdomain, dict):
        rows.append({
            "Check": "Subdomain spoofing",
            "Status": "Signal found" if subdomain.get("is_spoofed") else "Clear",
            "Risk": "+80" if subdomain.get("is_spoofed") else "+0",
            "Meaning": subdomain.get("reason", ""),
        })

    page = details.get("page_existence")
    if isinstance(page, dict):
        page_score = 10 if page.get("status") == "unreachable" else 0
        rows.append({
            "Check": "Page existence",
            "Status": page.get("status", "unknown"),
            "Risk": risk_label(page_score),
            "Meaning": format_value(page.get("evidence", [])),
        })

    dns = details.get("dns_infrastructure")
    if isinstance(dns, dict):
        rows.append({
            "Check": "DNS / MX",
            "Status": dns.get("status", "unknown"),
            "Risk": risk_label(dns.get("score", 0)),
            "Meaning": dns.get("description", "") or "No DNS infrastructure risk added.",
        })

    age_days = details.get("domain_age_days")
    age_status, age_score = whois_age_status(age_days)
    rows.append({
        "Check": "WHOIS age",
        "Status": age_status,
        "Risk": risk_label(age_score),
        "Meaning": f"Domain age: {format_value(age_days)} days.",
    })

    entropy = details.get("domain_entropy")
    if isinstance(entropy, dict):
        rows.append({
            "Check": "Domain entropy",
            "Status": stage_state(entropy.get("score", 0)),
            "Risk": risk_label(entropy.get("score", 0)),
            "Meaning": entropy.get("description", "") or "Domain name does not look random.",
        })

    html = details.get("html_crawling")
    if isinstance(html, dict):
        rows.append({
            "Check": "HTML crawler",
            "Status": stage_state(html.get("score", 0), "No page signal"),
            "Risk": risk_label(html.get("score", 0)),
            "Meaning": "Password fields or sensitive markers found."
            if html.get("score", 0)
            else html.get("fetch_error") or "No risky HTML markers found.",
        })

    heuristics = details.get("url_heuristics")
    if isinstance(heuristics, dict):
        rows.append({
            "Check": "URL heuristics",
            "Status": stage_state(heuristics.get("score", 0)),
            "Risk": risk_label(heuristics.get("score", 0)),
            "Meaning": "Suspicious path keywords or domain shape."
            if heuristics.get("score", 0)
            else "URL shape looks normal.",
        })

    similarity = details.get("similarity_results", [])
    rows.append({
        "Check": "Brand similarity",
        "Status": "Signal found" if similarity else "Clear",
        "Risk": "+60" if similarity else "+0",
        "Meaning": format_value(similarity[:3]) if similarity else "No close trusted-brand match.",
    })

    page_rules = details.get("page_rules")
    if isinstance(page_rules, dict):
        rows.append({
            "Check": "Page content rules",
            "Status": "Hard block" if page_rules.get("hard_block") else stage_state(page_rules.get("score", 0)),
            "Risk": risk_label(page_rules.get("score", 0)),
            "Meaning": page_rules.get("fetch_error") or "Content rules evaluated.",
        })

    return rows


def render_technical_details(result: dict) -> None:
    details = result.get("details", {})
    overview_tab, evidence_tab, raw_tab = st.tabs(["Overview", "Evidence", "Raw payload"])

    with overview_tab:
        st.markdown("#### Decision summary")
        summary_cols = st.columns(3)
        summary_cols[0].metric("Verdict", verdict_label(result.get("verdict", "UNKNOWN")))
        summary_cols[1].metric("Risk score", f"{result.get('score', 0)}%")
        summary_cols[2].metric("Reasons", len(result.get("reasons", [])))

        st.table(table_rows({
            "input_url": details.get("input_url"),
            "hostname": details.get("hostname"),
            "registered_domain": details.get("domain"),
        }))

        st.markdown("#### Check overview")
        st.table(build_overview_rows(result))

    with evidence_tab:
        render_stage_section(
            "CERT blacklist",
            "Listed" if details.get("blacklist_match") else "Clear",
            100 if details.get("blacklist_match") else 0,
            "Checks whether the registered domain appears on the CERT Polska phishing list.",
            {"blacklist_match": details.get("blacklist_match")},
        )

        subdomain = details.get("subdomain_spoofing")
        if isinstance(subdomain, dict):
            render_stage_section(
                "Subdomain spoofing",
                "Signal found" if subdomain.get("is_spoofed") else "Clear",
                80 if subdomain.get("is_spoofed") else 0,
                subdomain.get("reason", ""),
                subdomain,
            )

        page = details.get("page_existence")
        if isinstance(page, dict):
            render_stage_section(
                "Page existence",
                page.get("status", "unknown"),
                10 if page.get("status") == "unreachable" else 0,
                "Checks DNS and HTTP response evidence without overriding stronger phishing signals.",
                {
                    "exists": page.get("exists"),
                    "domain_exists": page.get("domain_exists"),
                    "http_status": page.get("http_status"),
                    "final_url": page.get("final_url"),
                    "confidence": page.get("confidence"),
                    "error": page.get("error"),
                },
                evidence=page.get("evidence", []),
            )

        dns = details.get("dns_infrastructure")
        if isinstance(dns, dict):
            render_stage_section(
                "DNS / MX infrastructure",
                dns.get("status", "unknown"),
                dns.get("score", 0),
                dns.get("description", "") or "Checks whether an untrusted domain has mail infrastructure.",
                dns,
            )

        age_status, age_score = whois_age_status(details.get("domain_age_days"))
        render_stage_section(
            "WHOIS domain age",
            age_status,
            age_score,
            "Very new domains are riskier when WHOIS data is available.",
            {
                "domain_age_days": details.get("domain_age_days"),
                "whois_status": details.get("whois_status"),
            },
        )

        entropy = details.get("domain_entropy")
        if isinstance(entropy, dict):
            render_stage_section(
                "Domain entropy",
                "Signal found" if entropy.get("flagged") else "Clear",
                entropy.get("score", 0),
                entropy.get("description", "") or "Checks whether the domain looks randomly generated.",
                entropy,
            )

        html = details.get("html_crawling")
        if isinstance(html, dict):
            render_stage_section(
                "HTML crawler",
                "Signal found" if html.get("score", 0) else "No signal",
                html.get("score", 0),
                html.get("fetch_error") or "Quickly scans downloaded HTML for risky login/payment markers.",
                {
                    "trusted_domain": html.get("trusted_domain"),
                    "password_field_count": html.get("password_field_count"),
                    "hidden_password_field_count": html.get("hidden_password_field_count"),
                    "matched_markers": html.get("matched_markers"),
                    "fetch_error": html.get("fetch_error"),
                },
                rules=html.get("matched_rules", []),
            )

        heuristics = details.get("url_heuristics")
        if isinstance(heuristics, dict):
            render_stage_section(
                "URL heuristics",
                "Signal found" if heuristics.get("score", 0) else "Clear",
                heuristics.get("score", 0),
                "Looks for risky path keywords and long or hyphen-heavy domains.",
                {"total_score": heuristics.get("score", 0), "error": heuristics.get("error")},
                rules=heuristics.get("matched_rules", []),
            )

        similarity = details.get("similarity_results", [])
        render_stage_section(
            "Brand similarity",
            "Signal found" if similarity else "Clear",
            60 if similarity else 0,
            "Compares the registered domain against trusted brands.",
            {"top_matches": similarity[:5]},
        )

        page_rules = details.get("page_rules")
        if isinstance(page_rules, dict):
            render_stage_section(
                "Page content rules",
                "Hard block" if page_rules.get("hard_block") else stage_state(page_rules.get("score", 0)),
                page_rules.get("score", 0),
                page_rules.get("fetch_error") or "Scans page content for known credential-theft patterns.",
                {
                    "hard_block": page_rules.get("hard_block"),
                    "fetch_error": page_rules.get("fetch_error"),
                },
                rules=page_rules.get("matched_rules", []),
            )

    with raw_tab:
        st.caption("Raw analyzer payload is kept here for debugging.")
        st.json(result)


def render_verdict_banner(result: dict, not_found_label: str = "This link does not appear to exist") -> None:
    if result["verdict"] == VERDICT_DANGEROUS:
        st.error(f"{verdict_label(result['verdict'])} (risk: {result['score']}%)")
    elif result["verdict"] == VERDICT_SUSPICIOUS:
        st.warning(f"{verdict_label(result['verdict'])} (risk: {result['score']}%)")
    elif result["verdict"] == VERDICT_TRUSTED_BY_USER:
        st.info(f"{verdict_label(result['verdict'])} (original risk: {result['score']}%)")
    elif result["verdict"] == VERDICT_NOT_FOUND:
        st.info(not_found_label)
    else:
        st.success(f"{verdict_label(result['verdict'])}")


def render_external_link_button(label: str, url: str, button_type: str = "primary") -> None:
    safe_url = html_lib.escape(url, quote=True)
    safe_label = html_lib.escape(label)
    background = "#111827" if button_type == "primary" else "#334155"

    st.markdown(
        (
            f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer" data-ss-ignore="1" '
            'data-signalshield-ignore="1" class="ss-navigation-link" '
            'style="display:inline-block;padding:0.5rem 0.85rem;'
            f'border-radius:0.45rem;background:{background};color:white;'
            'text-decoration:none;font-weight:700;">'
            f"{safe_label}</a>"
        ),
        unsafe_allow_html=True,
    )


def clear_pending_navigation() -> None:
    st.session_state.pop("pending_navigation_url", None)
    st.session_state.pop("pending_navigation_verdict", None)


def rerun_app() -> None:
    if hasattr(st, "rerun"):
        st.rerun()
    else:
        st.experimental_rerun()


def render_navigation_warning(url: str, verdict: str) -> None:
    warning_text = (
        f"This page was classified as {verdict_label(verdict)}. It may be phishing, unreachable, "
        "or otherwise unsafe. Open it only if you trust the destination."
    )

    if hasattr(st, "dialog"):
        @st.dialog("Open checked page?")
        def warning_dialog() -> None:
            st.warning(warning_text)
            st.caption(url)
            render_external_link_button("Open anyway", url)
            if st.button("Cancel"):
                clear_pending_navigation()
                rerun_app()

        warning_dialog()
        return

    st.warning(warning_text)
    st.caption(url)
    render_external_link_button("Open anyway", url)


def render_open_checked_page(result: dict) -> None:
    details = result.get("details", {})
    target_url = details.get("input_url")

    if not target_url:
        return

    verdict = result.get("verdict", "")

    if verdict == VERDICT_SAFE:
        render_external_link_button("Open checked page", target_url)
        return

    if st.button("Open checked page"):
        st.session_state["pending_navigation_url"] = target_url
        st.session_state["pending_navigation_verdict"] = verdict

    if st.session_state.get("pending_navigation_url") == target_url:
        render_navigation_warning(
            st.session_state["pending_navigation_url"],
            st.session_state.get("pending_navigation_verdict", verdict),
        )


def scope_from_label(label: str) -> str:
    return SCOPE_URL if label == "Exact URL" else SCOPE_DOMAIN


def value_for_scope(url: str, hostname: str, scope: str) -> str:
    return url if scope == SCOPE_URL else hostname


def render_result_list_actions(result: dict) -> None:
    details = result.get("details", {})
    target_url = details.get("input_url", "")
    hostname = details.get("hostname", "")

    if not target_url or not hostname:
        return

    with st.expander("Local list action"):
        if result.get("verdict") in {VERDICT_DANGEROUS, VERDICT_SUSPICIOUS}:
            st.warning(
                "Adding a risky site to the trusted list makes it blue, "
                "but the original risk remains visible in technical details."
            )

        with st.form("result_list_action"):
            action = st.radio(
                "Action",
                ["Trust this target", "Block this target"],
                horizontal=True,
            )
            scope_label = st.radio(
                "Scope",
                ["Exact URL", "Exact hostname"],
                horizontal=True,
            )
            expiry_choice = st.selectbox(
                "Expires",
                ["Never", "24 hours", "7 days", "30 days"],
                index=0,
            )
            note = st.text_input("Note", placeholder="Optional reason")
            submitted = st.form_submit_button("Save to local list")

        if submitted:
            scope = scope_from_label(scope_label)
            list_type = LIST_TRUSTED if action == "Trust this target" else LIST_BLACKLIST
            value = value_for_scope(target_url, hostname, scope)
            entry = add_list_entry(
                list_type,
                scope,
                value,
                label=action,
                note=note,
                expires_at=expiry_from_choice(expiry_choice),
            )
            st.success(f"Saved {entry['list_type']} entry: {entry['scope']} {entry['value']}")


def list_type_label(list_type: str) -> str:
    if list_type == LIST_BLACKLIST:
        return "Blacklist"
    return "Trusted list"


def render_lists_page() -> None:
    st.header("Local lists")
    st.caption("Entries match only exact URLs or exact hostnames. Subdomains are not trusted automatically.")
    sync_summary = ensure_builtin_lists_synced()
    status = database_status()
    st.caption(f"SQLite database: {status['db_path']}")
    st.caption(
        "Built-in lists synced: "
        f"CERT {sync_summary['cert_polska']['available']} domains, "
        f"trusted brands {sync_summary['trusted_brands']['available']} domains."
    )

    list_cols = st.columns(5)
    list_cols[0].metric("User entries", status["user_entries"]["total"])
    list_cols[1].metric("User trusted", status["user_entries"].get(LIST_TRUSTED, 0))
    list_cols[2].metric("User blocked", status["user_entries"].get(LIST_BLACKLIST, 0))
    list_cols[3].metric("System entries", status["managed_entries"]["total"])
    list_cols[4].metric("Exact URLs", status["active_scopes"].get(SCOPE_URL, 0))

    with st.form("manual_list_entry"):
        list_label = st.radio(
            "List",
            ["Trusted list", "Blacklist"],
            horizontal=True,
        )
        scope_label = st.radio(
            "Scope",
            ["Exact URL", "Exact hostname"],
            horizontal=True,
        )
        value = st.text_input("URL or hostname")
        expiry_choice = st.selectbox(
            "Expires",
            ["Never", "24 hours", "7 days", "30 days"],
            index=0,
        )
        note = st.text_input("Note", placeholder="Optional reason")
        submitted = st.form_submit_button("Add entry")

    if submitted:
        list_type = LIST_TRUSTED if list_label == "Trusted list" else LIST_BLACKLIST
        entry = add_list_entry(
            list_type,
            scope_from_label(scope_label),
            value,
            label=list_label,
            note=note,
            expires_at=expiry_from_choice(expiry_choice),
        )
        st.success(f"Saved {entry['list_type']} entry: {entry['scope']} {entry['value']}")

    entries = list_entries()

    if not entries:
        st.info("No local list entries yet.")
        return

    st.markdown("#### Active entries")
    st.dataframe(
        [
            {
                "id": entry["id"],
                "list": list_type_label(entry["list_type"]),
                "scope": entry["scope"],
                "value": entry["value"],
                "expires_at": entry.get("expires_at") or "Never",
                "note": entry.get("note", ""),
            }
            for entry in entries
        ],
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("#### Remove entry")
    entry_options = {
        f"{entry['id']} - {list_type_label(entry['list_type'])}: {entry['scope']} {entry['value']}": entry["id"]
        for entry in entries
    }
    selected = st.selectbox("Entry", list(entry_options.keys()))

    if st.button("Deactivate selected entry"):
        deactivate_list_entry(entry_options[selected])
        st.success("Entry deactivated.")
        rerun_app()


def render_analytics_page() -> None:
    st.header("Service analytics")
    ensure_builtin_lists_synced()
    status = database_status()
    st.caption(f"SQLite database: {status['db_path']}")

    verdicts = summarize_verdicts()
    total = sum(verdicts.values())
    metric_cols = st.columns(6)
    metric_cols[0].metric("Checked links", total)
    metric_cols[1].metric("Dangerous", verdicts.get(VERDICT_DANGEROUS, 0))
    metric_cols[2].metric("Suspicious", verdicts.get(VERDICT_SUSPICIOUS, 0))
    metric_cols[3].metric("Safe", verdicts.get(VERDICT_SAFE, 0))
    metric_cols[4].metric("Does not exist", verdicts.get(VERDICT_NOT_FOUND, 0))
    metric_cols[5].metric("Trusted", verdicts.get(VERDICT_TRUSTED_BY_USER, 0))

    db_cols = st.columns(3)
    db_cols[0].metric("Page domains", status["scan_events"]["page_domains"])
    db_cols[1].metric("User list entries", status["user_entries"]["total"])
    db_cols[2].metric("Last scan", status["scan_events"]["last_seen"] or "None")

    page_rows = summarize_page_domains()
    st.markdown("#### Page domains")
    if page_rows:
        st.dataframe(page_rows, use_container_width=True, hide_index=True)
    else:
        st.info("No scan events recorded yet.")

    recent_rows = recent_scan_events(100)
    st.markdown("#### Recent checks")
    if recent_rows:
        st.dataframe(
            [
                {
                    "created_at": row["created_at"],
                    "page_domain": row["page_domain"] or "manual",
                    "target_domain": row["target_domain"],
                    "verdict": row["verdict"],
                    "score": row["score"],
                    "source": row["source"],
                    "target_url": row["target_url"],
                }
                for row in recent_rows
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No recent checks yet.")


def render_reasons(result: dict) -> None:
    if not result.get("reasons"):
        return

    st.write("**Reasons:**")
    for reason in result["reasons"]:
        st.write(f"- {reason}")


def message_link_rows(result: dict) -> list[dict[str, str]]:
    rows = []

    for index, link in enumerate(result.get("links", []), start=1):
        characteristics = link.get("characteristics", {})
        rows.append({
            "#": str(index),
            "URL": link.get("url", ""),
            "Domain": characteristics.get("registered_domain", ""),
            "Verdict": verdict_label(link.get("verdict", "")),
            "URL risk": f"{link.get('score', 0)}%",
            "Link signs": risk_label(characteristics.get("score", 0)),
        })

    return rows


def render_message_details(result: dict) -> None:
    overview_tab, links_tab, raw_tab = st.tabs(["Overview", "Links", "Raw payload"])
    details = result.get("details", {})
    message_signals = result.get("message_signals", {})
    email_authenticity = result.get("email_authenticity", {})
    market_manipulation = result.get("market_manipulation", {})

    with overview_tab:
        st.markdown("#### Message summary")
        summary_cols = st.columns(4)
        summary_cols[0].metric("Verdict", verdict_label(result.get("verdict", "UNKNOWN")))
        summary_cols[1].metric("Risk score", f"{result.get('score', 0)}%")
        summary_cols[2].metric("Links found", details.get("link_count", 0))
        summary_cols[3].metric("Domains", len(details.get("unique_domains", [])))

        st.table(table_rows({
            "message_length": details.get("message_length"),
            "unique_domains": details.get("unique_domains"),
            "max_link_score": details.get("max_link_score"),
            "message_signal_score": details.get("message_signal_score"),
            "email_authenticity_score": details.get("email_authenticity_score"),
            "market_manipulation_score": details.get("market_manipulation_score"),
            "link_characteristic_score": details.get("link_characteristic_score"),
            "not_found_link_count": details.get("not_found_link_count"),
        }))

        render_stage_section(
            "Message context",
            "Signal found" if message_signals.get("score", 0) else "Clear",
            message_signals.get("score", 0),
            "Looks for social-engineering markers in the whole message.",
            {"total_score": message_signals.get("score", 0)},
            rules=message_signals.get("matched_rules", []),
        )

        if email_authenticity:
            render_stage_section(
                "Email authenticity",
                "Signal found" if email_authenticity.get("score", 0) else "Clear",
                email_authenticity.get("score", 0),
                "Checks visible email headers for SPF, DKIM, DMARC, and sender-domain mismatches.",
                {
                    "auth_results": email_authenticity.get("auth_results"),
                    "domains": email_authenticity.get("domains"),
                    "headers": email_authenticity.get("headers"),
                },
                rules=email_authenticity.get("matched_rules", []),
            )

        if market_manipulation:
            render_stage_section(
                "Market manipulation",
                market_manipulation.get("status", "SAFE"),
                market_manipulation.get("score", 0),
                "Looks for pump-and-dump, unrealistic return, insider-tip, and signal-group language.",
                {"matched_rules": market_manipulation.get("matched_rules", [])},
                evidence=market_manipulation.get("reasons", []),
            )

        rows = message_link_rows(result)
        if rows:
            st.markdown("#### Link overview")
            st.table(rows)
        else:
            st.info("No links were found in the message.")

    with links_tab:
        links = result.get("links", [])

        if not links:
            st.info("No links to inspect.")
        else:
            for index, link in enumerate(links, start=1):
                title = (
                    f"{index}. {verdict_label(link.get('verdict', 'UNKNOWN'))} "
                    f"({link.get('score', 0)}%) - {link.get('url', '')}"
                )
                with st.expander(title):
                    characteristics = link.get("characteristics", {})
                    st.markdown("#### Link characteristics")
                    st.table(table_rows({
                        "original": link.get("original"),
                        "normalized_url": link.get("url"),
                        "hostname": characteristics.get("hostname"),
                        "registered_domain": characteristics.get("registered_domain"),
                        "uses_https": characteristics.get("uses_https"),
                        "is_shortener": characteristics.get("is_shortener"),
                        "is_ip_host": characteristics.get("is_ip_host"),
                        "has_userinfo_trick": characteristics.get("has_userinfo_trick"),
                        "tld": characteristics.get("tld"),
                        "characteristic_score": characteristics.get("score"),
                    }))
                    render_rule_list(characteristics.get("matched_rules", []))

                    if link.get("reasons"):
                        st.markdown("#### URL verdict reasons")
                        for reason in link["reasons"]:
                            st.markdown(f"- {reason}")

                    st.markdown("#### URL analysis details")
                    render_technical_details(link.get("analysis", {}))

    with raw_tab:
        st.caption("Raw message analyzer payload is kept here for debugging.")
        st.json(result)


def get_query_param(name: str, default: str = "") -> str:
    try:
        value = st.query_params.get(name, default)
    except Exception:
        values = st.experimental_get_query_params().get(name, [default])
        value = values[0] if values else default

    if isinstance(value, list):
        return value[0] if value else default

    return value or default


st.set_page_config(page_title="SignalShield PL")

st.title("SignalShield PL")
st.subheader("Check financial scam risk before you pay")

query_url = get_query_param("url")
query_message = get_query_param("message")
query_mode = get_query_param("mode")
query_auto = get_query_param("auto").lower() in {"1", "true", "yes"}
mode_options = ["Single link", "Full message", "Lists", "Analytics"]
default_mode_index = 1 if query_mode == "message" else 0

if query_mode == "lists":
    default_mode_index = 2
elif query_mode == "analytics":
    default_mode_index = 3

mode = st.radio(
    "View",
    mode_options,
    index=default_mode_index,
    horizontal=True,
)

if mode == "Single link":
    url = st.text_input(
        "Paste a link to analyze:",
        value=query_url,
        placeholder="https://example.pl",
    )
    should_analyze_link = st.button("Analyze link") or bool(query_url and query_auto)

    if should_analyze_link and url:
        with st.spinner("Analyzing link..."):
            result = analyze_url(url, context=make_analysis_context())
            record_scan_event(url, result, source="streamlit")

        render_verdict_banner(result)
        render_reasons(result)
        render_open_checked_page(result)
        render_result_list_actions(result)

        with st.expander("Technical details", expanded=True):
            render_technical_details(result)

elif mode == "Full message":
    message = st.text_area(
        "Paste the full SMS, email, or chat message:",
        height=180,
        value=query_message,
        placeholder=(
            "Pilne: dopłata do paczki 1.99 zł. "
            "Zaloguj się: vasiapupkin.xyz/allegro.pl/pay/blik-secure"
        ),
    )

    if (st.button("Analyze message") or bool(query_message and query_auto)) and message:
        with st.spinner("Analyzing message and all detected links..."):
            result = analyze_message(message, context=make_analysis_context())
            for link in result.get("links", []):
                record_scan_event(
                    link.get("url", ""),
                    link.get("analysis", link),
                    source="streamlit_message",
                )

        render_verdict_banner(result, not_found_label="This message is empty or could not be analyzed")
        render_reasons(result)

        with st.expander("Message analysis details", expanded=True):
            render_message_details(result)

elif mode == "Lists":
    render_lists_page()

else:
    render_analytics_page()

st.divider()
st.caption(
    "Checks: blacklist, subdomain spoofing, page existence, DNS/MX, WHOIS age, "
    "entropy, HTML crawler, URL heuristics, brand similarity, page content rules, "
    "and full-message social engineering signals."
)
