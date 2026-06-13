import html as html_lib

import streamlit as st

from core.message_analyzer import analyze_message
from core.verdict import (
    VERDICT_DANGEROUS,
    VERDICT_NOT_FOUND,
    VERDICT_SAFE,
    VERDICT_SUSPICIOUS,
    analyze_url,
)


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
        summary_cols[0].metric("Verdict", result.get("verdict", "UNKNOWN"))
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


def render_verdict_banner(result: dict, not_found_label: str = "Page not found") -> None:
    if result["verdict"] == VERDICT_DANGEROUS:
        st.error(f"⛔ {result['verdict']} (risk: {result['score']}%)")
    elif result["verdict"] == VERDICT_SUSPICIOUS:
        st.warning(f"⚠️ {result['verdict']} (risk: {result['score']}%)")
    elif result["verdict"] == VERDICT_NOT_FOUND:
        st.info(not_found_label)
    else:
        st.success(f"✅ {result['verdict']}")


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
        f"This page was classified as {verdict}. It may be phishing, unreachable, "
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
            "Verdict": link.get("verdict", ""),
            "URL risk": f"{link.get('score', 0)}%",
            "Link signs": risk_label(characteristics.get("score", 0)),
        })

    return rows


def render_message_details(result: dict) -> None:
    overview_tab, links_tab, raw_tab = st.tabs(["Overview", "Links", "Raw payload"])
    details = result.get("details", {})
    message_signals = result.get("message_signals", {})

    with overview_tab:
        st.markdown("#### Message summary")
        summary_cols = st.columns(4)
        summary_cols[0].metric("Verdict", result.get("verdict", "UNKNOWN"))
        summary_cols[1].metric("Risk score", f"{result.get('score', 0)}%")
        summary_cols[2].metric("Links found", details.get("link_count", 0))
        summary_cols[3].metric("Domains", len(details.get("unique_domains", [])))

        st.table(table_rows({
            "message_length": details.get("message_length"),
            "unique_domains": details.get("unique_domains"),
            "max_link_score": details.get("max_link_score"),
            "message_signal_score": details.get("message_signal_score"),
            "link_characteristic_score": details.get("link_characteristic_score"),
        }))

        render_stage_section(
            "Message context",
            "Signal found" if message_signals.get("score", 0) else "Clear",
            message_signals.get("score", 0),
            "Looks for social-engineering markers in the whole message.",
            {"total_score": message_signals.get("score", 0)},
            rules=message_signals.get("matched_rules", []),
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
                    f"{index}. {link.get('verdict', 'UNKNOWN')} "
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


st.set_page_config(page_title="SignalShield PL", page_icon="🛡️")

st.title("🛡️ SignalShield PL")
st.subheader("Check financial scam risk before you pay")

query_url = get_query_param("url")
query_mode = get_query_param("mode")
query_auto = get_query_param("auto").lower() in {"1", "true", "yes"}
mode_options = ["Single link", "Full message"]
default_mode_index = 1 if query_mode == "message" else 0

mode = st.radio(
    "Analysis mode",
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
            result = analyze_url(url)

        render_verdict_banner(result)
        render_reasons(result)
        render_open_checked_page(result)

        with st.expander("Technical details", expanded=True):
            render_technical_details(result)

else:
    message = st.text_area(
        "Paste the full SMS, email, or chat message:",
        height=180,
        placeholder=(
            "Pilne: dopłata do paczki 1.99 zł. "
            "Zaloguj się: vasiapupkin.xyz/allegro.pl/pay/blik-secure"
        ),
    )

    if st.button("Analyze message") and message:
        with st.spinner("Analyzing message and all detected links..."):
            result = analyze_message(message)

        render_verdict_banner(result, not_found_label="Message is empty or could not be analyzed")
        render_reasons(result)

        with st.expander("Message analysis details", expanded=True):
            render_message_details(result)

st.divider()
st.caption(
    "Checks: blacklist, subdomain spoofing, page existence, DNS/MX, WHOIS age, "
    "entropy, HTML crawler, URL heuristics, brand similarity, page content rules, "
    "and full-message social engineering signals."
)
