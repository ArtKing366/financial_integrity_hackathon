import streamlit as st

from core.verdict import VERDICT_DANGEROUS, VERDICT_SAFE, VERDICT_SUSPICIOUS, analyze_url

st.set_page_config(page_title="SignalShield PL", page_icon="🛡️")

st.title("🛡️ SignalShield PL")
st.subheader("Check link safety before you pay")

url = st.text_input("Paste a link to analyze:", placeholder="https://example.pl")

if st.button("Analyze") and url:
    with st.spinner("Analyzing..."):
        result = analyze_url(url)

    if result["verdict"] == VERDICT_DANGEROUS:
        st.error(f"⛔ {result['verdict']} (risk: {result['score']}%)")
    elif result["verdict"] == VERDICT_SUSPICIOUS:
        st.warning(f"⚠️ {result['verdict']} (risk: {result['score']}%)")
    else:
        st.success(f"✅ {result['verdict']}")

    if result.get("reasons"):
        st.write("**Reasons:**")
        for reason in result["reasons"]:
            st.write(f"- {reason}")

    with st.expander("Technical details"):
        st.json(result)

st.divider()
st.caption(
    "Stage 1: CERT Polska blacklist | Stage 2: WHOIS domain age | Stage 3: Levenshtein similarity"
)
