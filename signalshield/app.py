"""Streamlit-интерфейс SignalShield PL."""

import streamlit as st

from core.verdict import analyze_url

st.set_page_config(page_title="SignalShield PL", page_icon="🛡️")

st.title("🛡️ SignalShield PL")
st.subheader("Проверка безопасности ссылок перед оплатой")

url = st.text_input("Вставьте ссылку для проверки:", placeholder="https://example.pl")

if st.button("Проверить") and url:
    with st.spinner("Анализируем..."):
        result = analyze_url(url)

    if result["verdict"] == "ОПАСНО":
        st.error(f"⛔ {result['verdict']} (риск: {result['score']}%)")
    elif result["verdict"] == "ПОДОЗРИТЕЛЬНО":
        st.warning(f"⚠️ {result['verdict']} (риск: {result['score']}%)")
    else:
        st.success(f"✅ {result['verdict']}")

    if result.get("reasons"):
        st.write("**Причины:**")
        for reason in result["reasons"]:
            st.write(f"- {reason}")

    with st.expander("Технические детали"):
        st.json(result)

st.divider()
st.caption(
    "Этап 1: CERT Polska blacklist | Этап 2: WHOIS возраст домена | Этап 3: Алгоритм Левенштейна"
)
