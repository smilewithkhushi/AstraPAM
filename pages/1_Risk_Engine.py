"""AegisPAM — Risk Engine page."""
from __future__ import annotations

import _sidebar
import pandas as pd
import streamlit as st

import risk as risk_engine
from schemas import init_db

st.set_page_config(
    page_title="AegisPAM · Risk Engine",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

# ── sidebar: risk demo controls ───────────────────────────────────────────────
with st.sidebar:
    st.divider()
    st.markdown("**Demo Controls**")
    st.caption("Score a session to see the full output below.")

    if st.button("Score normal session", width="stretch"):
        with st.spinner("Scoring…"):
            st.session_state["last_risk"]     = risk_engine.score(_sidebar.NORMAL_FEATURES)
            st.session_state["last_features"] = _sidebar.NORMAL_FEATURES

    if st.button("Score malicious session", width="stretch"):
        with st.spinner("Scoring…"):
            st.session_state["last_risk"]     = risk_engine.score(_sidebar.MAL_FEATURES)
            st.session_state["last_features"] = _sidebar.MAL_FEATURES

    st.divider()
    if st.button("Refresh", width="stretch"):
        st.rerun()

# ── header ────────────────────────────────────────────────────────────────────
st.title("Risk Engine")
st.markdown(
    "Session-level behavioural anomaly scoring using an LSTM autoencoder trained on the "
    "CERT Insider Threat dataset. Every decision is fully explainable — the score, the "
    "contributing features, and any named attack patterns are surfaced together."
)
st.divider()

# ── risk result ───────────────────────────────────────────────────────────────
r = st.session_state.get("last_risk")

if r is None:
    st.info("Use the demo controls in the sidebar to score a session.")
else:
    color = _sidebar.DECISION_COLOR.get(r.decision, "#555")
    badge = _sidebar.DECISION_BADGE.get(r.decision, r.decision.upper())

    st.markdown(
        f"<div style='background:{color};color:white;padding:12px 20px;"
        f"border-radius:6px;font-size:18px;font-weight:600;text-align:center'>"
        f"{badge}</div>",
        unsafe_allow_html=True,
    )
    st.markdown("")

    m1, m2, m3 = st.columns(3)
    m1.metric("Risk Score",  f"{r.score:.3f}")
    m2.metric("Decision",    r.decision.upper())
    m3.metric("Attack Tags", len(r.attack_tags))

    st.divider()

    # ── attack pattern tags ───────────────────────────────────────────────────
    st.subheader("Attack Pattern Tags")
    st.caption(
        "Rule-based checks on raw session features applied on top of the ML score. "
        "These are not ML outputs — they name the pattern the model responded to."
    )
    if r.attack_tags:
        tag_cols = st.columns(min(len(r.attack_tags), 4))
        for i, tag in enumerate(r.attack_tags):
            tag_cols[i % 4].error(tag)
    else:
        st.success("No attack patterns triggered for this session.")

    st.divider()

    # ── shap explainability ───────────────────────────────────────────────────
    st.subheader("SHAP Feature Attribution")
    st.caption(
        "Each bar shows how much a feature pushed the score up or down. "
        "▲ raises risk · ▼ lowers risk."
    )
    if r.top_factors:
        df_shap = pd.DataFrame([
            {
                "Feature":      f.feature,
                "Contribution": abs(f.contribution),
                "Direction":    "raises risk" if f.contribution > 0 else "lowers risk",
            }
            for f in sorted(r.top_factors, key=lambda x: abs(x.contribution), reverse=True)
        ])
        st.bar_chart(df_shap.set_index("Feature")["Contribution"])
        for f in r.top_factors:
            sign = "▲" if f.contribution > 0 else "▼"
            st.caption(f"{sign} `{f.feature}` → {f.contribution:+.4f}")
    else:
        st.info("No factor data available.")
