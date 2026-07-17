"""AstraPAM — Reconciliation page."""
from __future__ import annotations

import _sidebar
import httpx
import streamlit as st

import reconcile
from schemas import init_db

st.set_page_config(
    page_title="AstraPAM · Reconciliation",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

with st.sidebar:
    st.divider()
    if st.button("↺ Refresh", use_container_width=True):
        st.rerun()

# ── header ────────────────────────────────────────────────────────────────────
_sidebar.render_navbar("Reconciliation")
_sidebar.render_page_header(
    "🔍", "Cross-Channel Ledger Reconciliation",
    "Every privileged financial action recorded in AstraPAM is compared against the core-banking ledger in real time. If no matching CBS entry exists within the configured SLA window, an alert is raised immediately.",
    "This is the detection primitive that targets the PNB fraud pattern — not an anomalous transaction, but the structural absence of a ledger record that should always accompany one.",
)

# ── demo flow panel ───────────────────────────────────────────────────────────
with st.container(border=True):
    st.markdown("##### Simulate the PNB Pattern")
    st.caption(
        "Run Step 1 to inject an out-of-band SWIFT action with no ledger entry, "
        "then Step 2 to surface it as a reconciliation alert."
    )
    step1, arrow, step2 = st.columns([2, 0.3, 2])

    with step1:
        st.markdown("**Step 1 — Issue SWIFT LoU**")
        st.caption(
            "Posts a privileged financial action directly to Mock CBS — "
            "bypassing the normal grant path, leaving no ledger record."
        )
        if st.button("Issue SWIFT LoU (no ledger entry)", use_container_width=True, type="primary"):
            try:
                resp = httpx.post(
                    f"{_sidebar.CBS_URL}/swift/action",
                    json={"user_id": "rogue_admin", "amount": 14000.0,
                          "description": "Fake LoU — PNB pattern"},
                    timeout=3,
                )
                st.success(f"Action issued — id=`{resp.json()['action_id'][:8]}…`")
            except Exception:
                st.error("Start services first: `./script.sh`")

    with arrow:
        st.markdown("<div style='text-align:center;font-size:2rem;padding-top:2.5rem'>→</div>", unsafe_allow_html=True)

    with step2:
        st.markdown("**Step 2 — Run Reconciliation**")
        st.caption(
            "Diffs the privileged-action log against the CBS ledger. "
            "Any unmatched action becomes a severity-tiered alert below."
        )
        if st.button("Run reconciliation check", use_container_width=True):
            try:
                reconcile.sync_from_cbs()
                new_alerts = reconcile.run(sla_seconds=0)
                if new_alerts:
                    st.error(f"{len(new_alerts)} new alert(s) raised ↓")
                else:
                    st.success("No new unmatched actions")
            except Exception as e:
                st.error(str(e))

st.divider()

# ── alerts ────────────────────────────────────────────────────────────────────
st.subheader("Reconciliation Alerts")
st.caption(
    "Alerts are severity-tiered. Each carries a one-line recommended response action "
    "drawn from a lookup table — not generated text."
)

alerts = reconcile.get_all_alerts()

if not alerts:
    st.success("No unmatched privileged financial actions detected.")
else:
    severity_order = ("critical", "high", "medium", "low")
    for a in sorted(alerts, key=lambda x: severity_order.index(x.severity)):
        label = _sidebar.SEVERITY_LABEL.get(a.severity, a.severity.upper())
        fn    = st.error if a.severity == "critical" else (
                st.warning if a.severity in ("high", "medium") else st.info)
        fn(
            f"{label} &nbsp;|&nbsp; {a.reason}\n\n"
            f"**Recommended action:** {a.recommended_action}\n\n"
            f"<sub>action `{a.action_id[:22]}…` · detected {a.detected_at.strftime('%Y-%m-%d %H:%M:%S')}</sub>",
        )
