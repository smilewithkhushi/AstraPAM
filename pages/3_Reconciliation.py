"""AegisPAM — Reconciliation page."""
from __future__ import annotations

import _sidebar
import httpx
import streamlit as st

import reconcile
from schemas import init_db

st.set_page_config(
    page_title="AegisPAM · Reconciliation",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

# ── sidebar: reconciliation demo controls ─────────────────────────────────────
with st.sidebar:
    st.divider()
    st.markdown("**Demo Controls**")
    st.caption("Issue an out-of-band action, then run the reconciliation check.")

    if st.button("Issue SWIFT LoU (no ledger entry)", width="stretch"):
        try:
            resp = httpx.post(
                f"{_sidebar.CBS_URL}/swift/action",
                json={"user_id": "rogue_admin", "amount": 14000.0,
                      "description": "Fake LoU — PNB pattern"},
                timeout=3,
            )
            st.success(f"Action issued — id={resp.json()['action_id'][:8]}…")
        except Exception:
            st.error("Start services first: ./script.sh")

    if st.button("Run reconciliation (SLA = 0s)", width="stretch"):
        try:
            reconcile.sync_from_cbs()
            alerts = reconcile.run(sla_seconds=0)
            if alerts:
                st.error(f"{len(alerts)} new alert(s) raised — see below")
            else:
                st.success("No new alerts")
        except Exception as e:
            st.error(str(e))

    st.divider()
    if st.button("Refresh", width="stretch"):
        st.rerun()

# ── header ────────────────────────────────────────────────────────────────────
st.title("Cross-Channel Reconciliation")
st.markdown(
    "Flags every privileged financial action that has no matching entry in the core-banking ledger. "
    "This is the structural detection primitive that targets the PNB fraud signature: "
    "not an anomalous payment, but the complete absence of a ledger record."
)
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
