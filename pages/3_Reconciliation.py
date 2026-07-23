"""AstraPAM — Reconciliation page."""
from __future__ import annotations

import _sidebar
import httpx
import streamlit as st

from core import reconcile
from core.schemas import init_db

st.set_page_config(
    page_title="AstraPAM · Reconciliation",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

_sidebar.render_page_header(
    "🔍", "Transaction Reconciliation",
    "Every financial action done through the system is cross-checked against the bank's core ledger. If something was done without a matching ledger entry, we flag it.",
)

# ── simulation panel ──────────────────────────────────────────────────────────
with st.container(border=True):
    st.markdown("##### See it in action")
    st.caption("Issue a SWIFT transaction with no bank record behind it, then run the check to see it get flagged.")
    act_col, recon_col = st.columns(2)

    with act_col:
        st.markdown("**Issue SWIFT transaction**")
        if st.button("Issue SWIFT LoU (no ledger entry)", width="stretch", type="primary"):
            try:
                resp = httpx.post(
                    f"{_sidebar.CBS_URL}/swift/action",
                    json={"user_id": "rogue_admin", "amount": 14000.0,
                          "description": "Fake LoU — PNB pattern"},
                    timeout=3,
                )
                st.success(f"Action issued, id=`{resp.json()['action_id'][:8]}…`")
            except Exception:
                st.error("Start services first: `./script.sh`")

    with recon_col:
        st.markdown("**Run the check**")
        if st.button("Run reconciliation check", width="stretch"):
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
st.subheader("Alerts")

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
