"""AstraPAM — Overview page (entry point).

Run: streamlit run dashboard.py
Requires: main API on :8000 + mock CBS on :8001 (./script.sh starts both).
"""
from __future__ import annotations

import _sidebar
import broker
import crypto
import reconcile
import streamlit as st
from schemas import init_db

st.set_page_config(
    page_title="AstraPAM",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)


init_db()

with st.sidebar:
    st.divider()
    st.caption("Navigate the pages above to explore each module.")
    if st.button("Refresh", width="stretch"):
        st.rerun()

# ── navbar + header ───────────────────────────────────────────────────────────
_sidebar.render_navbar("Overview")
_hcol, _logo_col = st.columns([6, 1])
with _hcol:
    _sidebar.render_page_header(
        "🛡", "AstraPAM — Control Plane Overview",
        "A privileged access management system built for Indian core banking — enforcing zero standing privilege, real-time risk scoring, and cryptographic audit on every sensitive action.",
        "Use the navigation bar above to explore each control module, or open the CBS Simulation to trigger live access decisions and watch them surface here.",
    )
with _logo_col:
    st.image("preview/logo-astrapam.jpeg", width=90)

# ── system health (left) + cbs callout (right) ───────────────────────────────
_left, _right = st.columns([3, 2])

try:
    broker.expire_stale()
    active_grants = broker.get_active_grants()
except Exception:
    active_grants = []

all_alerts     = reconcile.get_all_alerts()
critical_count = sum(1 for a in all_alerts if a.severity == "critical")
cs = st.session_state.get("chain_status") or crypto.verify_chain()

with _left:
    st.subheader("System Health")
    st.caption("Live snapshot across all four control modules.")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Audit Chain",           "Intact" if cs["valid"] else "BROKEN",
              help=f"{cs['length']} signed records")
    m2.metric("Active JIT Grants",     len(active_grants),
              help="Zero is the correct state — zero standing privilege enforced")
    m3.metric("Reconciliation Alerts", len(all_alerts))
    m4.metric("Critical Alerts",       critical_count)

    if cs["valid"]:
        st.success(f"Audit chain intact — {cs['length']} Dilithium-signed records, hash chain unbroken.")
    else:
        st.error(
            f"Audit chain broken at seq={cs.get('first_bad_seq')} — "
            "tamper or deletion detected. See Access Control."
        )
    if critical_count:
        st.error(
            f"{critical_count} critical reconciliation alert(s) require immediate action. "
            "See Reconciliation."
        )

with _right:
    st.subheader("Try it Live")
    st.info(
        "**Trigger AstraPAM from the bank side.**\n\n"
        "Open the **CBS Simulation** — a Core Banking System portal inspired by "
        "**Finacle** (Infosys), used by 1,000+ banks including SBI and Bank of Baroda. "
        "Log in as any employee, attempt a transaction, and watch the metrics here update in real time.",
        icon="🏦",
    )
    st.link_button(
        "Open CBS Simulation →",
        "https://cbs-simulation.vercel.app/",
        use_container_width=True,
        type="primary",
    )

st.divider()

# # ── module summary ─────────────────────────────────────────────────────────────
# st.subheader("Modules")
# st.caption("Use the sidebar navigation to explore each module.")

# m1, m2, m3, m4 = st.columns(4)

# with m1:
#     st.markdown("**Risk Engine**")
#     st.caption(
#         "Behavioural anomaly scoring via an LSTM autoencoder trained on the CERT Insider "
#         "Threat dataset. Every decision is explainable via SHAP attribution and named "
#         "attack-pattern tags."
#     )
# with m2:
#     st.markdown("**Access Control**")
#     st.caption(
#         "Just-in-time ephemeral grants with auto-expiry — no standing privilege. "
#         "Credentials are issued via a hybrid ML-KEM-768 + X25519 post-quantum handshake "
#         "and every event is written to a tamper-evident audit chain."
#     )
# with m3:
#     st.markdown("**Reconciliation**")
#     st.caption(
#         "Cross-channel ledger diffing that flags any privileged financial action with "
#         "no matching CBS entry — the structural detection primitive that targets the PNB "
#         "fraud signature."
#     )
# with m4:
#     st.markdown("**Compliance**")
#     st.caption(
#         "Non-Human Identity lifecycle governance with mandatory expiry and owner attribution. "
#         "Includes a live Cryptographic Bill of Materials aligned to the RBI Q-SAFE CBOM workstream."
#     )
