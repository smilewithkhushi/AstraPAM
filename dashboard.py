"""AstraPAM — Overview page (entry point).

Run: streamlit run dashboard.py
Requires: main API on :8000 + mock CBS on :8001 (./script.sh starts both).
"""
from __future__ import annotations

import _sidebar
from core import broker
from core import crypto
from core import reconcile
import streamlit as st
from core.schemas import init_db

st.set_page_config(
    page_title="AstraPAM",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()


_hcol, _logo_col = st.columns([6, 1])
with _hcol:
    _sidebar.render_page_header(
        "🛡", "AstraPAM",
        "Privileged access management for Indian core banking. Zero standing privilege, real-time risk scoring, cryptographic audit.",
    )
with _logo_col:
    st.image("preview/logo-astrapam.jpeg", width=90)

try:
    broker.expire_stale()
    active_grants = broker.get_active_grants()
except Exception:
    active_grants = []

all_alerts     = reconcile.get_all_alerts()
critical_count = sum(1 for a in all_alerts if a.severity == "critical")
cs = st.session_state.get("chain_status") or crypto.verify_chain()

_left, _right = st.columns([3, 2])

with _left:
    st.subheader("System Health")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Audit Chain",           "Intact" if cs["valid"] else "BROKEN",
              help=f"{cs['length']} signed records")
    m2.metric("Active JIT Grants",     len(active_grants),
              help="Zero = no standing access anywhere in the system")
    m3.metric("Reconciliation Alerts", len(all_alerts))
    m4.metric("Critical Alerts",       critical_count)

    if cs["valid"]:
        st.success(f"Audit log is intact. {cs['length']} records, nothing altered.")
    else:
        st.error(f"Log tampered at seq={cs.get('first_bad_seq')}. Go to Access Control.")
    if critical_count:
        st.error(f"{critical_count} critical reconciliation alert(s) require immediate action. See Reconciliation.")

with _right:
    st.subheader("Try it from the bank side")
    st.info(
        "Open the CBS Simulation, log in as a bank employee, and make a transaction. "
        "The numbers on this page will update in real time.",
        icon="🏦",
    )
    st.link_button(
        "Open CBS Simulation →",
        "https://cbs-simulation.vercel.app/",
        width="stretch",
        type="primary",
    )
