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


_logo_col, _hcol = st.columns([1, 6])
with _logo_col:
    st.image("preview/logo-astrapam.jpeg", width=180)
with _hcol:
    _sidebar.render_page_header(
        "", "AstraPAM",
        " Privileged Access Management (PAM) system built for Indian core banking. Offers Zero standing privilege, real-time risk scoring and cryptographic audit.",
    )
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

    st.markdown(
        """
        <style>
        .metric-card {
            border: 1.5px solid #4a90d9;
            border-radius: 10px;
            padding: 16px 18px 12px 18px;
            background: rgba(74, 144, 217, 0.04);
        }
        .metric-card .label {
            font-size: 0.78rem;
            color: #888;
            margin-bottom: 4px;
        }
        .metric-card .value {
            font-size: 1.6rem;
            font-weight: 700;
            color: inherit;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    row1_c1, row1_c2 = st.columns(2)
    with row1_c1:
        st.markdown(
            f'<div class="metric-card"><div class="label">Audit Chain</div>'
            f'<div class="value">{"Intact" if cs["valid"] else "BROKEN"}</div></div>',
            unsafe_allow_html=True,
        )
    with row1_c2:
        st.markdown(
            f'<div class="metric-card"><div class="label">Active JIT Grants</div>'
            f'<div class="value">{len(active_grants)}</div></div>',
            unsafe_allow_html=True,
        )

    st.write("")

    row2_c1, row2_c2 = st.columns(2)
    with row2_c1:
        st.markdown(
            f'<div class="metric-card"><div class="label">Reconciliation Alerts</div>'
            f'<div class="value">{len(all_alerts)}</div></div>',
            unsafe_allow_html=True,
        )
    with row2_c2:
        st.markdown(
            f'<div class="metric-card"><div class="label">Critical Alerts</div>'
            f'<div class="value">{critical_count}</div></div>',
            unsafe_allow_html=True,
        )

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
