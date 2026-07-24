"""AstraPAM — entry point. Defines navigation with section labels."""
from __future__ import annotations

import streamlit as st

st.set_page_config(
    page_title="AstraPAM",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

pg = st.navigation(
    {
        "": [
            st.Page("pages/0_Overview.py", title="Overview", icon="🏠", default=True),
        ],
        "Identity & Access": [
            st.Page("pages/2_Access_Control.py",  title="Access Control",   icon="🔐"),
            st.Page("pages/6_Exposure.py",         title="Exposure Score",   icon="📊"),
            st.Page("pages/7_Roles_Trace.py",      title="Roles & Trace",    icon="🔍"),
        ],
        "Transactions & Controls": [
            st.Page("pages/1_SoD_MakerChecker.py", title="SoD & Maker-Checker", icon="✅"),
            st.Page("pages/3_Reconciliation.py",   title="Reconciliation",       icon="⚖️"),
        ],
        "Threat Intelligence": [
            st.Page("pages/4_Risk_Engine.py",  title="Risk Engine",  icon="🎯"),
            st.Page("pages/5_SOC_Console.py",  title="SOC Console",  icon="🛡"),
        ],
        "Governance & Audit": [
            st.Page("pages/8_Compliance.py",    title="Compliance",    icon="📋"),
            st.Page("pages/9_Logs_Reports.py",  title="Logs & Reports", icon="📄"),
        ],
    }
)
pg.run()
