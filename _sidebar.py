"""Shared constants used across all AstraPAM pages."""
from __future__ import annotations

import os


_MOBILE_CSS = """
<style>
@media (max-width: 768px) {
    /* Stack all column groups vertically */
    div[data-testid="stHorizontalBlock"] {
        flex-direction: column !important;
    }
    div[data-testid="column"] {
        width: 100% !important;
        min-width: 100% !important;
        flex: 1 1 100% !important;
    }
    /* Make tables and dataframes scroll horizontally */
    div[data-testid="stDataFrame"],
    div[data-testid="stTable"] {
        overflow-x: auto !important;
    }
    /* Reduce header font size */
    h2 { font-size: 1.3rem !important; }
    /* Shrink metric labels */
    div[data-testid="stMetric"] label { font-size: 0.75rem !important; }
}
</style>
"""


def render_page_header(icon: str, title: str, subtitle: str) -> None:
    try:
        import streamlit as st
    except ImportError:
        return
    st.markdown(_MOBILE_CSS, unsafe_allow_html=True)
    st.markdown(
        f"<h2 style='margin-bottom:2px;color:#111827'>{icon} {title}</h2>"
        f"<p style='color:#4b5563;margin:0 0 12px 0;font-size:0.92rem'>{subtitle}</p>",
        unsafe_allow_html=True,
    )
    st.divider()


try:
    import streamlit as st
    def _get(key: str, default: str) -> str:
        try:
            return st.secrets[key]
        except Exception:
            return os.getenv(key, default)
except ImportError:
    def _get(key: str, default: str) -> str:  # type: ignore[misc]
        return os.getenv(key, default)

API_URL = _get("API_URL", "http://localhost:8000")
CBS_URL = _get("CBS_URL", "http://localhost:8001")

# Semantic color tokens — use these everywhere, never hardcode hex in pages
C_ALLOW    = "#166534"   # dark green
C_THROTTLE = "#92400e"   # dark amber
C_STEP_UP  = "#92400e"
C_DENY     = "#991b1b"   # dark red
C_INFO     = "#1e3a5f"   # navy
C_MUTED    = "#6b7280"   # gray
C_BORDER   = "#e5e7eb"

DECISION_COLOR = {
    "allow":    C_ALLOW,
    "throttle": C_THROTTLE,
    "step_up":  C_STEP_UP,
    "deny":     C_DENY,
}
DECISION_BADGE = {
    "allow":    "✅ ALLOW",
    "throttle": "⚡ THROTTLE",
    "step_up":  "🔐 STEP UP",
    "deny":     "🚫 DENY",
}
SEVERITY_LABEL = {
    "critical": "🔴 CRITICAL",
    "high":     "🟠 HIGH",
    "medium":   "🟡 MEDIUM",
    "low":      "🔵 LOW",
}

NORMAL_FEATURES: dict[str, float] = {
    "logon_count": 5.0, "after_hours": 0.0, "unique_pcs": 1.0,
    "device_events": 0.0, "file_events": 12.0, "http_events": 60.0, "email_events": 10.0,
}
MAL_FEATURES: dict[str, float] = {
    "logon_count": 1.0, "after_hours": 0.9, "unique_pcs": 4.0,
    "device_events": 8.0, "file_events": 150.0, "http_events": 2.0, "email_events": 0.0,
}
