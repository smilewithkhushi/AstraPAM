"""Shared constants used across all AstraPAM pages."""
from __future__ import annotations

import os

_NAV_ITEMS = [
    ("Overview",         "/"),
    ("SoD & Maker-Checker", "/SoD_MakerChecker"),
    ("Access Control",   "/Access_Control"),
    ("Reconciliation",   "/Reconciliation"),
    ("Risk Engine",      "/Risk_Engine"),
    ("Console",          "/Console"),
    ("Exposure",         "/Exposure"),
    ("Roles & Trace",    "/Roles_Trace"),
    ("Compliance",       "/Compliance"),
    ("Logs & Reports",   "/Logs_Reports"),
]

def render_navbar(active: str = "Overview") -> None:
    try:
        import streamlit as st
    except ImportError:
        return

    links_html = ""
    for name, url in _NAV_ITEMS:
        is_active = name == active
        style = (
            "padding:6px 14px;border-radius:6px;text-decoration:none;font-size:0.8rem;"
            "font-weight:600;white-space:nowrap;transition:background 0.15s;"
        )
        if is_active:
            style += "background:#1e40af;color:#e0eaff;"
        else:
            style += "color:#94a3b8;"
        links_html += f'<a href="{url}" target="_self" style="{style}">{name}</a>'

    st.markdown(
        f"""
        <div style="
            background:#0f172a;border-bottom:1px solid #1e293b;
            padding:10px 20px;margin:-1rem -1rem 1.5rem -1rem;
            display:flex;align-items:center;gap:6px;flex-wrap:wrap;
        ">
            <span style="color:#60a5fa;font-weight:700;font-size:0.85rem;
                         margin-right:12px;letter-spacing:.05em;">AstraPAM</span>
            {links_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_page_header(icon: str, title: str, line1: str, line2: str) -> None:
    try:
        import streamlit as st
    except ImportError:
        return
    st.markdown(
        f"<h2 style='margin-bottom:4px'>{icon} {title}</h2>"
        f"<p style='color:#64748b;margin:0 0 6px 0;font-size:0.95rem;line-height:1.6'>"
        f"{line1}<br>{line2}</p>",
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

DECISION_COLOR = {
    "allow":    "#1a7a1a",
    "throttle": "#b36b00",
    "step_up":  "#b36b00",
    "deny":     "#a00000",
}
DECISION_BADGE = {
    "allow":    "🟢 ALLOW",
    "throttle": "🟡 THROTTLE",
    "step_up":  "🟠 STEP UP",
    "deny":     "🔴 DENY",
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
