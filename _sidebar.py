"""Shared constants used across all AstraPAM pages."""
from __future__ import annotations

import os

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
