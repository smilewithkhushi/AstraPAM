"""AegisPAM — Compliance page."""
from __future__ import annotations

import _sidebar
import pandas as pd
import streamlit as st

import cbom as cbom_scanner
import nhi as nhi_module
from schemas import init_db

st.set_page_config(
    page_title="AegisPAM · Compliance",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

# ── sidebar: compliance demo controls ─────────────────────────────────────────
with st.sidebar:
    st.divider()
    st.markdown("**Demo Controls**")
    st.caption("Seed identities, then scan to surface expired credentials.")

    if st.button("Seed demo NHIs", width="stretch"):
        try:
            seeded = [
                nhi_module.register(
                    "svc_cbs_reader", "service_account", "infra-team",
                    ttl_days=90, description="Read-only CBS data service account",
                ),
                nhi_module.register(
                    "api_key_reporting", "api_key", "analytics-team",
                    ttl_days=-30, description="Analytics API key — ORPHANED (expired 30d ago)",
                ),
                nhi_module.register(
                    "ai_agent_fraud_detector", "ai_agent", "ml-team",
                    ttl_days=7, description="Fraud-detection ML agent credential",
                ),
            ]
            st.success(f"Registered {len(seeded)} NHIs")
        except Exception as e:
            st.error(str(e))

    if st.button("Scan for expired NHIs", width="stretch"):
        expired = nhi_module.scan_expired()
        if expired:
            st.warning(f"{len(expired)} newly-expired NHI(s) — signed in audit chain")
        else:
            st.success("No newly-expired NHIs")

    st.divider()
    if st.button("Refresh", width="stretch"):
        st.rerun()

# ── header ────────────────────────────────────────────────────────────────────
st.title("Compliance")
st.markdown(
    "Non-Human Identity governance enforces mandatory expiry and owner attribution on every "
    "service account, API key, and AI-agent credential. The Cryptographic Bill of Materials "
    "provides a live audit of every algorithm in use, aligned to the RBI Q-SAFE CBOM workstream."
)
st.divider()

# ── nhi inventory ─────────────────────────────────────────────────────────────
st.subheader("Non-Human Identity Inventory")
st.caption(
    "Every non-human identity must have a named owner and a mandatory expiry date. "
    "Expired identities are flagged automatically and written to the audit chain."
)

_nhis = nhi_module.list_all()

if not _nhis:
    st.info("No NHIs registered. Press **Seed demo NHIs** in the sidebar to populate.")
else:
    active  = sum(1 for n in _nhis if n.status == "active")
    soon    = sum(1 for n in _nhis if n.status == "expiring_soon")
    expired = sum(1 for n in _nhis if n.status == "expired")
    revoked = sum(1 for n in _nhis if n.status == "revoked")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Active",        active)
    c2.metric("Expiring Soon", soon)
    c3.metric("Expired",       expired)
    c4.metric("Revoked",       revoked)

    STATUS_LABEL = {
        "active":        "Active",
        "expiring_soon": "Expiring Soon",
        "expired":       "Expired",
        "revoked":       "Revoked",
    }
    TYPE_LABEL = {
        "service_account": "Service Account",
        "api_key":         "API Key",
        "ai_agent":        "AI Agent",
    }

    df_nhi = pd.DataFrame([{
        "Type":        TYPE_LABEL.get(n.nhi_type, n.nhi_type),
        "Name":        n.name,
        "Owner":       n.owner,
        "Status":      STATUS_LABEL.get(n.status, n.status),
        "Expires":     n.expires_at.strftime("%Y-%m-%d"),
        "Last Used":   n.last_used.strftime("%Y-%m-%d") if n.last_used else "Never",
        "Description": n.description,
    } for n in _nhis])
    st.dataframe(df_nhi, width="stretch", hide_index=True)

st.divider()

# ── cbom ──────────────────────────────────────────────────────────────────────
st.subheader("Cryptographic Bill of Materials")
st.caption(
    "Live scan of all project .py files. Classifies every cryptographic primitive as "
    "quantum-safe, hybrid PQC, classical symmetric, or quantum-vulnerable. "
    "Mirrors the RBI Q-SAFE CBOM workstream requirement."
)

_cbom = cbom_scanner.scan()

if _cbom.quantum_vulnerable_count == 0:
    st.success(_cbom.verdict)
else:
    st.error(_cbom.verdict)

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Files Scanned", _cbom.scanned_files)
c2.metric("Quantum-Safe",  _cbom.quantum_safe_count)
c3.metric("Hybrid PQC",    _cbom.hybrid_pqc_count)
c4.metric("Classical",     _cbom.classical_count)
c5.metric("Vulnerable",    _cbom.quantum_vulnerable_count)

if _cbom.entries:
    STATUS_CBOM = {
        "quantum_safe":        "Quantum-Safe",
        "hybrid_pqc":          "Hybrid PQC",
        "quantum_vulnerable":  "Vulnerable",
        "classical_symmetric": "Classical",
    }
    df_cbom = pd.DataFrame([{
        "File":      e.file,
        "Line":      e.line,
        "Algorithm": e.algorithm,
        "Status":    STATUS_CBOM.get(e.category, e.category),
        "Reason":    e.reason,
    } for e in _cbom.entries])
    st.dataframe(df_cbom, width="stretch", hide_index=True)
