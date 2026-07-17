"""AstraPAM — Compliance page."""
from __future__ import annotations

import _sidebar
import pandas as pd
import streamlit as st

import cbom as cbom_scanner
import nhi as nhi_module
from schemas import init_db

st.set_page_config(
    page_title="AstraPAM · Compliance",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

with st.sidebar:
    st.divider()
    if st.button("↺ Refresh", use_container_width=True):
        st.rerun()

# ── header ────────────────────────────────────────────────────────────────────
_sidebar.render_navbar("Compliance")
_sidebar.render_page_header(
    "📋", "Compliance — NHI Governance & Cryptographic Inventory",
    "Governs Non-Human Identities (service accounts, API keys, AI-agent credentials) with mandatory expiry dates and owner attribution — eliminating the orphaned credential risk that regulators increasingly flag during audits.",
    "The Cryptographic Bill of Materials provides a live inventory of every algorithm in use across the system, aligned to the RBI Q-SAFE Committee's CBOM workstream for post-quantum readiness.",
)

# ── demo action panel ─────────────────────────────────────────────────────────
with st.container(border=True):
    st.markdown("##### Demo Actions")
    st.caption("Seed identities first, then scan to surface lifecycle violations.")
    s1, arrow, s2 = st.columns([2, 0.3, 2])

    with s1:
        st.markdown("**Step 1 — Seed Demo NHIs**")
        st.caption(
            "Registers 3 non-human identities: a healthy service account, "
            "an orphaned API key (expired 30 days ago), and an AI-agent credential."
        )
        if st.button("Seed demo NHIs", use_container_width=True, type="primary"):
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
                st.success(f"Registered {len(seeded)} NHIs — refresh to see inventory below")
            except Exception as e:
                st.error(str(e))

    with arrow:
        st.markdown("<div style='text-align:center;font-size:2rem;padding-top:2.5rem'>→</div>", unsafe_allow_html=True)

    with s2:
        st.markdown("**Step 2 — Scan for Expired NHIs**")
        st.caption(
            "Flags any identity past its TTL, writes the violation to the "
            "Dilithium-signed audit chain, and surfaces it in the inventory table."
        )
        if st.button("Scan for expired NHIs", use_container_width=True):
            expired = nhi_module.scan_expired()
            if expired:
                st.warning(f"{len(expired)} expired NHI(s) flagged and signed in audit chain")
            else:
                st.success("No newly-expired NHIs found")

st.divider()

# ── nhi inventory ─────────────────────────────────────────────────────────────
st.subheader("Non-Human Identity Inventory")
st.caption(
    "Every non-human identity must have a named owner and a mandatory expiry date. "
    "Expired identities are flagged automatically and written to the audit chain."
)

_nhis = nhi_module.list_all()

if not _nhis:
    st.info("No NHIs registered. Click **Seed demo NHIs** above to populate.")
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
