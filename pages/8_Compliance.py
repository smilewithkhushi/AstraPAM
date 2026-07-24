"""AstraPAM — Compliance page."""
from __future__ import annotations

import _sidebar
import pandas as pd
import streamlit as st

from core import cbom as cbom_scanner
from core import nhi as nhi_module
from core.schemas import DB_PATH, init_db

init_db()

_sidebar.render_page_header(
    "", "Compliance",
    "Tracks all service accounts, API keys and automated agents, and makes sure they have an owner and an expiry date. Also shows which encryption methods the system is using.",
)

tab_nhi, tab_cbom = st.tabs(["Service Accounts (NHI)", "Encryption Inventory (CBOM)"])

# ── Tab 1: NHI ────────────────────────────────────────────────────────────────
with tab_nhi:
    st.subheader("Non-Human Identity Governance")
    st.caption("Every service account, API key, and automated agent must have a named owner and a mandatory expiry. Orphaned or expired credentials are flagged and signed into the audit chain.")

    with st.container(border=True):
        st.markdown("##### Actions")
        seed_col, scan_col = st.columns(2)

        with seed_col:
            st.markdown("**Load Sample NHIs**")
            st.caption("Adds three example accounts including one that is already expired, so you can see how the scan works.")
            if st.button("Load sample NHIs", width="stretch", type="primary"):
                try:
                    seeded = [
                        nhi_module.register(
                            "svc_cbs_reader", "service_account", "infra-team",
                            ttl_days=90, description="Read-only CBS data service account",
                        ),
                        nhi_module.register(
                            "api_key_reporting", "api_key", "analytics-team",
                            ttl_days=-30, description="Analytics API key, ORPHANED (expired 30d ago)",
                        ),
                        nhi_module.register(
                            "ai_agent_fraud_detector", "ai_agent", "ml-team",
                            ttl_days=7, description="Fraud-detection ML agent credential",
                        ),
                    ]
                    st.success(f"Registered {len(seeded)} accounts. Refresh to see them below.")
                except Exception as e:
                    st.error(str(e))

        with scan_col:
            st.markdown("**Scan for Expired NHIs**")
            st.caption("Finds any account that has passed its expiry date and logs the violation.")
            if st.button("Scan for expired NHIs", width="stretch"):
                expired = nhi_module.scan_expired()
                if expired:
                    st.warning(f"{len(expired)} expired NHI(s) flagged and signed in audit chain.")
                else:
                    st.success("No newly-expired NHIs found.")

    st.divider()

    st.subheader("Service Account Inventory")
    st.caption(
        "A live list of all automated accounts registered in the system — the bots, integrations, and background services that act on behalf of the bank. "
        "Each one must have a human owner and an expiry date; anything missing either is flagged as a compliance violation."
    )

    _nhis = nhi_module.list_all()

    if not _nhis:
        st.info("No NHIs registered. Click **Load sample NHIs** above to populate.")
    else:
        active  = sum(1 for n in _nhis if n.status == "active")
        soon    = sum(1 for n in _nhis if n.status == "expiring_soon")
        expired = sum(1 for n in _nhis if n.status == "expired")
        revoked = sum(1 for n in _nhis if n.status == "revoked")

        st.markdown(
            "<div style='display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:12px'>"
            + "".join(
                f"<div style='border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;text-align:center'>"
                f"<div style='font-size:2rem;font-weight:700;color:#111827'>{val}</div>"
                f"<div style='font-size:0.82rem;color:#6b7280;margin-top:2px'>{label}</div>"
                f"</div>"
                for label, val in [
                    ("Active",        active),
                    ("Expiring Soon", soon),
                    ("Expired",       expired),
                    ("Revoked",       revoked),
                ]
            )
            + "</div>",
            unsafe_allow_html=True,
        )

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

# ── Tab 2: CBOM ───────────────────────────────────────────────────────────────
with tab_cbom:
    st.subheader("Cryptographic Bill of Materials")
    st.caption(
        "A live scan of every encryption primitive in use across the codebase. "
        "Aligned to the RBI Q-SAFE Committee's CBOM workstream requirement. "
        "Flags any algorithm that would be broken by a sufficiently powerful quantum computer."
    )

    _cbom = cbom_scanner.scan()

    # persist scan result and show last-scanned timestamp
    import sqlite3 as _sqlite3
    from datetime import datetime as _dt, timezone as _tz
    _now_ts = _dt.now(_tz.utc).isoformat()
    try:
        _con = _sqlite3.connect(DB_PATH)
        _con.execute(
            "INSERT INTO cbom_scans (scanned_at, files_scanned, quantum_safe, hybrid_pqc, classical, vulnerable, verdict)"
            " VALUES (?,?,?,?,?,?,?)",
            (_now_ts, _cbom.scanned_files, _cbom.quantum_safe_count,
             _cbom.hybrid_pqc_count, _cbom.classical_count,
             _cbom.quantum_vulnerable_count, _cbom.verdict),
        )
        _con.commit()
        _last = _con.execute(
            "SELECT scanned_at FROM cbom_scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        _con.close()
        if _last:
            st.caption(f"Last scanned: {_last[0][:19].replace('T', ' ')} UTC")
    except Exception:
        pass

    if _cbom.quantum_vulnerable_count == 0:
        st.success(_cbom.verdict)
    else:
        st.error(_cbom.verdict)

    st.markdown(
        "<div style='display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:12px'>"
        + "".join(
            f"<div style='border:1px solid #e5e7eb;border-radius:8px;padding:16px 20px;text-align:center'>"
            f"<div style='font-size:2rem;font-weight:700;color:#111827'>{val}</div>"
            f"<div style='font-size:0.82rem;color:#6b7280;margin-top:2px'>{label}</div>"
            f"</div>"
            for label, val in [
                ("Files Scanned", _cbom.scanned_files),
                ("Quantum-Safe",  _cbom.quantum_safe_count),
                ("Hybrid PQC",    _cbom.hybrid_pqc_count),
                ("Classical",     _cbom.classical_count),
                ("Vulnerable",    _cbom.quantum_vulnerable_count),
            ]
        )
        + "</div>",
        unsafe_allow_html=True,
    )

    if _cbom.entries:
        STATUS_CBOM = {
            "quantum_safe":        "Quantum-Safe",
            "hybrid_pqc":          "Hybrid PQC",
            "quantum_vulnerable":  "Vulnerable",
            "classical_symmetric": "Classical",
        }
        st.divider()
        st.subheader("Algorithm Inventory")
        st.caption(
            "Every place in the codebase where encryption is used — what algorithm, which file, and whether it's safe against future quantum attacks. "
            "Anything marked Vulnerable needs to be replaced before quantum computers become powerful enough to break it."
        )
        df_cbom = pd.DataFrame([{
            "File":      e.file,
            "Line":      e.line,
            "Algorithm": e.algorithm,
            "Status":    STATUS_CBOM.get(e.category, e.category),
            "Reason":    e.reason,
        } for e in _cbom.entries])
        st.dataframe(df_cbom, width="stretch", hide_index=True)
