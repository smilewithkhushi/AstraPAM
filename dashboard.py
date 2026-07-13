"""AegisPAM — unified Streamlit dashboard. Read-only view of the control plane.

Run: streamlit run dashboard.py
Requires: main API on :8000 + mock CBS on :8001 (./script.sh starts both).
"""
from __future__ import annotations

import json
import sqlite3

import httpx
import pandas as pd
import streamlit as st

import broker
import crypto
import reconcile
import risk as risk_engine
from schemas import DB_PATH, init_db

# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AegisPAM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

# ── constants ─────────────────────────────────────────────────────────────────
DECISION_ICON  = {"allow": "🟢", "throttle": "🟡", "step_up": "🟠", "deny": "🔴"}
DECISION_COLOR = {"allow": "#1a7a1a", "throttle": "#b36b00", "step_up": "#b36b00", "deny": "#a00000"}
SEVERITY_ICON  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}

_NORMAL_FEATURES: dict[str, float] = {
    "logon_count": 5.0, "after_hours": 0.0, "unique_pcs": 1.0,
    "device_events": 0.0, "file_events": 12.0, "http_events": 60.0, "email_events": 10.0,
}
_MAL_FEATURES: dict[str, float] = {
    "logon_count": 1.0, "after_hours": 0.9, "unique_pcs": 4.0,
    "device_events": 8.0, "file_events": 150.0, "http_events": 2.0, "email_events": 0.0,
}

CBS_URL = "http://localhost:8001"


# ── header ────────────────────────────────────────────────────────────────────
st.markdown(
    "<h1 style='margin-bottom:0'>🛡️ AegisPAM</h1>"
    "<p style='color:gray;margin-top:4px'>Zero-Standing-Privilege · Explainable Risk AI · "
    "Cross-Channel Reconciliation · Post-Quantum Cryptography</p>",
    unsafe_allow_html=True,
)
st.divider()


# ── sidebar — demo controls ───────────────────────────────────────────────────
with st.sidebar:
    st.header("Demo Controls")
    st.caption("Step through the demo script with these buttons.")

    st.subheader("1 — Risk Scoring")
    if st.button("✅ Score normal session", use_container_width=True):
        with st.spinner("Scoring…"):
            st.session_state["last_risk"]     = risk_engine.score(_NORMAL_FEATURES)
            st.session_state["last_features"] = _NORMAL_FEATURES

    if st.button("🚨 Score malicious session", use_container_width=True):
        with st.spinner("Scoring…"):
            st.session_state["last_risk"]     = risk_engine.score(_MAL_FEATURES)
            st.session_state["last_features"] = _MAL_FEATURES

    st.subheader("2 — Reconciliation")
    if st.button("💸 Issue SWIFT LoU (no ledger)", use_container_width=True):
        try:
            resp = httpx.post(
                f"{CBS_URL}/swift/action",
                json={"user_id": "rogue_admin", "amount": 14000.0,
                      "description": "Fake LoU — PNB pattern"},
                timeout=3,
            )
            st.success(f"SWIFT action issued  id={resp.json()['action_id'][:8]}…")
        except Exception:
            st.error("Start services first: ./script.sh")

    if st.button("🔍 Run reconciliation (SLA=0s)", use_container_width=True):
        try:
            sw, le = reconcile.sync_from_cbs()
            alerts = reconcile.run(sla_seconds=0)
            if alerts:
                st.error(f"🚨 {len(alerts)} new alert(s) — see main panel")
            else:
                st.success("No new alerts")
        except Exception as e:
            st.error(str(e))

    st.subheader("3 — PQC Credential")
    if st.button("🔐 Issue PQC credential", use_container_width=True):
        art = crypto.issue_credential("demo_user", "grant-demo")
        st.session_state["last_artifact"] = art
        st.success(f"ML-KEM-768 handshake complete — pk={art.pubkey_bytes}B")

    if st.button("🔗 Verify audit chain", use_container_width=True):
        st.session_state["chain_status"] = crypto.verify_chain()

    st.subheader("4 — Tamper Detection Demo")
    if st.button("💥 Tamper audit record (seq=1)", use_container_width=True):
        con = sqlite3.connect(DB_PATH)
        rows = con.execute("SELECT seq FROM audit_records LIMIT 1").fetchall()
        if rows:
            con.execute("UPDATE audit_records SET payload='[TAMPERED]' WHERE seq=1")
            con.commit()
            st.warning("Record tampered — press 'Verify audit chain' to detect it")
        else:
            st.info("Issue a credential first to populate the audit log")
        con.close()

    st.divider()
    if st.button("🔄 Refresh dashboard", use_container_width=True):
        st.rerun()


# ── top row: risk feed | pqc + audit ─────────────────────────────────────────
col_risk, col_pqc = st.columns([3, 2])

# ── RISK FEED ─────────────────────────────────────────────────────────────────
with col_risk:
    st.subheader("🔴 Live Risk Feed")
    r = st.session_state.get("last_risk")

    if r is None:
        st.info("Use **Score normal session** or **Score malicious session** in the sidebar.")
    else:
        # decision banner
        color = DECISION_COLOR.get(r.decision, "#555")
        icon  = DECISION_ICON.get(r.decision, "⚪")
        st.markdown(
            f"<div style='background:{color};color:white;padding:10px 18px;"
            f"border-radius:8px;font-size:20px;font-weight:bold;text-align:center'>"
            f"{icon} {r.decision.upper()}</div>",
            unsafe_allow_html=True,
        )
        st.markdown("")

        m1, m2, m3 = st.columns(3)
        m1.metric("Risk Score", f"{r.score:.3f}")
        m2.metric("Decision", r.decision.upper())
        m3.metric("Attack Tags", len(r.attack_tags))

        # attack tags
        if r.attack_tags:
            st.markdown("**Attack pattern tags** *(rule-based on session features — not ML outputs)*")
            tag_cols = st.columns(min(len(r.attack_tags), 4))
            for i, tag in enumerate(r.attack_tags):
                tag_cols[i % 4].error(f"⚠ {tag}")

        # SHAP explainability
        if r.top_factors:
            st.markdown("**SHAP feature attribution** *(why this score)*")
            df_shap = pd.DataFrame(
                [{"Feature": f.feature, "Contribution": abs(f.contribution),
                  "Direction": "▲ raises risk" if f.contribution > 0 else "▼ lowers risk"}
                 for f in sorted(r.top_factors, key=lambda x: abs(x.contribution), reverse=True)]
            )
            st.bar_chart(df_shap.set_index("Feature")["Contribution"])
            for f in r.top_factors:
                sign = "▲" if f.contribution > 0 else "▼"
                st.caption(f"{sign} `{f.feature}` → {f.contribution:+.4f}")


# ── PQC ARTIFACT + AUDIT ──────────────────────────────────────────────────────
with col_pqc:
    st.subheader("🔐 PQC Credential Vault")
    art = st.session_state.get("last_artifact")

    if art is None:
        st.info("Press **Issue PQC credential** to run a real ML-KEM-768 + X25519 handshake.")
    else:
        st.markdown(f"**Algorithm:** `{art.algorithm}`")
        b1, b2, b3 = st.columns(3)
        b1.metric("Public Key",     f"{art.pubkey_bytes} B")
        b2.metric("Ciphertext",     f"{art.ciphertext_bytes} B")
        b3.metric("Shared Secret",  f"{art.shared_secret_bytes} B")
        st.success("Real NIST FIPS 203 byte-counts — KEM is not mocked")

    st.divider()
    st.subheader("🔗 Audit Chain Integrity")

    cs = st.session_state.get("chain_status") or crypto.verify_chain()
    if cs["valid"]:
        st.success(f"✅ VALID — {cs['length']} records, chain unbroken")
    else:
        st.error(
            f"🚨 CHAIN BROKEN at seq={cs['first_bad_seq']} — "
            "tamper or deletion detected"
        )

    log = crypto.get_audit_log()
    if log:
        with st.expander(f"Last {min(5, len(log))} audit entries"):
            for rec in reversed(log[-5:]):
                try:
                    ev = json.loads(rec.payload).get("event", rec.payload[:50])
                except Exception:
                    ev = rec.payload[:50]
                st.caption(f"[{rec.seq}] `{ev}`  …`{rec.hash[:12]}`")

    st.subheader("🔑 Active JIT Grants")
    try:
        broker.expire_stale()
    except Exception:
        pass
    grants = broker.get_active_grants()
    if not grants:
        st.success("No standing privileges — Zero Standing Privilege enforced ✓")
    else:
        df_g = pd.DataFrame([{
            "Grant ID":   g.grant_id[:12] + "…",
            "User":       g.user_id,
            "Target":     g.target,
            "Expires":    g.expires_at.strftime("%H:%M:%S"),
            "Rate Cap":   f"₹{g.rate_cap:,.0f}" if g.rate_cap else "—",
        } for g in grants])
        st.dataframe(df_g, use_container_width=True, hide_index=True)


# ── RECONCILIATION ALERTS ─────────────────────────────────────────────────────
st.divider()
st.subheader("🚨 Reconciliation Alerts  *(cross-channel ledger check — the PNB fix)*")
alerts = reconcile.get_all_alerts()

if not alerts:
    st.success("No unmatched privileged financial actions detected.")
else:
    for a in sorted(alerts, key=lambda x: ("critical","high","medium","low").index(x.severity)):
        icon = SEVERITY_ICON.get(a.severity, "⚪")
        fn   = st.error if a.severity == "critical" else (
               st.warning if a.severity == "high" else st.info)
        fn(
            f"{icon} **{a.severity.upper()}** &nbsp;|&nbsp; {a.reason}\n\n"
            f"**→ {a.recommended_action}**\n\n"
            f"<sub>action_id: `{a.action_id[:20]}…`  &nbsp;·&nbsp;  "
            f"detected: `{a.detected_at.strftime('%Y-%m-%d %H:%M:%S')}`</sub>",
        )
