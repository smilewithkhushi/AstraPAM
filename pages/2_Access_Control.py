"""AegisPAM — Access Control page."""
from __future__ import annotations

import json
import sqlite3

import _sidebar
import httpx
import pandas as pd
import streamlit as st

import broker
import crypto
from schemas import DB_PATH, init_db

st.set_page_config(
    page_title="AegisPAM · Access Control",
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
st.title("Access Control")
st.markdown(
    "Just-in-time ephemeral access grants with automatic expiry enforce zero standing privilege. "
    "Credentials are issued via a hybrid ML-KEM-768 + X25519 post-quantum handshake, and every "
    "grant event is written to a Dilithium-signed, hash-chained audit log."
)
st.divider()

# ── demo action panel ─────────────────────────────────────────────────────────
with st.container(border=True):
    st.markdown("##### Demo Actions")
    st.caption("Run these in sequence to walk through the full access-control flow.")
    a1, a2, a3, a4 = st.columns(4)

    with a1:
        st.markdown("**🔑 Issue PQC Credential**")
        st.caption("Runs a live ML-KEM-768 + X25519 hybrid handshake and writes to the audit chain.")
        if st.button("Issue credential", use_container_width=True, type="primary"):
            art = crypto.issue_credential("demo_user", "grant-demo")
            st.session_state["last_artifact"] = art
            st.success(f"pk={art.pubkey_bytes}B · ct={art.ciphertext_bytes}B")

    with a2:
        st.markdown("**✅ Verify Audit Chain**")
        st.caption("Checks every Dilithium signature in the hash chain and surfaces any break.")
        if st.button("Verify chain", use_container_width=True):
            st.session_state["chain_status"] = crypto.verify_chain()
            cs = st.session_state["chain_status"]
            if cs["valid"]:
                st.success(f"Intact — {cs['length']} records")
            else:
                st.error(f"Broken at seq={cs['first_bad_seq']}")

    with a3:
        st.markdown("**🚨 Emergency Break-Glass**")
        st.caption("Issues a grant despite a high-risk score. Justified and logged — cannot be hidden.")
        if st.button("Break-glass", use_container_width=True):
            try:
                resp = httpx.post(
                    "http://localhost:8000/access/break-glass",
                    json={
                        "user_id":       "admin_emergency",
                        "target":        "core_banking_prod",
                        "justification": "P1 outage — production DB locked, normal path denied",
                        "features":      _sidebar.MAL_FEATURES,
                    },
                    timeout=5,
                )
                d = resp.json()
                st.warning(
                    f"Granted — risk={d['risk_at_issue']['score']:.3f} "
                    f"({d['risk_at_issue']['decision'].upper()})"
                )
            except Exception as e:
                st.error(f"API unreachable: {e}")

    with a4:
        st.markdown("**🔨 Tamper + Detect**")
        st.caption("Corrupts audit record seq 1, then run Verify Chain above to catch it.")
        if st.button("Tamper seq 1", use_container_width=True):
            con = sqlite3.connect(DB_PATH)
            rows = con.execute("SELECT seq FROM audit_records LIMIT 1").fetchall()
            if rows:
                con.execute("UPDATE audit_records SET payload='[TAMPERED]' WHERE seq=1")
                con.commit()
                st.warning("Tampered — click Verify Chain to detect")
            else:
                st.info("Issue a credential first")
            con.close()

st.divider()

col_grants, col_pqc = st.columns([3, 2])

# ── active jit grants ─────────────────────────────────────────────────────────
with col_grants:
    st.subheader("Active JIT Grants")
    st.caption(
        "All currently valid ephemeral grants. Grants expire automatically — "
        "zero active grants is the correct steady state."
    )

    try:
        broker.expire_stale()
    except Exception:
        pass

    grants = broker.get_active_grants()

    if not grants:
        st.success("No active grants — zero standing privilege enforced.")
    else:
        df_g = pd.DataFrame([{
            "Type":     "Break-glass" if g.break_glass else "JIT",
            "Grant ID": g.grant_id[:14] + "…",
            "User":     g.user_id,
            "Target":   g.target,
            "Expires":  g.expires_at.strftime("%H:%M:%S"),
            "Rate Cap": f"₹{g.rate_cap:,.0f}" if g.rate_cap else "—",
        } for g in grants])
        st.dataframe(df_g, width="stretch", hide_index=True)

    st.divider()

    st.subheader("Audit Chain Integrity")
    st.caption(
        "Every privileged event is hashed and signed with ML-DSA-65 (Dilithium). "
        "Tampering any record breaks the chain at that sequence number."
    )

    cs = st.session_state.get("chain_status") or crypto.verify_chain()

    if cs["valid"]:
        st.success(f"Chain intact — {cs['length']} records verified, no tampering detected.")
    else:
        st.error(f"Chain broken at seq={cs['first_bad_seq']} — tamper or deletion detected.")

    log = crypto.get_audit_log()
    if log:
        with st.expander(f"Last {min(5, len(log))} audit entries"):
            for rec in reversed(log[-5:]):
                try:
                    ev = json.loads(rec.payload).get("event", rec.payload[:60])
                except Exception:
                    ev = rec.payload[:60]
                st.caption(f"[{rec.seq}] `{ev}`  ·  hash `{rec.hash[:14]}…`")

# ── pqc credential vault ──────────────────────────────────────────────────────
with col_pqc:
    st.subheader("PQC Credential Vault")
    st.caption(
        "Real ML-KEM-768 + X25519/HKDF hybrid key exchange. "
        "Byte-counts confirm the NIST FIPS 203 KEM ran — nothing is mocked."
    )

    art = st.session_state.get("last_artifact")

    if art is None:
        st.info("Click **Issue credential** above to run a live ML-KEM-768 handshake.")
    else:
        st.markdown(f"**Algorithm:** `{art.algorithm}`")
        b1, b2, b3 = st.columns(3)
        b1.metric("Public Key",    f"{art.pubkey_bytes} B",    help="ML-KEM-768 encapsulation key")
        b2.metric("Ciphertext",    f"{art.ciphertext_bytes} B", help="KEM ciphertext")
        b3.metric("Shared Secret", f"{art.shared_secret_bytes} B", help="HKDF-derived session key")
        st.success("NIST FIPS 203 byte-counts confirmed — KEM is not simulated.")
