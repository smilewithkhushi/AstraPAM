"""AstraPAM — Access Control page."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

import _sidebar
import httpx
import pandas as pd
import requests
import streamlit as st

from core import broker
from core import crypto
from core import roles as roles_module
from core.schemas import DB_PATH, AccessRequest, init_db

st.set_page_config(
    page_title="AstraPAM · Access Control",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

_sidebar.render_page_header(
    "🛡", "Access Control",
    "Nobody gets permanent access to anything. Every request is checked in real time and access expires automatically. If there are zero active grants, that's a good thing.",
)

with st.expander("📖 JIT Access lifecycle", expanded=False):
    st.image(
        "preview/diagram_zero_standing_privilege_light.png",
        width="stretch",
        caption="Zero Standing Privilege. No permanent access. Every grant is time-limited, scoped, and auto-revoked.",
    )

st.divider()

# ── JIT ACCESS REQUEST ────────────────────────────────────────────────────────
st.subheader("Request Access")

with st.container(border=True):
    col_form, col_result = st.columns([1, 1])

    with col_form:
        all_users = roles_module.get_all_users()
        user_ids = [u.user_id for u in all_users]

        req_user = st.selectbox(
            "Requesting user",
            user_ids,
            format_func=lambda uid: f"{uid}: {roles_module.get_user(uid).name}",
            key="jit_user",
        )
        req_target = st.selectbox(
            "Target system",
            ["core_banking_prod", "swift_gateway", "lou_issuance_system",
             "treasury_ledger", "audit_db", "reporting_portal"],
            key="jit_target",
        )
        req_action = st.selectbox(
            "Action type",
            ["read", "financial", "admin"],
            format_func=lambda a: {
                "read": "read: view data only",
                "financial": "financial: initiate transactions",
                "admin": "admin: system-level changes",
            }[a],
            key="jit_action",
        )

        st.markdown("**Session risk profile**")
        profile = st.radio(
            "Preset",
            ["Normal session", "Suspicious session", "Custom"],
            horizontal=True,
            key="jit_profile",
            label_visibility="collapsed",
        )

        if profile == "Normal session":
            features = _sidebar.NORMAL_FEATURES.copy()
        elif profile == "Suspicious session":
            features = _sidebar.MAL_FEATURES.copy()
        else:
            with st.expander("Configure session features"):
                features = {
                    "logon_count":    st.slider("Logon count", 0, 20, 5),
                    "after_hours":    st.slider("After-hours ratio", 0.0, 1.0, 0.0),
                    "unique_pcs":     st.slider("Unique PCs", 1, 10, 1),
                    "device_events":  st.slider("Device events", 0, 20, 0),
                    "file_events":    st.slider("File events", 0, 200, 12),
                    "http_events":    st.slider("HTTP events", 0, 200, 60),
                    "email_events":   st.slider("Email events", 0, 50, 10),
                }

        cid_jit = st.text_input(
            "Correlation ID (auto-generated if blank)",
            value="",
            key="jit_cid",
        )

        request_btn = st.button("Request Access", type="primary", width="stretch")

    with col_result:
        st.markdown("**Decision output**")

        if request_btn:
            cid = cid_jit.strip() or str(uuid.uuid4())
            payload = {
                "user_id":      req_user,
                "target":       req_target,
                "action_type":  req_action,
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "correlation_id": cid,
            }
            data = None
            try:
                resp = requests.post(
                    f"{_sidebar.API_URL}/access/request",
                    json={**payload, "features": features},
                    timeout=5,
                )
                data = resp.json() if resp.ok else None
            except Exception:
                try:
                    from schemas import AccessRequest as AR
                    req_obj = AR(
                        user_id=req_user,
                        target=req_target,
                        action_type=req_action,
                        requested_at=datetime.now(timezone.utc),
                        correlation_id=cid,
                    )
                    data = broker.request_access(req_obj, features)
                except Exception as e:
                    st.error(f"Error: {e}")

            if data:
                st.session_state["jit_result"] = {
                    "data": data, "cid": cid, "target": req_target,
                }

        result = st.session_state.get("jit_result")
        if result:
            data       = result["data"]
            cid        = result["cid"]
            req_target = result["target"]

            status   = data.get("status", "")
            risk     = data.get("risk", {})
            score    = risk.get("score", data.get("score", 0))
            decision = risk.get("decision", "deny" if "denied" in status else "allow")

            DECISION_COLOR = _sidebar.DECISION_COLOR
            DECISION_LABEL = {
                "allow":    "✅ ALLOW",
                "throttle": "⚡ THROTTLE",
                "step_up":  "🔐 STEP UP REQUIRED",
                "deny":     "🚫 DENY",
            }
            color = DECISION_COLOR.get(decision, _sidebar.C_INFO)
            label = DECISION_LABEL.get(decision, decision.upper())

            st.markdown(
                f'<div style="background:{color};color:#fff;padding:12px 20px;border-radius:6px;'
                f'font-size:1.2rem;font-weight:700;text-align:center;margin-bottom:12px">'
                f'{label}</div>',
                unsafe_allow_html=True,
            )

            m1, m2 = st.columns(2)
            m1.metric("Risk Score", f"{score:.3f}", help="0 = safe, 1 = critical")
            m2.metric("Correlation ID", f"`{cid[:10]}…`")

            if decision == "allow":
                grant = data.get("grant", {})
                expires = grant.get("expires_at", "")
                st.success(
                    f"Grant issued → `{grant.get('grant_id','')[:12]}…`  \n"
                    f"Target: `{req_target}` · Expires: `{expires[:19] if expires else '—'}`"
                )
                actor = data.get("actor", {})
                if actor.get("role"):
                    st.caption(f"Issued to: {actor['role']} @ {actor.get('branch','—')}")

            elif decision == "throttle":
                grant = data.get("grant", {})
                st.warning(
                    f"Grant issued with a rate cap of ₹1,000. Elevated risk detected.  \n"
                    f"Grant: `{grant.get('grant_id','')[:12]}…`"
                )

            elif decision == "step_up":
                st.warning(
                    "**Additional authentication required.**  \n"
                    "Grant is not issued until step-up is completed."
                )

            elif decision == "deny" or status == "denied":
                reason = data.get("reason", "Risk score exceeded threshold.")
                st.error(f"**Access denied.** {reason}")

            tags = risk.get("attack_tags", data.get("attack_tags", []))
            if tags:
                st.markdown("**Attack tags:** " + " ".join(f'`{t}`' for t in tags))

            factors = risk.get("top_factors", data.get("top_factors", []))
            if factors:
                with st.expander("SHAP risk factors"):
                    for f in factors:
                        feat    = f.get("feature", "")
                        contrib = f.get("contribution", 0)
                        bar_color = _sidebar.C_DENY if contrib > 0 else _sidebar.C_ALLOW
                        bar_width = min(abs(contrib) * 300, 100)
                        sign = "+" if contrib > 0 else ""
                        st.markdown(
                            f'<div style="display:flex;align-items:center;gap:10px;margin:3px 0">'
                            f'<span style="font-family:monospace;min-width:140px;font-size:0.8rem">{feat}</span>'
                            f'<div style="background:{bar_color};width:{bar_width}px;height:10px;border-radius:3px"></div>'
                            f'<span style="font-size:0.8rem;color:{bar_color}">{sign}{contrib:.3f}</span>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )
        else:
            st.markdown(
                '<div style="border:1px dashed #d1d5db;border-radius:6px;padding:40px;text-align:center;color:#9ca3af">'
                '<div style="font-size:2rem">🛡</div>'
                '<div style="margin-top:8px">Submit a request to see the live risk decision</div>'
                '</div>',
                unsafe_allow_html=True,
            )

st.divider()

col_grants, col_tools = st.columns([3, 2])

with col_grants:
    st.subheader("Active JIT Grants")

    try:
        broker.expire_stale()
    except Exception:
        pass

    grants = broker.get_active_grants()
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    if not grants:
        st.success("No open access at the moment. This is exactly how it should be.")
    else:
        for g in grants:
            remaining = (g.expires_at - now_utc).total_seconds()
            mins = int(remaining // 60)
            secs = int(remaining % 60)
            ttl_str = f"{mins}m {secs}s" if mins > 0 else f"{secs}s"
            urgency = _sidebar.C_DENY if remaining < 60 else (_sidebar.C_THROTTLE if remaining < 120 else _sidebar.C_ALLOW)
            badge = "🚨 BREAK-GLASS" if g.break_glass else "🔑 JIT"
            cap_str = f"₹{g.rate_cap:,.0f} cap" if g.rate_cap else "no cap"

            with st.container(border=True):
                c1, c2, c3, c4 = st.columns([2, 2, 1.5, 1])
                c1.markdown(f"**{badge}**  \n`{g.grant_id[:16]}…`")
                c2.markdown(f"**{g.user_id}** → `{g.target}`  \n{cap_str}")
                c3.markdown(
                    f'<div style="color:{urgency};font-weight:700;font-size:1.05rem">⏱ {ttl_str}</div>',
                    unsafe_allow_html=True,
                )
                with c4:
                    if st.button("Revoke", key=f"rev_{g.grant_id}", type="secondary"):
                        try:
                            requests.post(f"{_sidebar.API_URL}/access/revoke/{g.grant_id}", timeout=3)
                        except Exception:
                            broker.revoke(g.grant_id)
                        st.rerun()

    st.divider()
    st.subheader("Audit Log")

    cs = st.session_state.get("chain_status") or crypto.verify_chain()

    if cs["valid"]:
        st.success(f"Audit log is intact. {cs['length']} records checked, nothing altered.")
    else:
        st.error(f"Log tampered at seq={cs['first_bad_seq']}. Something was altered.")

    log = crypto.get_audit_log()
    if log:
        with st.expander(f"Last {min(5, len(log))} audit entries"):
            for rec in reversed(log[-5:]):
                try:
                    ev = json.loads(rec.payload).get("event", rec.payload[:60])
                except Exception:
                    ev = rec.payload[:60]
                st.caption(f"[{rec.seq}] `{ev}`  ·  hash `{rec.hash[:14]}…`")

    st.divider()
    st.subheader("Encryption Keys")

    art = st.session_state.get("last_artifact")

    if art is None:
        st.info("Click Issue Credential below to see the output.")
    else:
        st.markdown(f"**Algorithm:** `{art.algorithm}`")
        b1, b2, b3 = st.columns(3)
        b1.metric("Public Key",    f"{art.pubkey_bytes} B",     help="ML-KEM-768 encapsulation key")
        b2.metric("Ciphertext",    f"{art.ciphertext_bytes} B", help="KEM ciphertext")
        b3.metric("Shared Secret", f"{art.shared_secret_bytes} B", help="HKDF-derived session key")
        st.success("Encryption key generated using post-quantum algorithm. Not simulated.")

with col_tools:
    st.subheader("Credential Tools")

    with st.container(border=True):
        st.markdown("**Issue Credential**")
        st.caption("Generates a post-quantum encrypted key and logs it.")
        if st.button("Issue credential", width="stretch", type="primary"):
            art = crypto.issue_credential("demo_user", "grant-demo")
            st.session_state["last_artifact"] = art
            st.success(f"pk={art.pubkey_bytes}B · ct={art.ciphertext_bytes}B")

    with st.container(border=True):
        st.markdown("**Verify Audit Log**")
        st.caption("Confirms that no log entry has been altered or deleted.")
        if st.button("Verify chain", width="stretch"):
            st.session_state["chain_status"] = crypto.verify_chain()
            cs = st.session_state["chain_status"]
            if cs["valid"]:
                st.success(f"Intact, {cs['length']} records")
            else:
                st.error(f"Broken at seq={cs['first_bad_seq']}")

    with st.container(border=True):
        st.markdown("**Emergency Access**")
        st.caption("Grants access even during a high-risk situation. Still logged and auditable.")
        if st.button("Break-glass", width="stretch"):
            try:
                resp = httpx.post(
                    "http://localhost:8000/access/break-glass",
                    json={
                        "user_id":       "admin_emergency",
                        "target":        "core_banking_prod",
                        "justification": "P1 outage. Production DB locked, normal path denied.",
                        "features":      _sidebar.MAL_FEATURES,
                    },
                    timeout=5,
                )
                d = resp.json()
                st.warning(
                    f"Granted. Risk={d['risk_at_issue']['score']:.3f} "
                    f"({d['risk_at_issue']['decision'].upper()})"
                )
            except Exception as e:
                st.error(f"API unreachable: {e}")

    with st.container(border=True):
        st.markdown("**Tamper Test**")
        st.caption("Corrupts a log entry, then verify the audit log catches it.")
        t_col, r_col = st.columns(2)
        with t_col:
            if st.button("Corrupt seq 1", width="stretch"):
                con = sqlite3.connect(DB_PATH)
                rows = con.execute("SELECT seq FROM audit_records LIMIT 1").fetchall()
                if rows:
                    con.execute("UPDATE audit_records SET payload='[TAMPERED]' WHERE seq=1")
                    con.commit()
                    st.warning("Corrupted. Click Verify Audit Log to detect it.")
                else:
                    st.info("Issue a credential first")
                con.close()
        with r_col:
            if st.button("Reset chain", width="stretch"):
                con = sqlite3.connect(DB_PATH)
                con.execute("DELETE FROM audit_records")
                con.commit()
                con.close()
                st.session_state.pop("chain_status", None)
                st.session_state.pop("last_artifact", None)
                st.success("Chain reset")
                st.rerun()
