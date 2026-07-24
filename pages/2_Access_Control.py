"""AstraPAM — Access Control page."""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

import _sidebar
import httpx
import requests
import streamlit as st

from core import broker
from core import crypto
from core import roles as roles_module
from core.schemas import DB_PATH, init_db

st.set_page_config(
    page_title="AstraPAM · Access Control",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

_sidebar.render_page_header(
    "", "Access Control",
    "Nobody gets permanent access to anything. The super-admin in AstraPAM checks every request in real time and access expires automatically. Zero active grants indicate a secure system.",
)

tab_request, tab_grants, tab_audit, tab_emergency = st.tabs([
    "Request Access", "Active JIT Grants", "Audit Log & Keys", "Emergency Access"
])

# ── Tab 1: Request Access ─────────────────────────────────────────────────────
with tab_request:
    with st.expander("📖 JIT Access lifecycle", expanded=False):
        st.image(
            "preview/diagram_zero_standing_privilege_light.png",
            width="stretch",
        )

    _fa, _fb = st.columns([5, 1])
    if _fb.button("📋 Fill sample data", key="fill_jit_btn"):
        st.session_state["jit_user"]    = "user_004"
        st.session_state["jit_target"]  = "swift_gateway"
        st.session_state["jit_action"]  = "financial"
        st.session_state["jit_profile"] = "Suspicious session"
        st.session_state["jit_cid"]     = "DEMO-CID-PNB-001"
        st.rerun()

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
                    "user_id":        req_user,
                    "target":         req_target,
                    "action_type":    req_action,
                    "requested_at":   datetime.now(timezone.utc).isoformat(),
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
                        from core.schemas import AccessRequest as AR
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
                    if hasattr(expires, "isoformat"):
                        expires = expires.isoformat()
                    st.success(
                        f"Grant issued → `{grant.get('grant_id','')[:12]}…`  \n"
                        f"Target: `{req_target}` · Expires: `{str(expires)[:19] if expires else '—'}`"
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

# ── Tab 2: Active JIT Grants ──────────────────────────────────────────────────
with tab_grants:
    st.subheader("Active JIT Grants")
    st.caption("Just-In-Time access: credentials are created the moment they are needed and automatically deleted when the window closes, so there is nothing to steal in between.")

    try:
        broker.expire_stale()
    except Exception:
        pass

    grants = broker.get_active_grants()
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    if not grants:
        st.success("No open access at the moment. This is exactly how it should be.")
    else:
        # shrink button height so every grant row stays on one line
        st.markdown("""
        <style>
        div[data-testid="stHorizontalBlock"] button[kind="secondary"] {
            padding: 2px 10px !important;
            font-size: 0.72rem !important;
            min-height: 0 !important;
            height: 26px !important;
            line-height: 1 !important;
        }
        div[data-testid="stHorizontalBlock"] div[data-testid="stVerticalBlock"] {
            gap: 0 !important;
        }
        </style>
        """, unsafe_allow_html=True)

        # header row
        COLS = [0.9, 1.4, 2.2, 1.8, 0.9, 1.0, 0.8]
        HEADERS = ["Type", "Grant ID", "User", "Target", "Cap", "TTL", ""]
        hcols = st.columns(COLS)
        for hc, label in zip(hcols, HEADERS):
            hc.markdown(
                f"<span style='font-size:0.7rem;font-weight:700;color:#6b7280;"
                f"text-transform:uppercase;letter-spacing:.06em'>{label}</span>",
                unsafe_allow_html=True,
            )
        st.divider()

        for g in grants:
            remaining = (g.expires_at - now_utc).total_seconds()
            mins = int(remaining // 60)
            secs = int(remaining % 60)
            ttl_str = f"{mins}m{secs}s" if mins > 0 else f"{secs}s"
            urgency = _sidebar.C_DENY if remaining < 60 else (_sidebar.C_THROTTLE if remaining < 120 else _sidebar.C_ALLOW)
            if g.break_glass:
                badge_html = "<span style='background:#ef4444;color:#fff;font-size:0.65rem;font-weight:700;padding:1px 5px;border-radius:3px;white-space:nowrap'>🚨 BRK-GLASS</span>"
            else:
                badge_html = "<span style='background:#3b82f6;color:#fff;font-size:0.65rem;font-weight:700;padding:1px 5px;border-radius:3px'>🔑 JIT</span>"
            cap_str = f"₹{g.rate_cap:,.0f}" if g.rate_cap else "—"
            user_obj = roles_module.get_user(g.user_id)
            user_label = (user_obj.name if user_obj else g.user_id) + f" <span style='color:#9ca3af'>({g.user_id})</span>"

            c1, c2, c3, c4, c5, c6, c7 = st.columns(COLS)
            c1.markdown(badge_html, unsafe_allow_html=True)
            c2.markdown(f"<span style='font-family:monospace;font-size:0.72rem;color:#374151'>{g.grant_id[:12]}…</span>", unsafe_allow_html=True)
            c3.markdown(f"<span style='font-size:0.78rem'>{user_label}</span>", unsafe_allow_html=True)
            c4.markdown(f"<span style='font-family:monospace;font-size:0.75rem;color:#374151'>{g.target}</span>", unsafe_allow_html=True)
            c5.markdown(f"<span style='font-size:0.78rem'>{cap_str}</span>", unsafe_allow_html=True)
            c6.markdown(
                f"<span style='color:{urgency};font-weight:700;font-size:0.78rem'>⏱ {ttl_str}</span>",
                unsafe_allow_html=True,
            )
            with c7:
                if st.button("Revoke", key=f"rev_{g.grant_id}", type="secondary"):
                    try:
                        requests.post(f"{_sidebar.API_URL}/access/revoke/{g.grant_id}", timeout=3)
                    except Exception:
                        broker.revoke(g.grant_id)
                    st.rerun()
            st.markdown("<hr style='margin:1px 0;border-color:#f3f4f6'>", unsafe_allow_html=True)

# ── Tab 3: Audit Log & Keys ───────────────────────────────────────────────────
with tab_audit:

    # ── Chain integrity banner ────────────────────────────────────────────────
    cs = st.session_state.get("chain_status") or crypto.verify_chain()
    if cs["valid"]:
        st.success(f"Audit chain intact · {cs['length']} blocks verified · nothing altered")
    else:
        st.error(f"Chain broken at block #{cs['first_bad_seq']} — tampering detected")

    # ── Blockchain visualization ──────────────────────────────────────────────
    st.subheader("Audit Chain")
    st.caption("Each block's hash is computed from its payload + the previous block's hash. Altering any record invalidates every block that follows it.")

    audit_log = crypto.get_audit_log()
    if not audit_log:
        st.info("No audit blocks yet. Issue a credential or submit an access request to create the first block.")
    else:
        DECISION_BLOCK = {
            "allow":   ("#f0fdf4", "#22c55e", "#16a34a"),
            "throttle":("#fffbeb", "#f59e0b", "#d97706"),
            "step_up": ("#eff6ff", "#3b82f6", "#2563eb"),
            "deny":    ("#fef2f2", "#ef4444", "#dc2626"),
        }
        DEFAULT_BLOCK  = ("#f8fafc", "#6b7280", "#374151")

        for row_start in range(0, len(audit_log), 3):
            row_blocks = audit_log[row_start:row_start + 3]
            cols = st.columns(3)
            for col, rec in zip(cols, row_blocks):
                try:
                    pl       = json.loads(rec.payload)
                    event    = pl.get("event", "unknown")
                    user_id  = pl.get("user_id", "")
                    decision = pl.get("decision", pl.get("risk_decision", ""))
                    score    = pl.get("score",    pl.get("risk_score", ""))
                    target   = pl.get("target",   "")
                    cid      = pl.get("correlation_id", "")
                except Exception:
                    event = rec.payload[:40]
                    user_id = decision = score = target = cid = ""

                is_genesis = not rec.prev_hash or rec.prev_hash == "0" * 64
                bg, border, text = (
                    ("#fef2f2", "#ef4444", "#991b1b") if "break_glass" in event
                    else DECISION_BLOCK.get(decision, DEFAULT_BLOCK)
                )

                user_obj   = roles_module.get_user(user_id)
                user_label = (f"{user_obj.name}<br>({user_id})" if user_obj else user_id) if user_id else ""

                rows_html = ""
                if user_label:
                    rows_html += f"<tr><td style=\"color:#6b7280;white-space:nowrap;padding-right:6px\">User</td><td style=\"font-size:0.72rem\">{user_label}</td></tr>"
                if target:
                    rows_html += f"<tr><td style=\"color:#6b7280;white-space:nowrap;padding-right:6px\">Target</td><td style=\"font-family:monospace;font-size:0.7rem\">{target}</td></tr>"
                if decision:
                    rows_html += f"<tr><td style=\"color:#6b7280;white-space:nowrap;padding-right:6px\">Decision</td><td style=\"font-weight:700;color:{border}\">{decision.upper()}</td></tr>"
                if score != "":
                    rows_html += f"<tr><td style=\"color:#6b7280;white-space:nowrap;padding-right:6px\">Risk</td><td>{float(score):.3f}</td></tr>"
                if cid:
                    rows_html += f"<tr><td style=\"color:#6b7280;white-space:nowrap;padding-right:6px\">CID</td><td style=\"font-family:monospace;font-size:0.65rem\">{cid[:16]}…</td></tr>"

                genesis_tag = "&nbsp;<span style=\"background:#7c3aed;color:#fff;font-size:0.58rem;padding:1px 4px;border-radius:3px\">GENESIS</span>" if is_genesis else ""
                prev_color  = "#7c3aed" if is_genesis else "#374151"
                prev_val    = "GENESIS" if is_genesis else rec.prev_hash[:20] + "…"

                block_html = (
                    f"<div style=\"border:1.5px solid {border};border-radius:8px;background:{bg};padding:10px 12px;height:100%;box-sizing:border-box\">"
                    f"<div style=\"font-size:0.62rem;font-weight:700;color:{border};margin-bottom:2px\">BLOCK #{rec.seq}{genesis_tag}</div>"
                    f"<div style=\"font-weight:700;font-size:0.78rem;color:{text};margin-bottom:6px\">{event.replace('_',' ').upper()}</div>"
                    f"<table style=\"font-size:0.73rem;width:100%;border-collapse:collapse;margin-bottom:7px\">{rows_html}</table>"
                    f"<div style=\"font-size:0.62rem;border-top:1px solid {border}40;padding-top:5px;word-break:break-all\">"
                    f"<span style=\"color:#6b7280\">hash </span><code style=\"font-size:0.6rem;color:#374151\">{rec.hash[:32]}…</code><br>"
                    f"<span style=\"color:#6b7280\">prev </span><code style=\"font-size:0.6rem;color:{prev_color}\">{prev_val}</code>"
                    f"</div></div>"
                )
                with col:
                    st.markdown(block_html, unsafe_allow_html=True)
            st.markdown("<div style=\"height:8px\"></div>", unsafe_allow_html=True)

    st.divider()

    # ── Access Request History ────────────────────────────────────────────────
    st.subheader("Access Request History")
    st.caption("Every access decision logged — allows, denials, step-ups, throttles, and break-glass events.")

    con  = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT requested_at, user_id, target, action_type, decision, risk_score,"
        "       attack_tags, grant_id, break_glass, correlation_id"
        " FROM access_request_log ORDER BY requested_at DESC LIMIT 200"
    ).fetchall()
    con.close()

    if not rows:
        st.info("No access requests logged yet.")
    else:
        import pandas as pd

        DECISION_EMOJI = {"allow": "✅", "throttle": "⚡", "step_up": "🔐", "deny": "🚫"}

        records = []
        for r in rows:
            uid      = r[1]
            uobj     = roles_module.get_user(uid)
            uname    = f"{uobj.name} ({uid})" if uobj else uid
            tags_raw = r[6]
            try:
                tags = ", ".join(json.loads(tags_raw)) if tags_raw and tags_raw != "[]" else "—"
            except Exception:
                tags = "—"
            dec   = r[4]
            gid   = r[7]
            records.append({
                "Time":           r[0][:19].replace("T", " "),
                "User":           uname,
                "Target":         r[2],
                "Action":         r[3],
                "Decision":       f"{DECISION_EMOJI.get(dec, '')} {dec.upper()}",
                "Risk Score":     f"{r[5]:.3f}",
                "Attack Tags":    tags,
                "Grant ID":       (gid[:14] + "…") if gid else "—",
                "Break Glass":    "🚨 Yes" if r[8] else "No",
                "Correlation ID": r[9][:20] + "…" if r[9] else "—",
            })

        st.dataframe(pd.DataFrame(records), use_container_width=True, hide_index=True)

    st.divider()

    # ── Tools row ────────────────────────────────────────────────────────────
    st.subheader("Tools")
    t1, t2, t3 = st.columns(3)

    with t1:
        with st.container(border=True):
            st.markdown("**Issue Credential**")
            st.caption("Generates a one-time post-quantum encrypted key pair for a JIT grant session. The shared secret protects the credential in transit — even a future quantum computer cannot decrypt it.")
            if st.button("Issue credential", width="stretch", type="primary"):
                art = crypto.issue_credential("demo_user", "grant-demo")
                st.session_state["last_artifact"] = art
                st.success("Credential issued and logged to the audit chain.")
                st.markdown(
                    f"<table style='font-size:0.76rem;width:100%;border-collapse:collapse;margin-top:6px'>"
                    f"<tr><td style='color:#6b7280;padding:3px 8px 3px 0;white-space:nowrap'>Algorithm</td>"
                    f"<td><code>{art.algorithm}</code> — post-quantum key encapsulation</td></tr>"
                    f"<tr><td style='color:#6b7280;padding:3px 8px 3px 0;white-space:nowrap'>Public Key</td>"
                    f"<td><b>{art.pubkey_bytes} B</b> — sent to the recipient to wrap the secret</td></tr>"
                    f"<tr><td style='color:#6b7280;padding:3px 8px 3px 0;white-space:nowrap'>Ciphertext</td>"
                    f"<td><b>{art.ciphertext_bytes} B</b> — encrypted blob returned by the recipient</td></tr>"
                    f"<tr><td style='color:#6b7280;padding:3px 8px 3px 0;white-space:nowrap'>Shared Secret</td>"
                    f"<td><b>{art.shared_secret_bytes} B</b> — HKDF-derived key used to encrypt this grant session; never transmitted</td></tr>"
                    f"<tr><td style='color:#6b7280;padding:3px 8px 3px 0;white-space:nowrap'>Logged to</td>"
                    f"<td>Audit chain (see block added above)</td></tr>"
                    f"</table>",
                    unsafe_allow_html=True,
                )

    with t2:
        with st.container(border=True):
            st.markdown("**Verify Audit Chain**")
            st.caption("Confirms that no log entry has been altered or deleted.")
            if st.button("Verify chain", width="stretch"):
                st.session_state["chain_status"] = crypto.verify_chain()
                cs = st.session_state["chain_status"]
                if cs["valid"]:
                    st.success(f"Intact · {cs['length']} blocks")
                else:
                    st.error(f"Broken at #{cs['first_bad_seq']}")

    with t3:
        with st.container(border=True):
            st.markdown("**Tamper Test**")
            st.caption("Corrupts block #1 to verify the chain detects it.")
            tc1, tc2 = st.columns(2)
            with tc1:
                if st.button("Corrupt", width="stretch"):
                    con = sqlite3.connect(DB_PATH)
                    rows_t = con.execute("SELECT seq FROM audit_records LIMIT 1").fetchall()
                    if rows_t:
                        con.execute("UPDATE audit_records SET payload='[TAMPERED]' WHERE seq=1")
                        con.commit()
                        st.warning("Corrupted.")
                    else:
                        st.info("No blocks yet.")
                    con.close()
            with tc2:
                if st.button("Reset", width="stretch"):
                    con = sqlite3.connect(DB_PATH)
                    con.execute("DELETE FROM audit_records")
                    con.commit()
                    con.close()
                    st.session_state.pop("chain_status", None)
                    st.session_state.pop("last_artifact", None)
                    st.success("Reset.")
                    st.rerun()


# ── Tab 4: Emergency Access ───────────────────────────────────────────────────
with tab_emergency:
    st.subheader("Emergency Access")
    st.caption("Break-glass grants immediate access even during a high-risk situation. Every break-glass event is permanently logged and auditable — misuse will be detected.")

    with st.container(border=True):
        st.warning("**Use only for genuine P1/P2 incidents.** This action is logged with your identity and timestamp and cannot be undone.")
        if st.button("Trigger Break-Glass Access", type="primary", width="stretch"):
            try:
                resp = httpx.post(
                    f"{_sidebar.API_URL}/access/break-glass",
                    json={
                        "user_id":       "admin_emergency",
                        "target":        "core_banking_prod",
                        "justification": "P1 outage. Production DB locked, normal path denied.",
                        "features":      _sidebar.MAL_FEATURES,
                    },
                    timeout=5,
                )
                resp.raise_for_status()
                d = resp.json()
                st.warning(
                    f"Granted. Risk={d['risk_at_issue']['score']:.3f} "
                    f"({d['risk_at_issue']['decision'].upper()})"
                )
            except Exception:
                d = broker.break_glass_access(
                    user_id="admin_emergency",
                    target="core_banking_prod",
                    justification="P1 outage. Production DB locked, normal path denied.",
                    session_features=_sidebar.MAL_FEATURES,
                )
                risk = d.get("risk_at_issue", {})
                st.warning(
                    f"Granted (local). Risk={risk.get('score', 0):.3f} "
                    f"({risk.get('decision', '—').upper()}) · "
                    f"Grant: `{d.get('grant', {}).get('grant_id', '')[:12]}…`"
                )
                st.rerun()
