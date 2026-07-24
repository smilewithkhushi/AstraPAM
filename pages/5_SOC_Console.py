"""Phase 8 — Admin / SOC mitigation console.

Every action is maker-checker'd and cryptographically logged.
Frozen/blocked users are denied new grants by broker.py.
"""
from __future__ import annotations

import pandas as pd
import requests
import streamlit as st

import _sidebar
from core import roles as roles_module

API = _sidebar.API_URL

_sidebar.render_page_header(
    "", "SOC (Security Operations Center) Console",
    "Security Operations Center is the team responsible for acting on live threats shared by the risk engine or a reconciliation alert. "
    "Here they can freeze a bank employee's access temporarily, block them entirely, or revoke an active session. "
    "Every action requires a written reason, and high-impact actions like BLOCK need a second person to approve before they take effect.",
)

tab_act, tab_hist = st.tabs(["Apply Action", "Action History"])

with tab_act:
    _act_col, _demo_col = st.columns([4, 1])
    _act_col.subheader("Apply Mitigation Action")
    if _demo_col.button("Try Demo Scenario", width="stretch"):
        st.session_state["console_operator"] = "user_006"
        st.session_state["console_target"]   = "user_007"
        st.session_state["console_action"]   = "FREEZE"
        st.session_state["console_reason"]   = (
            "SOC-2025-001: Risk engine flagged anomalous SWIFT access outside business hours "
            "from multiple terminals. Temporary freeze pending investigation."
        )
        st.session_state["console_approver"] = "user_001"
        st.session_state["console_cid"]      = ""
        st.rerun()
    st.caption("Pre-fills a realistic SOC freeze scenario using seeded bank identities. Submit it to see the full audit flow.")

    ALL_USERS = roles_module.get_all_users()
    USER_MAP = {u.user_id: u for u in ALL_USERS}

    with st.form("console_form"):
        operator_id = st.selectbox(
            "Operator (SOC analyst)",
            [u.user_id for u in ALL_USERS],
            format_func=lambda uid: f"{uid}: {USER_MAP[uid].name}",
            key="console_operator",
        )
        target_user_id = st.selectbox(
            "Target bank employee",
            [u.user_id for u in ALL_USERS],
            format_func=lambda uid: f"{uid}: {USER_MAP[uid].name}",
            key="console_target",
        )
        action = st.selectbox(
            "Action",
            ["FREEZE", "BLOCK", "UNBLOCK", "HOLD", "REVOKE_SESSION", "REQUIRE_STEPUP"],
            key="console_action",
        )
        reason = st.text_area(
            "Reason (mandatory)",
            placeholder="e.g. SOC-2024-001: anomalous SWIFT activity detected",
            key="console_reason",
        )
        approver_id = st.selectbox(
            "Approver (required for BLOCK)",
            [u.user_id for u in ALL_USERS],
            format_func=lambda uid: f"{uid}: {USER_MAP[uid].name}",
            key="console_approver",
        )
        alert_cid = st.text_input(
            "Correlation ID of triggering alert (optional, links this action to the alert in trace)",
            key="console_cid",
        )
        submit = st.form_submit_button("Apply Action", type="primary")

    if submit:
        if not reason.strip():
            st.error("Reason is mandatory.")
        else:
            payload = {
                "operator_id": operator_id,
                "target_user_id": target_user_id,
                "action": action,
                "reason": reason,
                "approver_id": approver_id if action == "BLOCK" else None,
                "correlation_id": alert_cid,
            }
            try:
                resp = requests.post(f"{API}/console/action", json=payload, timeout=5)
                if resp.ok:
                    data = resp.json()
                    st.success(
                        f"✅ Action recorded. Status: **{data['status']}** | "
                        f"Action ID: `{data['action_id']}`"
                    )
                    if data["status"] == "APPLIED":
                        st.info(
                            f"**{action}** applied to `{target_user_id}`. "
                            f"Their next access request will be {'denied' if action in ('FREEZE', 'BLOCK') else 'affected'}."
                        )
                    elif data["status"] == "PENDING":
                        st.warning(
                            "Action is pending. A second approver must confirm before it takes effect."
                        )
                else:
                    err = resp.json()
                    st.error(f"Error {resp.status_code}: {err.get('detail', resp.text)}")
            except Exception as e:
                st.error(f"Cannot reach API: {e}")

    st.divider()
    _va_title, _va_btn = st.columns([4, 1])
    _va_title.subheader("Verify Audit Log")
    _va_title.caption("Replays every audit record and verifies the cryptographic hash chain is unbroken.")
    with _va_btn:
        st.markdown("&nbsp;", unsafe_allow_html=True)
        verify_clicked = st.button("Verify chain", width="stretch", key="verify_chain")
    if verify_clicked:
        try:
            resp = requests.get(f"{API}/crypto/verify", timeout=5)
            result = resp.json()
            if result.get("valid"):
                st.success(f"✅ Audit log is intact. {result['length']} records, nothing altered.")
            else:
                st.error(f"❌ Chain broken at seq={result.get('first_bad_seq')}. Tamper detected.")
        except Exception as e:
            st.error(f"Cannot reach API: {e}")

with tab_hist:
    _h_title, _h_btn = st.columns([5, 1])
    _h_title.subheader("Console Action History")
    _h_title.caption("Past actions cannot be edited or deleted.")
    _h_btn.button("Refresh", width="stretch")

    _STATUS_LABEL = {"APPLIED": "✅ Applied", "PENDING": "⏳ Pending", "REJECTED": "❌ Rejected"}
    _ACTION_LABEL = {
        "FREEZE":         "🟡 Freeze",
        "BLOCK":          "🔴 Block",
        "UNBLOCK":        "🟢 Unblock",
        "HOLD":           "🟠 Hold",
        "REVOKE_SESSION": "🔴 Revoke Session",
        "REQUIRE_STEPUP": "🟠 Require Step-Up",
    }

    try:
        resp = requests.get(f"{API}/console/actions", timeout=5)
        actions = resp.json() if resp.ok else []
    except Exception:
        actions = []

    if not actions:
        st.info("No console actions recorded yet.")
    else:
        rows = []
        for a in actions:
            target_user = roles_module.get_user(a["target_user_id"])
            target_name = f"{target_user.name} ({a['target_user_id']})" if target_user else a["target_user_id"]
            op_user = roles_module.get_user(a["operator_id"])
            op_name = f"{op_user.name} ({a['operator_id']})" if op_user else a["operator_id"]
            approver = roles_module.get_user(a.get("approver_id") or "")
            approver_name = approver.name if approver else "—"
            rows.append({
                "Status":          _STATUS_LABEL.get(a["status"], a["status"]),
                "Action":          _ACTION_LABEL.get(a["action"], a["action"]),
                "Target Employee": target_name,
                "Operator":        op_name,
                "Reason":          a["reason"],
                "Approver":        approver_name,
                "Timestamp":       a["timestamp"][:19].replace("T", " "),
            })
        st.dataframe(
            pd.DataFrame(rows),
            width="stretch",
            hide_index=True,
            column_config={
                "Status":          st.column_config.TextColumn("Status",          width="small"),
                "Action":          st.column_config.TextColumn("Action",          width="small"),
                "Target Employee": st.column_config.TextColumn("Target Employee", width="medium"),
                "Operator":        st.column_config.TextColumn("Operator",        width="medium"),
                "Reason":          st.column_config.TextColumn("Reason",          width="large"),
                "Approver":        st.column_config.TextColumn("Approver",        width="small"),
                "Timestamp":       st.column_config.TextColumn("Timestamp",       width="medium"),
            },
        )
