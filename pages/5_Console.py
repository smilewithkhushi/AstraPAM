"""Phase 8 — Admin / SOC mitigation console.

Every action is maker-checker'd and cryptographically logged.
Frozen/blocked users are denied new grants by broker.py.
"""
from __future__ import annotations

import requests
import streamlit as st

import _sidebar
from core import roles as roles_module

st.set_page_config(page_title="AstraPAM · Mitigation Console", page_icon="🛡", layout="wide")

API = _sidebar.API_URL

_sidebar.render_page_header(
    "🚨", "Security Response",
    "Take action on a user when something looks wrong. Freeze them temporarily, block them entirely, or revoke their session. Every action requires a reason and is permanently logged.",
)

tab_act, tab_hist = st.tabs(["Apply Action", "Action History"])

with tab_act:
    st.subheader("Apply Mitigation Action")

    ALL_USERS = roles_module.get_all_users()
    USER_MAP = {u.user_id: u for u in ALL_USERS}

    with st.form("console_form"):
        operator_id = st.selectbox(
            "Operator (SOC analyst)",
            [u.user_id for u in ALL_USERS],
            format_func=lambda uid: f"{uid}: {USER_MAP[uid].name}",
        )
        target_user_id = st.selectbox(
            "Target user",
            [u.user_id for u in ALL_USERS],
            format_func=lambda uid: f"{uid}: {USER_MAP[uid].name}",
        )
        action = st.selectbox(
            "Action",
            ["FREEZE", "BLOCK", "UNBLOCK", "HOLD", "REVOKE_SESSION", "REQUIRE_STEPUP"],
        )
        reason = st.text_area("Reason (mandatory)", placeholder="e.g. SOC-2024-001: anomalous SWIFT activity detected")
        approver_id = st.selectbox(
            "Approver (required for BLOCK)",
            [u.user_id for u in ALL_USERS],
            format_func=lambda uid: f"{uid}: {USER_MAP[uid].name}",
        )
        alert_cid = st.text_input(
            "Correlation ID of triggering alert (optional, links this action to the alert in trace)",
            value="",
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
                    st.json(data)
                else:
                    err = resp.json()
                    st.error(f"Error {resp.status_code}: {err.get('detail', resp.text)}")
            except Exception as e:
                st.error(f"Cannot reach API: {e}")

    st.divider()
    st.subheader("Verify Audit Log")
    if st.button("Verify chain"):
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
    st.subheader("Console Action History")
    st.caption("Past actions cannot be edited or deleted.")

    if st.button("Refresh history"):
        try:
            resp = requests.get(f"{API}/console/actions", timeout=5)
            actions = resp.json() if resp.ok else []
        except Exception:
            actions = []

        if not actions:
            st.info("No console actions recorded yet.")
        else:
            for a in actions:
                status_icon = {"APPLIED": "✅", "PENDING": "⏳", "REJECTED": "❌"}.get(a["status"], "?")
                action_color = {
                    "FREEZE": "🟡", "BLOCK": "🔴", "UNBLOCK": "🟢",
                    "HOLD": "🟠", "REVOKE_SESSION": "🔴", "REQUIRE_STEPUP": "🟠",
                }.get(a["action"], "🔵")
                target_user = roles_module.get_user(a["target_user_id"])
                target_name = target_user.name if target_user else a["target_user_id"]
                op_user = roles_module.get_user(a["operator_id"])
                op_name = op_user.name if op_user else a["operator_id"]

                with st.expander(
                    f"{status_icon} {action_color} **{a['action']}** → {target_name} "
                    f"| by {op_name} | `{a['timestamp'][:19]}`",
                    expanded=False,
                ):
                    st.markdown(f"**Action ID:** `{a['action_id']}`")
                    st.markdown(f"**Correlation ID:** `{a['correlation_id'] or '—'}`")
                    st.markdown(f"**Reason:** {a['reason']}")
                    st.markdown(f"**Approver:** `{a['approver_id'] or '—'}`")
                    st.markdown(f"**Status:** `{a['status']}`")
