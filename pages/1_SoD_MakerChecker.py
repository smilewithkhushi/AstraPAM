"""Phase 7 — Segregation of Duties conflict detection + maker-checker enforcement."""
from __future__ import annotations

import requests
import streamlit as st

import _sidebar
from core import roles as roles_module

st.set_page_config(page_title="AstraPAM · SoD & Maker-Checker", page_icon="🛡", layout="wide")

API = _sidebar.API_URL

_sidebar.render_page_header(
    "", "Segregation of Duties",
    "This feature catches situations where one person has too much power & access (eg: able to both create and approve a transaction). Every high-value action needs a second person to sign off.",
)

tab_sod, tab_mc = st.tabs(["SoD Conflict Scan", "Maker-Checker Requests"])

# ── SoD Conflict Scan ─────────────────────────────────────────────────────────
with tab_sod:
    st.subheader("Conflict Rules")
    st.caption("These are the four combinations we watch for. SOD-001 is the exact setup that made the PNB fraud possible.")

    sod_data = []
    for ent_a, ent_b, rule_id, severity in roles_module.SOD_MATRIX:
        sod_data.append({
            "Rule ID": rule_id,
            "Entitlement A": ent_a,
            "Entitlement B": ent_b,
            "Severity": severity.upper(),
        })
    st.table(sod_data)

    st.divider()

    _scan_left, _scan_right = st.columns(2)

    with _scan_left:
        st.subheader("Scan All Users")

        if st.button("Run Conflict Scan", type="primary"):
            try:
                resp = requests.get(f"{API}/sod/conflicts", timeout=5)
                conflicts = resp.json() if resp.ok else []
            except Exception:
                conflicts = [c.model_dump() for c in roles_module.scan_all_conflicts()]

            if not conflicts:
                st.success("No SoD conflicts detected across all users.")
            else:
                st.error(f"**{len(conflicts)} SoD conflict(s) detected.**")
                for c in conflicts:
                    badge = "🔴" if c["severity"] == "critical" else "🟠"
                    user = roles_module.get_user(c["user_id"])
                    name = user.name if user else c["user_id"]
                    st.markdown(
                        f"{badge} **{c['rule_id']}** · **{c['severity'].upper()}**: "
                        f"**{name}** (`{c['user_id']}`) holds both "
                        f"`{c['entitlement_a']}` + `{c['entitlement_b']}`"
                    )
                    if c["rule_id"] == "SOD-001":
                        st.warning(
                            "This user can create and approve Letters of Undertaking, with no one else in the loop, leaving a gap for potential fraud."
                        )


    with _scan_right:
        st.subheader("Per-User Scan")
        user_ids = [u.user_id for u in roles_module.get_all_users()]
        selected = st.selectbox("Select user", user_ids,
                                format_func=lambda uid: f"{uid}: {roles_module.get_user(uid).name}")
        if st.button("Scan user"):
            try:
                resp = requests.get(f"{API}/sod/conflicts/{selected}", timeout=5)
                conflicts = resp.json() if resp.ok else []
            except Exception:
                u = roles_module.get_user(selected)
                conflicts = [c.model_dump() for c in roles_module.scan_sod_conflicts(u)] if u else []

            if not conflicts:
                st.success(f"No SoD conflicts for {selected}.")
            else:
                for c in conflicts:
                    badge = "🔴" if c["severity"] == "critical" else "🟠"
                    st.error(
                        f"{badge} **{c['rule_id']}** ({c['severity'].upper()}): "
                        f"`{c['entitlement_a']}` + `{c['entitlement_b']}`"
                    )

# ── Maker-Checker ─────────────────────────────────────────────────────────────
with tab_mc:
    _mc_left, _mc_right = st.columns(2)

    with _mc_left:
        st.subheader("Initiate a Transaction")

        with st.form("maker_form"):
            maker_id = st.selectbox(
                "Initiating user (maker)",
                [u.user_id for u in roles_module.get_all_users()],
                format_func=lambda uid: f"{uid}: {roles_module.get_user(uid).name}",
            )
            amount = st.number_input("Amount (₹)", min_value=1.0, value=500000.0, step=10000.0)
            cid_in = st.text_input("Correlation ID (auto-generated if blank)", value="")
            submitted = st.form_submit_button("Submit", width="stretch")

        if submitted:
            try:
                resp = requests.post(f"{API}/maker-checker/submit", json={
                    "grant_id": "demo",
                    "user_id": maker_id,
                    "amount": amount,
                    "correlation_id": cid_in,
                }, timeout=5)
                if resp.ok:
                    data = resp.json()
                    if data["status"] == "APPROVED":
                        st.success(
                            f"Auto-approved. Within maker's authorisation limit. "
                            f"Correlation ID: `{data['correlation_id']}`"
                        )
                    else:
                        st.warning(
                            f"Pending checker approval. Request ID: `{data['request_id']}` · "
                            f"Correlation ID: `{data['correlation_id']}`"
                        )
                    st.json(data)
                else:
                    st.error(f"API error {resp.status_code}: {resp.text}")
            except Exception as e:
                st.error(f"Cannot reach API: {e}")

    with _mc_right:
        st.subheader("Approve or Reject")
        st.caption("Must be a different person from whoever submitted. If you try to approve your own transaction, it gets blocked automatically.")

        with st.form("checker_form"):
            req_id_in = st.text_input("Request ID")
            checker_id = st.selectbox(
                "Approving user (checker)",
                [u.user_id for u in roles_module.get_all_users()],
                format_func=lambda uid: f"{uid}: {roles_module.get_user(uid).name}",
            )
            approve = st.radio("Decision", ["Approve", "Reject"]) == "Approve"
            decide = st.form_submit_button("Submit Decision", width="stretch")

        if decide:
            try:
                resp = requests.post(f"{API}/maker-checker/decide", json={
                    "request_id": req_id_in,
                    "checker_id": checker_id,
                    "approve": approve,
                }, timeout=5)
                if resp.ok:
                    data = resp.json()
                    status = data["status"]
                    if status == "SELF_APPROVAL_BLOCKED":
                        st.error("🚫 You cannot approve your own transaction.")
                    elif status == "APPROVED":
                        st.success(f"✅ Approved by {checker_id}.")
                    else:
                        st.warning(f"Rejected by {checker_id}.")
                    st.json(data)
                else:
                    st.error(f"API error {resp.status_code}: {resp.text}")
            except Exception as e:
                st.error(f"Cannot reach API: {e}")

    st.divider()
    st.subheader("All Maker-Checker Requests")
    if st.button("Refresh list"):
        try:
            resp = requests.get(f"{API}/maker-checker/list", timeout=5)
            reqs = resp.json() if resp.ok else []
        except Exception:
            reqs = []
        if not reqs:
            st.info("No requests yet.")
        else:
            for r in reqs:
                status_icon = {"APPROVED": "✅", "REJECTED": "❌",
                               "SELF_APPROVAL_BLOCKED": "🚫", "PENDING": "⏳"}.get(r["status"], "?")
                st.markdown(
                    f"{status_icon} `{r['request_id'][:8]}…` | "
                    f"Maker: `{r['maker_id']}` | Checker: `{r['checker_id'] or '—'}` | "
                    f"₹`{r['amount']}` | **{r['status']}**"
                )
