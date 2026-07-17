"""Phase 7 — Segregation of Duties conflict detection + maker-checker enforcement."""
from __future__ import annotations

import requests
import streamlit as st

import _sidebar
import roles as roles_module

st.set_page_config(page_title="SoD & Maker-Checker", page_icon="⚖️", layout="wide")

API = _sidebar.API_URL

_sidebar.render_page_header(
    "⚖️", "Segregation of Duties & Maker-Checker",
    "Detects toxic entitlement combinations — such as a single employee holding both ISSUE_LOU and APPROVE_LOU — before any fraudulent transaction can occur. This is the exact control that was absent during the ₹14,000 Cr PNB fraud.",
    "Maker-Checker enforces dual authorisation at the transaction level: every high-value action requires a separate approver, and self-approval is hard-blocked by the system with no override path.",
)

tab_sod, tab_mc = st.tabs(["SoD Conflict Scan", "Maker-Checker Requests"])

# ── SoD Conflict Scan ─────────────────────────────────────────────────────────
with tab_sod:
    st.subheader("SoD Conflict Rules")
    st.caption(
        "The four forbidden entitlement pairs built into AstraPAM's Finacle-grounded control matrix. "
        "Any user whose effective entitlements include both columns A and B for a given rule is in violation. "
        "`SOD-001` is the exact combination that made the PNB fraud structurally possible."
    )

    sod_data = []
    for ent_a, ent_b, rule_id, severity in roles_module.SOD_MATRIX:
        sod_data.append({
            "Rule ID": rule_id,
            "Entitlement A": ent_a,
            "Entitlement B": ent_b,
            "Severity": severity.upper(),
        })
    st.table(sod_data)

    _scan_left, _scan_right = st.columns(2)

    with _scan_left:
        st.subheader("Live Conflict Scan — All Users")
        st.caption(
            "Scans every seeded user's effective entitlements (role entitlements + any extra privileges granted) "
            "against the SoD rule matrix. A match means one person holds a toxic pair — flag raised immediately, "
            "no fraudulent action required to trigger it."
        )

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
                        f"{badge} **{c['rule_id']}** · **{c['severity'].upper()}** — "
                        f"**{name}** (`{c['user_id']}`) holds both "
                        f"`{c['entitlement_a']}` + `{c['entitlement_b']}`"
                    )
                    if c["rule_id"] == "SOD-001":
                        st.warning(
                            "This is the **PNB combination**: a single identity can both issue "
                            "and approve Letters of Undertaking — the structural flaw that enabled "
                            "₹11,400 Cr in unauthorised LoUs over 7 years. "
                            "The system flags this before any fraudulent action."
                        )

    with _scan_right:
        st.subheader("Per-User Conflict Scan")
        st.caption("Drill into a specific user to see which rules they violate and which entitlements are in conflict.")
        user_ids = [u.user_id for u in roles_module.get_all_users()]
        selected = st.selectbox("Select user", user_ids,
                                format_func=lambda uid: f"{uid} — {roles_module.get_user(uid).name}")
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
        st.subheader("Submit Financial Action (Maker)")
        st.caption(
            "The **maker** is the person initiating the financial action. "
            "If the amount is within their authorisation limit, the system auto-approves it. "
            "If it exceeds the limit, the request enters `PENDING` state and must be reviewed by a separate checker — "
            "the maker cannot approve it themselves."
        )

        with st.form("maker_form"):
            maker_id = st.selectbox(
                "Maker (initiating user)",
                [u.user_id for u in roles_module.get_all_users()],
                format_func=lambda uid: f"{uid} — {roles_module.get_user(uid).name}",
            )
            amount = st.number_input("Amount (₹)", min_value=1.0, value=500000.0, step=10000.0)
            cid_in = st.text_input("Correlation ID (optional — generated if blank)", value="")
            submitted = st.form_submit_button("Submit", use_container_width=True)

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
                            f"Auto-approved (within maker's auth_limit). "
                            f"Correlation ID: `{data['correlation_id']}`"
                        )
                    else:
                        st.warning(
                            f"Requires checker approval. Request ID: `{data['request_id']}` | "
                            f"Correlation ID: `{data['correlation_id']}`"
                        )
                    st.json(data)
                else:
                    st.error(f"API error {resp.status_code}: {resp.text}")
            except Exception as e:
                st.error(f"Cannot reach API: {e}")

    with _mc_right:
        st.subheader("Checker Decision")
        st.caption(
            "The **checker** is the second person who reviews and approves or rejects a pending request. "
            "They must be a different user from the maker — if the same user ID is submitted, "
            "the system returns `SELF_APPROVAL_BLOCKED` and the transaction is halted. "
            "No override exists; a genuinely different approver is required."
        )

        with st.form("checker_form"):
            req_id_in = st.text_input("Request ID")
            checker_id = st.selectbox(
                "Checker (approving user)",
                [u.user_id for u in roles_module.get_all_users()],
                format_func=lambda uid: f"{uid} — {roles_module.get_user(uid).name}",
            )
            approve = st.radio("Decision", ["Approve", "Reject"]) == "Approve"
            decide = st.form_submit_button("Submit Decision", use_container_width=True)

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
                        st.error("🚫 **SELF_APPROVAL_BLOCKED** — the checker and maker cannot be the same person.")
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
