"""Phase 7 — Segregation of Duties conflict detection + maker-checker enforcement."""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone

import requests
import streamlit as st

import _sidebar
from core import roles as roles_module
from core.schemas import DB_PATH, init_db

init_db()

# ── SQLite helpers ────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _upsert_conflicts(conflicts: list[dict]) -> None:
    now = _now()
    con = sqlite3.connect(DB_PATH)
    for c in conflicts:
        existing = con.execute(
            "SELECT first_detected_at, status FROM sod_conflicts WHERE rule_id=? AND user_id=?",
            (c["rule_id"], c["user_id"]),
        ).fetchone()
        if existing:
            first_detected, current_status = existing
            # preserve status if already actioned; update last_scanned_at
            con.execute(
                "UPDATE sod_conflicts SET last_scanned_at=?, entitlement_a=?, entitlement_b=?, severity=?"
                " WHERE rule_id=? AND user_id=?",
                (now, c["entitlement_a"], c["entitlement_b"], c["severity"],
                 c["rule_id"], c["user_id"]),
            )
        else:
            con.execute(
                "INSERT INTO sod_conflicts"
                " (rule_id, user_id, entitlement_a, entitlement_b, severity, status, first_detected_at, last_scanned_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (c["rule_id"], c["user_id"], c["entitlement_a"], c["entitlement_b"],
                 c["severity"], "UNRESOLVED", now, now),
            )
    con.commit()
    con.close()


def _load_sod_history() -> list[dict]:
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT rule_id, user_id, entitlement_a, entitlement_b, severity, status,"
        " first_detected_at, last_scanned_at, resolved_at"
        " FROM sod_conflicts ORDER BY last_scanned_at DESC"
    ).fetchall()
    con.close()
    cols = ("rule_id", "user_id", "entitlement_a", "entitlement_b", "severity",
            "status", "first_detected_at", "last_scanned_at", "resolved_at")
    return [dict(zip(cols, r)) for r in rows]


def _update_conflict_status(rule_id: str, user_id: str, new_status: str) -> None:
    con = sqlite3.connect(DB_PATH)
    resolved_at = _now() if new_status == "RESOLVED" else None
    con.execute(
        "UPDATE sod_conflicts SET status=?, resolved_at=? WHERE rule_id=? AND user_id=?",
        (new_status, resolved_at, rule_id, user_id),
    )
    con.commit()
    con.close()


def _mc_submit(user_id: str, amount: float, correlation_id: str) -> dict:
    cid    = correlation_id.strip() or str(uuid.uuid4())
    req_id = str(uuid.uuid4())
    now    = _now()
    con    = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO maker_checker_reqs"
        " (request_id, correlation_id, maker_id, checker_id, action_type, amount, status, created_at, decided_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (req_id, cid, user_id, None, "financial_transfer", amount, "SUBMITTED", now, None),
    )
    con.commit()
    con.close()
    return {"status": "SUBMITTED", "request_id": req_id, "correlation_id": cid}


def _mc_decide(request_id: str, checker_id: str, approve: bool) -> dict:
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT maker_id, status FROM maker_checker_reqs WHERE request_id=?",
        (request_id,),
    ).fetchone()
    if not row:
        con.close()
        return {"status": "NOT_FOUND", "request_id": request_id}
    maker_id, current_status = row
    if current_status in ("APPROVED", "REJECTED"):
        con.close()
        return {"status": "ALREADY_DECIDED", "request_id": request_id, "current_status": current_status}
    if maker_id == checker_id:
        con.close()
        return {"status": "SELF_APPROVAL_BLOCKED", "request_id": request_id}
    new_status = "APPROVED" if approve else "REJECTED"
    con.execute(
        "UPDATE maker_checker_reqs SET checker_id=?, status=?, decided_at=? WHERE request_id=?",
        (checker_id, new_status, _now(), request_id),
    )
    con.commit()
    con.close()
    return {"request_id": request_id, "status": new_status, "checker_id": checker_id}


def _mc_list() -> list[dict]:
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT request_id, correlation_id, maker_id, checker_id, amount, status, created_at"
        " FROM maker_checker_reqs ORDER BY created_at DESC"
    ).fetchall()
    con.close()
    cols = ("request_id", "correlation_id", "maker_id", "checker_id", "amount", "status", "created_at")
    return [dict(zip(cols, r)) for r in rows]

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

    import pandas as pd

    _SEVERITY_BADGE = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "medium": "🟡 MEDIUM"}
    _STATUS_LABEL = {
        "UNRESOLVED":        "🔴 Unresolved",
        "UNDER_REVIEW":      "🟡 Under Review",
        "ESCALATED":         "🟠 Escalated to CISO",
        "EXCEPTION_APPROVED":"🔵 Exception Approved",
        "RESOLVED":          "✅ Resolved",
    }
    _VALID_STATUSES = list(_STATUS_LABEL.keys())

    _scan_title, _scan_btn_col = st.columns([2, 1])
    _scan_title.subheader("Scan All Users")
    _run_scan = _scan_btn_col.button("Run Conflict Scan", type="primary", use_container_width=True)

    if _run_scan:
        try:
            resp = requests.get(f"{API}/sod/conflicts", timeout=5)
            fresh = resp.json() if resp.ok else []
        except Exception:
            fresh = [c.model_dump() for c in roles_module.scan_all_conflicts()]
        _upsert_conflicts(fresh)
        if not fresh:
            st.success("No SoD conflicts detected. All clear.")

    # always load from DB so results persist across reruns
    history = _load_sod_history()
    if history:
        unresolved = [h for h in history if h["status"] not in ("RESOLVED", "EXCEPTION_APPROVED")]
        if unresolved:
            has_sod001 = any(h["rule_id"] == "SOD-001" for h in unresolved)
            st.error(f"**{len(unresolved)} active conflict(s) on record.**")
           
        rows = []
        for h in history:
            user = roles_module.get_user(h["user_id"])
            name = user.name if user else h["user_id"]
            rows.append({
                "Rule ID":        h["rule_id"],
                "Severity":       _SEVERITY_BADGE.get(h["severity"], h["severity"].upper()),
                "User":           f"{name} ({h['user_id']})",
                "Entitlement A":  h["entitlement_a"],
                "Entitlement B":  h["entitlement_b"],
                "Status":         _STATUS_LABEL.get(h["status"], h["status"]),
                "First Detected": h["first_detected_at"][:19].replace("T", " "),
                "Last Scanned":   h["last_scanned_at"][:19].replace("T", " "),
                "Resolved At":    (h["resolved_at"] or "—")[:19].replace("T", " "),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        st.caption("Update status of a conflict:")
        _uc1, _uc2, _uc3, _uc4 = st.columns([2, 1, 2, 1])
        _sel_user = _uc1.selectbox(
            "User", [h["user_id"] for h in history],
            format_func=lambda uid: f"{uid}: {roles_module.get_user(uid).name if roles_module.get_user(uid) else uid}",
            key="status_user",
        )
        _sel_rule = _uc2.selectbox(
            "Rule", [h["rule_id"] for h in history if h["user_id"] == _sel_user],
            key="status_rule",
        )
        _new_status = _uc3.selectbox("New status", _VALID_STATUSES,
                                     format_func=lambda s: _STATUS_LABEL[s],
                                     key="new_status")
        _uc4.markdown("&nbsp;", unsafe_allow_html=True)
        if _uc4.button("Update", key="update_status_btn", use_container_width=True, type="primary"):
            _update_conflict_status(_sel_rule, _sel_user, _new_status)
            st.rerun()

    st.divider()

    _pu_title, _pu_btn_col = st.columns([2, 1])
    _pu_title.subheader("Per-User Scan")
    user_ids = [u.user_id for u in roles_module.get_all_users()]
    _pu_left, _pu_right = st.columns([2, 1])
    selected = _pu_left.selectbox("Select user", user_ids,
                                   format_func=lambda uid: f"{uid}: {roles_module.get_user(uid).name}",
                                   key="per_user_select")
    _scan_user = _pu_right.button("Scan user", use_container_width=True)
    if _scan_user:
        try:
            resp = requests.get(f"{API}/sod/conflicts/{selected}", timeout=5)
            per_conflicts = resp.json() if resp.ok else []
        except Exception:
            u = roles_module.get_user(selected)
            per_conflicts = [c.model_dump() for c in roles_module.scan_sod_conflicts(u)] if u else []
        _upsert_conflicts(per_conflicts)

    # load this user's history from DB
    per_history = [h for h in _load_sod_history() if h["user_id"] == selected]
    if not per_history:
        st.info(f"No conflicts on record for {roles_module.get_user(selected).name if roles_module.get_user(selected) else selected}. Run a scan to check.")
    else:
        uname = roles_module.get_user(selected)
        active = [h for h in per_history if h["status"] not in ("RESOLVED", "EXCEPTION_APPROVED")]
        if active:
            st.error(f"**{len(active)} active conflict(s) for {uname.name if uname else selected}.**")
        else:
            st.success(f"All conflicts for {uname.name if uname else selected} are resolved.")
        per_rows = [{
            "Rule ID":       h["rule_id"],
            "Severity":      _SEVERITY_BADGE.get(h["severity"], h["severity"].upper()),
            "Entitlement A": h["entitlement_a"],
            "Entitlement B": h["entitlement_b"],
            "Status":        _STATUS_LABEL.get(h["status"], h["status"]),
            "Last Scanned":  h["last_scanned_at"][:19].replace("T", " "),
        } for h in per_history]
        st.dataframe(pd.DataFrame(per_rows), use_container_width=True, hide_index=True)

# ── Maker-Checker ─────────────────────────────────────────────────────────────
with tab_mc:
    _mc_left, _mc_right = st.columns(2, gap="large")

    with _mc_left:
        _ml_title, _ml_fill = st.columns([4, 1])
        _ml_title.subheader("Initiate a Transaction")
        if _ml_fill.button("📋 Fill data", key="fill_maker_btn"):
            st.session_state["mc_maker_id"] = "user_004"
            st.session_state["mc_amount"]   = 500000.0
            st.session_state["mc_cid"]      = "DEMO-TXN-PNB-001"
            st.rerun()
        st.caption("The person who submits a transaction cannot also approve it. Amounts above ₹1,00,000 require a separate checker to sign off before they go through.")

        with st.form("maker_form"):
            maker_id = st.selectbox(
                "Initiating user (maker)",
                [u.user_id for u in roles_module.get_all_users()],
                format_func=lambda uid: f"{uid}: {roles_module.get_user(uid).name}",
                key="mc_maker_id",
            )
            amount = st.number_input("Amount (₹)", min_value=1.0, value=500000.0, step=10000.0, key="mc_amount")
            cid_in = st.text_input("Correlation ID (auto-generated if blank)", value="", key="mc_cid")
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
                else:
                    raise ValueError(resp.text)
            except Exception:
                data = _mc_submit(maker_id, amount, cid_in)
            if data["status"] == "SUBMITTED":
                st.success(
                    f"Transaction submitted. Awaiting checker approval.  \n"
                    f"Request ID: `{data['request_id']}`  \n"
                    f"Correlation ID: `{data['correlation_id']}`"
                )
            else:
                st.info(str(data))
            st.json(data)

    with _mc_right:
        _mr_title, _mr_fill = st.columns([4, 1])
        _mr_title.subheader("Approve or Reject")
        if _mr_fill.button("📋 Fill data", key="fill_checker_btn"):
            _con_fill = sqlite3.connect(DB_PATH)
            _latest = _con_fill.execute(
                "SELECT request_id, maker_id FROM maker_checker_reqs"
                " WHERE status='SUBMITTED' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            _con_fill.close()
            if _latest:
                st.session_state["mc_req_id"] = _latest[0]
                _all_uids = [u.user_id for u in roles_module.get_all_users()]
                st.session_state["mc_checker_id"] = next(
                    (u for u in _all_uids if u != _latest[1]), "user_006"
                )
            else:
                st.session_state["mc_req_id"] = ""
                st.session_state["mc_checker_id"] = "user_006"
            st.session_state["mc_decision"] = "Approve"
            st.rerun()
        st.caption("Must be a different person from whoever submitted. If you try to approve your own transaction, it gets blocked automatically.")

        with st.form("checker_form"):
            req_id_in = st.text_input("Request ID", key="mc_req_id")
            checker_id = st.selectbox(
                "Approving user (checker)",
                [u.user_id for u in roles_module.get_all_users()],
                format_func=lambda uid: f"{uid}: {roles_module.get_user(uid).name}",
                key="mc_checker_id",
            )
            _decision_val = st.radio("Decision", ["Approve", "Reject"], key="mc_decision")
            approve = _decision_val == "Approve"
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
                else:
                    raise ValueError(resp.text)
            except Exception:
                data = _mc_decide(req_id_in, checker_id, approve)
            status = data["status"]
            if status == "ALREADY_DECIDED":
                already = data.get("current_status", "decided")
                st.warning(
                    f"⚠️ This request is already **{already}** and cannot be updated again. "
                    f"Each request can only be decided once."
                )
            elif status == "SELF_APPROVAL_BLOCKED":
                st.error(
                    "🚫 **Self-approval blocked.** The maker and checker must be different people. "
                    "Note: if the table shows this request as APPROVED, it was auto-approved at "
                    "submission because the amount was within the maker's authorisation limit — "
                    "that approval is separate from this blocked checker attempt."
                )
            elif status == "NOT_FOUND":
                st.error(f"Request ID `{req_id_in}` not found.")
            elif status == "APPROVED":
                st.success(f"✅ Approved by {roles_module.get_user(checker_id).name if roles_module.get_user(checker_id) else checker_id}.")
            elif status == "REJECTED":
                st.warning(f"❌ Rejected by {roles_module.get_user(checker_id).name if roles_module.get_user(checker_id) else checker_id}.")
            st.json(data)

    st.divider()
    _list_title, _list_btn = st.columns([5, 1])
    _list_title.subheader("All Maker-Checker Requests")
    _list_btn.button("Refresh", use_container_width=True)

    try:
        resp = requests.get(f"{API}/maker-checker/list", timeout=5)
        all_reqs = resp.json() if resp.ok else []
        if not all_reqs:
            raise ValueError
    except Exception:
        all_reqs = _mc_list()

    if not all_reqs:
        st.info("No requests yet.")
    else:
        _status_icon = {
            "SUBMITTED": "📨 Submitted",
            "APPROVED":  "✅ Approved",
            "REJECTED":  "❌ Rejected",
            "SELF_APPROVAL_BLOCKED": "🚫 Blocked",
            "PENDING":   "⏳ Pending",
        }

        def _name(uid: str | None) -> str:
            if not uid:
                return "—"
            u = roles_module.get_user(uid)
            return f"{u.name} ({uid})" if u else uid

        import pandas as pd
        rows = []
        for r in all_reqs:
            rows.append({
                "Request ID":     r.get("request_id") or "—",
                "Correlation ID": r.get("correlation_id") or "—",
                "Maker":          _name(r.get("maker_id")),
                "Checker":        _name(r.get("checker_id")),
                "Amount (₹)":     f"₹{r.get('amount', 0):,.2f}",
                "Status":         _status_icon.get(r.get("status", ""), r.get("status", "")),
                "Submitted At":   r.get("created_at", "—"),
            })
        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True,
        )
