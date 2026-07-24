"""AstraPAM — Reconciliation page."""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone

import pandas as pd

import _sidebar
import httpx
import streamlit as st

from core import reconcile
from core.schemas import DB_PATH, init_db

st.set_page_config(
    page_title="AstraPAM · Reconciliation",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_db()

_sidebar.render_page_header(
    "", "Transaction Reconciliation",
    "Every financial action done through AstraPAM is cross-checked against the core ledger. "
    "A missing or mismatched entry is flagged immediately — the exact control that would have stopped the PNB LoU fraud.",
)

_now_str = lambda: datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

# ── Metrics strip ─────────────────────────────────────────────────────────────
con = sqlite3.connect(DB_PATH)
total_actions   = con.execute("SELECT COUNT(*) FROM privileged_actions").fetchone()[0]
matched_exact   = con.execute(
    "SELECT COUNT(DISTINCT pa.action_id) FROM privileged_actions pa"
    " JOIN ledger_entries le ON pa.action_id = le.action_id"
    " WHERE ROUND(pa.amount,2) = ROUND(le.amount,2)"
).fetchone()[0]
amount_mismatch = con.execute(
    "SELECT COUNT(DISTINCT pa.action_id) FROM privileged_actions pa"
    " JOIN ledger_entries le ON pa.action_id = le.action_id"
    " WHERE ROUND(pa.amount,2) != ROUND(le.amount,2)"
).fetchone()[0]
no_ledger = con.execute(
    "SELECT COUNT(*) FROM privileged_actions"
    " WHERE action_id NOT IN (SELECT action_id FROM ledger_entries WHERE action_id IS NOT NULL)"
).fetchone()[0]
alert_count = con.execute("SELECT COUNT(*) FROM recon_alerts").fetchone()[0]
con.close()

m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    with st.container(border=True):
        st.metric("Total Actions", total_actions)
with m2:
    with st.container(border=True):
        st.metric("✅ Matched", matched_exact)
with m3:
    with st.container(border=True):
        st.metric("❌ No Ledger Entry", no_ledger)
with m4:
    with st.container(border=True):
        st.metric("⚠️ Amount Mismatch", amount_mismatch)
with m5:
    with st.container(border=True):
        st.metric("🚨 Alerts", alert_count)

st.divider()

# ── Simulation panel ──────────────────────────────────────────────────────────
st.subheader("Simulate Transactions")
st.caption(
    "Three scenarios show the full range: a clean matched transaction, "
    "a SWIFT LoU with no ledger record (the PNB fraud pattern), "
    "and a tampered entry where the ledger amount doesn't match the action."
)

sim1, sim2, sim3, sim4 = st.columns([1.5, 1.5, 1.5, 1])

with sim1:
    with st.container(border=True):
        st.markdown("**✅ Normal CBS Transaction**")
        st.caption(
            "Issues a CBS financial action AND a matching ledger entry at the same amount. "
            "This is the happy path — the reconciliation check will pass it cleanly."
        )
        if st.button("Issue matched transaction", width="stretch", type="secondary"):
            action_id = str(uuid.uuid4())
            entry_id  = str(uuid.uuid4())
            now       = _now_str()
            con = sqlite3.connect(DB_PATH)
            con.execute(
                "INSERT OR IGNORE INTO privileged_actions"
                " (action_id, user_id, channel, amount, timestamp, correlation_id)"
                " VALUES (?,?,?,?,?,?)",
                (action_id, "branch_officer", "cbs", 50000.0, now, ""),
            )
            con.execute(
                "INSERT OR IGNORE INTO ledger_entries"
                " (entry_id, action_id, amount, timestamp, correlation_id)"
                " VALUES (?,?,?,?,?)",
                (entry_id, action_id, 50000.0, now, ""),
            )
            con.commit()
            con.close()
            st.success(f"Action + ledger entry created: `{action_id[:12]}…`")
            st.rerun()

with sim2:
    with st.container(border=True):
        st.markdown("**❌ SWIFT LoU — No Ledger**")
        st.caption(
            "Issues a SWIFT financial action with no backing ledger entry. "
            "This is the PNB pattern: the transaction looks authorised, but nothing was recorded in the CBS ledger."
        )
        if st.button("Issue unmatched LoU", width="stretch", type="primary"):
            try:
                resp = httpx.post(
                    f"{_sidebar.CBS_URL}/swift/action",
                    json={"user_id": "rogue_admin", "amount": 14000.0,
                          "description": "Fake LoU — PNB pattern"},
                    timeout=3,
                )
                aid = resp.json().get("action_id", "")
                st.error(f"Action issued via CBS: `{aid[:12]}…` — no ledger entry")
            except Exception:
                action_id = str(uuid.uuid4())
                con = sqlite3.connect(DB_PATH)
                con.execute(
                    "INSERT OR IGNORE INTO privileged_actions"
                    " (action_id, user_id, channel, amount, timestamp, correlation_id)"
                    " VALUES (?,?,?,?,?,?)",
                    (action_id, "rogue_admin", "swift_like", 14000.0, _now_str(), ""),
                )
                con.commit()
                con.close()
                st.error(f"Action issued (local): `{action_id[:12]}…` — no ledger entry created")
            st.rerun()

with sim3:
    with st.container(border=True):
        st.markdown("**⚠️ Tampered Ledger Entry**")
        st.caption(
            "Issues a SWIFT action for ₹2,80,000 but records only ₹14,000 in the ledger — "
            "simulating a backdated or manually altered entry to hide the true transaction size."
        )
        if st.button("Issue amount mismatch", width="stretch", type="secondary"):
            action_id = str(uuid.uuid4())
            entry_id  = str(uuid.uuid4())
            now       = _now_str()
            con = sqlite3.connect(DB_PATH)
            con.execute(
                "INSERT OR IGNORE INTO privileged_actions"
                " (action_id, user_id, channel, amount, timestamp, correlation_id)"
                " VALUES (?,?,?,?,?,?)",
                (action_id, "rogue_admin", "swift_like", 280000.0, now, ""),
            )
            con.execute(
                "INSERT OR IGNORE INTO ledger_entries"
                " (entry_id, action_id, amount, timestamp, correlation_id)"
                " VALUES (?,?,?,?,?)",
                (entry_id, action_id, 14000.0, now, ""),
            )
            con.commit()
            con.close()
            st.warning(
                f"Action ₹2,80,000 + ledger ₹14,000 created: `{action_id[:12]}…`  \n"
                f"Discrepancy: ₹2,66,000 hidden from the ledger."
            )
            st.rerun()

with sim4:
    with st.container(border=True):
        st.markdown("**Run Check**")
        st.caption("Cross-check all actions against the ledger and raise alerts for any unmatched gaps.")
        if st.button("Run reconciliation", width="stretch", type="primary"):
            try:
                reconcile.sync_from_cbs()
            except Exception:
                pass
            new_alerts = reconcile.run(sla_seconds=0)
            if new_alerts:
                st.error(f"{len(new_alerts)} new alert(s) raised")
            else:
                st.success("All clear — no new gaps")
            st.rerun()

st.divider()

# ── Cross-check table ─────────────────────────────────────────────────────────
st.subheader("Transaction Cross-Check")
st.caption(
    "Every privileged action compared against the core ledger entry by entry. "
    "✅ = amounts match · ❌ = no ledger record found · ⚠️ = ledger amount differs from action amount."
)

con = sqlite3.connect(DB_PATH)
cross_rows = con.execute(
    "SELECT pa.action_id, pa.user_id, pa.channel, pa.amount, pa.timestamp,"
    "       le.entry_id, le.amount"
    " FROM privileged_actions pa"
    " LEFT JOIN ledger_entries le ON pa.action_id = le.action_id"
    " ORDER BY pa.timestamp DESC LIMIT 200"
).fetchall()
con.close()

if not cross_rows:
    st.info("No transactions yet. Use the simulation panel above to create some.")
else:
    records = []
    for action_id, user_id, channel, action_amt, ts, entry_id, ledger_amt in cross_rows:
        action_amt_f  = float(action_amt or 0)
        if entry_id is None:
            status = "❌ No Ledger Entry"
        elif ledger_amt is not None and abs(action_amt_f - float(ledger_amt)) > 0.01:
            status = "⚠️ Amount Mismatch"
        else:
            status = "✅ Matched"

        records.append({
            "Status":         status,
            "Action ID":      action_id[:20] + "…",
            "User":           user_id or "—",
            "Channel":        channel or "—",
            "Action Amount":  f"₹{action_amt_f:,.2f}",
            "Ledger Amount":  f"₹{float(ledger_amt):,.2f}" if ledger_amt is not None else "—",
            "Discrepancy":    (
                f"₹{abs(action_amt_f - float(ledger_amt)):,.2f}"
                if ledger_amt is not None and abs(action_amt_f - float(ledger_amt)) > 0.01
                else "—"
            ),
            "Timestamp":      ts[:19].replace("T", " ") if ts else "—",
        })

    st.dataframe(
        pd.DataFrame(records),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Status":         st.column_config.TextColumn("Status",          width="medium"),
            "Action ID":      st.column_config.TextColumn("Action ID",       width="medium"),
            "User":           st.column_config.TextColumn("User",            width="small"),
            "Channel":        st.column_config.TextColumn("Channel",         width="small"),
            "Action Amount":  st.column_config.TextColumn("Action Amount",   width="small"),
            "Ledger Amount":  st.column_config.TextColumn("Ledger Amount",   width="small"),
            "Discrepancy":    st.column_config.TextColumn("Discrepancy",     width="small"),
            "Timestamp":      st.column_config.TextColumn("Timestamp",       width="medium"),
        },
    )

st.divider()

# ── Alerts ────────────────────────────────────────────────────────────────────
st.subheader("Alerts")
st.caption("Alerts are raised for unmatched actions only. Amount mismatches are visible in the cross-check table above.")

alerts = reconcile.get_all_alerts()

if not alerts:
    st.success("No unmatched privileged financial actions detected.")
else:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    SEVERITY_EMOJI = {
        "critical": "🔴 CRITICAL",
        "high":     "🟠 HIGH",
        "medium":   "🟡 MEDIUM",
        "low":      "🔵 LOW",
    }
    sorted_alerts = sorted(alerts, key=lambda x: severity_order.get(x.severity, 9))
    rows = []
    for a in sorted_alerts:
        rows.append({
            "Severity":           SEVERITY_EMOJI.get(a.severity, a.severity.upper()),
            "Reason":             a.reason,
            "Recommended Action": a.recommended_action,
            "Action ID":          a.action_id[:24] + "…",
            "Detected At":        a.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
        })
    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
        column_config={
            "Severity":           st.column_config.TextColumn("Severity",           width="small"),
            "Reason":             st.column_config.TextColumn("Reason",             width="large"),
            "Recommended Action": st.column_config.TextColumn("Recommended Action", width="large"),
            "Action ID":          st.column_config.TextColumn("Action ID",          width="medium"),
            "Detected At":        st.column_config.TextColumn("Detected At",        width="small"),
        },
    )
