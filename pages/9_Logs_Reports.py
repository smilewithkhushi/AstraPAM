"""Phase 10 — Logs & Reports: live activity log + scheduled reports."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import requests
import streamlit as st

import _sidebar
from core.schemas import DB_PATH, init_db

init_db()

API = _sidebar.API_URL

_sidebar.render_page_header(
    "", "Logs and Reports",
    "Everything that happened, in one place. Filter by source or download a full audit report for compliance or internal review.",
)

tab_logs, tab_reports = st.tabs(["📄 Activity Logs", "📊 Reports"])


def _get(path: str) -> list | dict:
    try:
        r = requests.get(f"{API}{path}", timeout=5)
        return r.json() if r.ok else []
    except Exception:
        return []


_IST = timezone(timedelta(hours=5, minutes=30))

def _fmt(ts: str | None) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(_IST).strftime("%Y-%m-%d  %H:%M:%S IST")
    except Exception:
        return ts


def _badge(label: str, color: str) -> str:
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.78rem;font-weight:600">{label}</span>'
    )


with tab_logs:
    col_filter, col_refresh = st.columns([3, 1])
    with col_filter:
        source_filter = st.multiselect(
            "Filter by source",
            ["Access Decisions", "Audit Chain", "Access Grants", "Recon Alerts", "Console Actions", "Maker-Checker"],
            default=["Access Decisions", "Audit Chain", "Access Grants", "Recon Alerts", "Console Actions", "Maker-Checker"],
        )
    with col_refresh:
        st.markdown("&nbsp;")
        if st.button("↺ Refresh", width="stretch"):
            st.rerun()

    st.markdown("&nbsp;", unsafe_allow_html=True)

    audit_rows   = _get("/crypto/audit")       if "Audit Chain"     in source_filter else []
    grants       = _get("/access/grants")      if "Access Grants"   in source_filter else []
    recon_alerts = _get("/reconcile/alerts")   if "Recon Alerts"    in source_filter else []
    console_acts = _get("/console/actions")    if "Console Actions" in source_filter else []
    mc_list      = _get("/maker-checker/list") if "Maker-Checker"   in source_filter else []

    # access_request_log — full decision history, queried directly from SQLite
    access_log_rows = []
    if "Access Decisions" in source_filter:
        try:
            _con = sqlite3.connect(DB_PATH)
            access_log_rows = _con.execute(
                "SELECT requested_at, user_id, target, action_type, decision,"
                "       risk_score, attack_tags, grant_id, break_glass, correlation_id"
                " FROM access_request_log ORDER BY requested_at DESC LIMIT 300"
            ).fetchall()
            _con.close()
        except Exception:
            access_log_rows = []

    events: list[dict] = []

    for g in grants:
        events.append({
            "timestamp": g.get("expires_at", ""),
            "source": "Access Grant",
            "actor": g.get("user_id", "—"),
            "target": g.get("target", "—"),
            "action": f"Grant issued, expires {_fmt(g.get('expires_at'))}",
            "status": "REVOKED" if g.get("revoked") else "ACTIVE",
            "status_color": _sidebar.C_DENY if g.get("revoked") else _sidebar.C_ALLOW,
            "correlation_id": g.get("correlation_id", ""),
            "break_glass": g.get("break_glass", False),
        })

    for a in recon_alerts:
        sev = a.get("severity", "medium")
        events.append({
            "timestamp": a.get("detected_at", ""),
            "source": "Recon Alert",
            "actor": "SYSTEM",
            "target": a.get("action_id", "—"),
            "action": a.get("reason", "—"),
            "status": sev.upper(),
            "status_color": (
                _sidebar.C_DENY if sev == "critical" else
                _sidebar.C_THROTTLE if sev in ("high", "medium") else _sidebar.C_INFO
            ),
            "correlation_id": a.get("correlation_id", ""),
            "recommended_action": a.get("recommended_action", ""),
        })

    for c in console_acts:
        status = c.get("status", "")
        events.append({
            "timestamp": c.get("timestamp", ""),
            "source": "Console Action",
            "actor": c.get("operator_id", "—"),
            "target": c.get("target_user_id", "—"),
            "action": c.get("action", "—"),
            "status": status,
            "status_color": _sidebar.C_ALLOW if status == "APPLIED" else _sidebar.C_THROTTLE if status == "PENDING" else _sidebar.C_DENY,
            "correlation_id": c.get("correlation_id", ""),
            "reason": c.get("reason", ""),
            "approver": c.get("approver_id") or "—",
        })

    for m in mc_list:
        status = m.get("status", "")
        events.append({
            "timestamp": m.get("created_at", ""),
            "source": "Maker-Checker",
            "actor": m.get("maker_id", "—"),
            "target": m.get("checker_id") or "pending",
            "action": m.get("action_type", "—"),
            "status": status,
            "status_color": (
                _sidebar.C_DENY if "BLOCKED" in status or "REJECTED" in status else
                _sidebar.C_ALLOW if status == "APPROVED" else _sidebar.C_THROTTLE
            ),
            "correlation_id": m.get("correlation_id", ""),
            "amount": m.get("amount"),
        })

    for row in audit_rows:
        try:
            payload = json.loads(row.get("payload", "{}"))
        except Exception:
            payload = {}
        ts = payload.get("timestamp") or payload.get("decided_at") or payload.get("ts", "")
        events.append({
            "timestamp": ts,
            "source": "Audit Chain",
            "actor": payload.get("operator_id") or payload.get("maker_id") or payload.get("user_id") or "SYSTEM",
            "target": payload.get("target_user_id") or payload.get("checker_id") or payload.get("target") or "—",
            "action": payload.get("action") or payload.get("action_type") or payload.get("event") or "Audit entry",
            "status": f"seq #{row.get('seq', '?')}",
            "status_color": _sidebar.C_INFO,
            "correlation_id": payload.get("correlation_id", ""),
            "hash": row.get("hash", "")[:16] + "…",
        })

    DECISION_EMOJI = {"allow": "✅ ALLOW", "throttle": "⚡ THROTTLE", "step_up": "🔐 STEP UP", "deny": "🚫 DENY"}
    for r in access_log_rows:
        requested_at, user_id, target, action_type, decision, risk_score, attack_tags_raw, grant_id, break_glass, correlation_id = r
        try:
            tags = ", ".join(json.loads(attack_tags_raw)) if attack_tags_raw and attack_tags_raw != "[]" else ""
        except Exception:
            tags = ""
        events.append({
            "timestamp":      requested_at,
            "source":         "Access Decision",
            "actor":          user_id or "—",
            "target":         target or "—",
            "action":         f"{action_type} → {DECISION_EMOJI.get(decision, decision.upper() if decision else '—')}",
            "status":         f"{risk_score:.3f}" if risk_score is not None else "—",
            "status_color":   _sidebar.C_DENY if decision == "deny" else _sidebar.C_ALLOW,
            "correlation_id": correlation_id or "",
            "break_glass":    bool(break_glass),
            "reason":         tags,
            "grant_id":       (grant_id[:14] + "…") if grant_id else "",
        })

    events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)

    if not events:
        st.info("No log entries found. Start some activity or check that the API is running.")
    else:
        import pandas as _pd

        SOURCE_ICON = {
            "Access Decision": "🔐 Access Decision",
            "Access Grant":    "🔑 Access Grant",
            "Recon Alert":     "⚠️ Recon Alert",
            "Console Action":  "🛡️ Console Action",
            "Maker-Checker":   "✅ Maker-Checker",
            "Audit Chain":     "🔒 Audit Chain",
        }

        rows = []
        for ev in events:
            extras = []
            if ev.get("break_glass"):
                extras.append("🚨 BREAK-GLASS")
            if ev.get("reason"):
                extras.append(ev["reason"])
            if ev.get("recommended_action"):
                extras.append(f"Rec: {ev['recommended_action']}")
            if ev.get("amount") is not None:
                extras.append(f"₹{ev['amount']:,.2f}")
            if ev.get("approver") and ev["approver"] != "—":
                extras.append(f"Approver: {ev['approver']}")
            if ev.get("grant_id"):
                extras.append(f"Grant: {ev['grant_id']}")
            if ev.get("hash"):
                extras.append(f"hash: {ev['hash']}")

            rows.append({
                "Time":           _fmt(ev["timestamp"]),
                "Source":         SOURCE_ICON.get(ev["source"], ev["source"]),
                "Actor":          ev["actor"],
                "Target":         ev["target"],
                "Action":         ev["action"],
                "Risk / Status":  ev["status"],
                "Correlation ID": (ev["correlation_id"][:16] + "…") if ev.get("correlation_id") else "—",
                "Details":        " · ".join(extras) if extras else "—",
            })

        st.caption(f"{len(rows)} event(s) across {len(source_filter)} source(s) — newest first.")
        st.dataframe(
            _pd.DataFrame(rows),
            width="stretch",
            hide_index=True,
            column_config={
                "Time":           st.column_config.TextColumn("Time",           width="medium"),
                "Source":         st.column_config.TextColumn("Source",         width="medium"),
                "Actor":          st.column_config.TextColumn("Actor",          width="small"),
                "Target":         st.column_config.TextColumn("Target",         width="small"),
                "Action":         st.column_config.TextColumn("Action",         width="large"),
                "Risk / Status":  st.column_config.TextColumn("Risk / Status",  width="small"),
                "Correlation ID": st.column_config.TextColumn("Correlation ID", width="medium"),
                "Details":        st.column_config.TextColumn("Details",        width="large"),
            },
        )

with tab_reports:
    from core import report_generator
    import pandas as _pd
    import time as _time

    def _save_report_history(report_type: str, period_days: int, fname: str, pdf_bytes: bytes) -> None:
        try:
            _con = sqlite3.connect(DB_PATH)
            _con.execute(
                "INSERT INTO report_history (generated_at, report_type, period_days, file_name, file_size_kb, status)"
                " VALUES (?,?,?,?,?,?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    report_type,
                    period_days,
                    fname,
                    round(len(pdf_bytes) / 1024, 1),
                    "SUCCESS",
                ),
            )
            _con.commit()
            _con.close()
        except Exception:
            pass

    st.markdown("&nbsp;", unsafe_allow_html=True)
    st.markdown("Pulls live data from the system and generates a formatted report you can share with your compliance team or submit during an audit.")

    col1, col2 = st.columns(2)

    with col1:
        with st.container(border=True):
            st.markdown("##### 7-Day Operational Audit")
            st.caption("Covers the past 7 days, access activity, alerts, and whether the audit log is intact.")
            st.markdown("&nbsp;", unsafe_allow_html=True)
            if st.button("Generate 7-Day Report", width="stretch", type="primary", key="gen_7d"):
                try:
                    with st.status("Compiling 7-day audit report…", expanded=True) as _s:
                        st.write("Fetching access decisions and JIT grant history…")
                        _time.sleep(0.5)
                        st.write("Loading reconciliation alerts and ledger diff results…")
                        _time.sleep(0.5)
                        st.write("Verifying audit chain integrity and block hashes…")
                        _time.sleep(0.5)
                        st.write("Pulling NHI governance data and cryptographic inventory…")
                        _time.sleep(0.4)
                        st.write("Generating PDF with regulatory alignment matrix (RBI CSF, IT Gov 2024)…")
                        pdf_bytes = report_generator.generate_pdf(days=7)
                        _s.update(label="Report ready.", state="complete", expanded=False)
                    fname = f"AstraPAM_Audit_7d_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
                    _save_report_history("7-Day Operational Audit", 7, fname, pdf_bytes)
                    st.download_button(
                        "⬇ Download PDF",
                        data=pdf_bytes,
                        file_name=fname,
                        mime="application/pdf",
                        width="stretch",
                        key="dl_7d",
                    )
                except Exception as e:
                    st.error(f"Generation failed: {e}")

    with col2:
        with st.container(border=True):
            st.markdown("##### 30-Day Periodic Review")
            st.caption("Full month view, useful for periodic internal reviews or board-level reporting.")
            st.markdown("&nbsp;", unsafe_allow_html=True)
            if st.button("Generate 30-Day Report", width="stretch", key="gen_30d"):
                try:
                    with st.status("Compiling 30-day periodic review…", expanded=True) as _s:
                        st.write("Fetching full month of access decisions and privileged actions…")
                        _time.sleep(0.5)
                        st.write("Aggregating reconciliation alerts and ledger discrepancies…")
                        _time.sleep(0.5)
                        st.write("Scanning audit chain — verifying all block hashes across the period…")
                        _time.sleep(0.5)
                        st.write("Compiling NHI lifecycle events and SoD conflict history…")
                        _time.sleep(0.4)
                        st.write("Building executive summary and regulatory alignment matrix…")
                        pdf_bytes = report_generator.generate_pdf(days=30)
                        _s.update(label="Report ready.", state="complete", expanded=False)
                    fname = f"AstraPAM_Audit_30d_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
                    _save_report_history("30-Day Periodic Review", 30, fname, pdf_bytes)
                    st.download_button(
                        "⬇ Download PDF",
                        data=pdf_bytes,
                        file_name=fname,
                        mime="application/pdf",
                        width="stretch",
                        key="dl_30d",
                    )
                except Exception as e:
                    st.error(f"Generation failed: {e}")

    st.markdown("&nbsp;", unsafe_allow_html=True)
    with st.expander("Report structure"):
        st.markdown(
            "Every generated report contains:\n\n"
            "1. **Cover page**: Report ID, period, classification, applicable standards\n"
            "2. **Executive Summary**: narrative grounded in live metrics\n"
            "3. **Access Control Summary**: grant volume, break-glass count, encryption mechanism\n"
            "4. **Behavioral Risk Engine**: session scores, decision distribution, attack tags\n"
            "5. **Reconciliation Findings**: alerts by severity, fraud pattern targeted\n"
            "6. **NHI Governance**: inventory by status, encryption alignment\n"
            "7. **Audit Chain Integrity**: record count, signing algorithm, tamper detection\n"
            "8. **Key Findings**: bullet observations\n"
            "9. **Regulatory Alignment**: RBI CSF, IT Governance 2024, Apr-2026 Auth Directions\n\n"
            "All quantitative sections are sourced directly from the control plane."
        )

    st.divider()
    st.subheader("Generation History")
    st.caption("Every report generated from this instance — timestamp, type, file size, and download name.")

    try:
        _con = sqlite3.connect(DB_PATH)
        _hist = _con.execute(
            "SELECT generated_at, report_type, period_days, file_name, file_size_kb, status"
            " FROM report_history ORDER BY generated_at DESC"
        ).fetchall()
        _con.close()
    except Exception:
        _hist = []

    if not _hist:
        st.info("No reports generated yet. Use the buttons above to generate your first report.")
    else:
        _hist_rows = []
        for h in _hist:
            generated_at, report_type, period_days, file_name, file_size_kb, status = h
            try:
                _dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
                if _dt.tzinfo is None:
                    _dt = _dt.replace(tzinfo=timezone.utc)
                _ts = _dt.astimezone(_IST).strftime("%Y-%m-%d  %H:%M:%S IST")
            except Exception:
                _ts = generated_at
            _hist_rows.append({
                "Generated At":  _ts,
                "Report Type":   report_type,
                "Period (Days)": period_days,
                "File Name":     file_name,
                "Size (KB)":     file_size_kb,
                "Status":        "✅ Success" if status == "SUCCESS" else f"❌ {status}",
            })

        st.dataframe(
            _pd.DataFrame(_hist_rows),
            width="stretch",
            hide_index=True,
            column_config={
                "Generated At":  st.column_config.TextColumn("Generated At",  width="medium"),
                "Report Type":   st.column_config.TextColumn("Report Type",   width="medium"),
                "Period (Days)": st.column_config.NumberColumn("Period (Days)", width="small"),
                "File Name":     st.column_config.TextColumn("File Name",     width="large"),
                "Size (KB)":     st.column_config.NumberColumn("Size (KB)",   width="small", format="%.1f"),
                "Status":        st.column_config.TextColumn("Status",        width="small"),
            },
        )
