"""Phase 10 — Logs & Reports: live activity log + (stub) scheduled reports."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import requests
import streamlit as st

import _sidebar

st.set_page_config(page_title="Logs & Reports", page_icon="📋", layout="wide")
API = _sidebar.API_URL

st.title("Logs & Reports")
st.divider()

tab_logs, tab_reports = st.tabs(["📄 Activity Logs", "📊 Reports"])

# ── helpers ───────────────────────────────────────────────────────────────────

def _get(path: str) -> list | dict:
    try:
        r = requests.get(f"{API}{path}", timeout=5)
        return r.json() if r.ok else []
    except Exception:
        return []


def _fmt(ts: str | None) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d  %H:%M:%S UTC")
    except Exception:
        return ts


def _badge(label: str, color: str) -> str:
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.78rem;font-weight:600">{label}</span>'
    )

# ── TAB 1 — Activity Logs ─────────────────────────────────────────────────────
with tab_logs:
    col_filter, col_refresh = st.columns([3, 1])
    with col_filter:
        source_filter = st.multiselect(
            "Filter by source",
            ["Audit Chain", "Access Grants", "Recon Alerts", "Console Actions", "Maker-Checker"],
            default=["Audit Chain", "Access Grants", "Recon Alerts", "Console Actions", "Maker-Checker"],
        )
    with col_refresh:
        st.markdown("&nbsp;")
        if st.button("↺ Refresh", use_container_width=True):
            st.rerun()

    st.markdown("&nbsp;", unsafe_allow_html=True)

    # ── Fetch all sources ────────────────────────────────────────────────────
    audit_rows   = _get("/crypto/audit")       if "Audit Chain"     in source_filter else []
    grants       = _get("/access/grants")      if "Access Grants"   in source_filter else []
    recon_alerts = _get("/reconcile/alerts")   if "Recon Alerts"    in source_filter else []
    console_acts = _get("/console/actions")    if "Console Actions" in source_filter else []
    mc_list      = _get("/maker-checker/list") if "Maker-Checker"   in source_filter else []

    # ── Build unified event list ─────────────────────────────────────────────
    events: list[dict] = []

    for g in grants:
        events.append({
            "timestamp": g.get("expires_at", ""),   # use grant time as proxy
            "source": "Access Grant",
            "actor": g.get("user_id", "—"),
            "target": g.get("target", "—"),
            "action": f"Grant issued — expires {_fmt(g.get('expires_at'))}",
            "status": "REVOKED" if g.get("revoked") else "ACTIVE",
            "status_color": "#a00000" if g.get("revoked") else "#1a7a1a",
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
            "status_color": _sidebar.SEVERITY_LABEL.get(sev, "🔵").split()[0] and (
                "#a00000" if sev == "critical" else
                "#b36b00" if sev in ("high", "medium") else "#2266cc"
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
            "status_color": "#1a7a1a" if status == "APPLIED" else "#b36b00" if status == "PENDING" else "#a00000",
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
                "#a00000" if "BLOCKED" in status or "REJECTED" in status else
                "#1a7a1a" if status == "APPROVED" else "#b36b00"
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
            "status_color": "#4a90d9",
            "correlation_id": payload.get("correlation_id", ""),
            "hash": row.get("hash", "")[:16] + "…",
        })

    # ── Sort newest-first ────────────────────────────────────────────────────
    events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)

    if not events:
        st.info("No log entries found. Start some activity or check that the API is running.")
    else:
        st.markdown("---")

        for ev in events:
            source_icon = {
                "Access Grant":   "🔑",
                "Recon Alert":    "⚠️",
                "Console Action": "🛡️",
                "Maker-Checker":  "✅",
                "Audit Chain":    "🔒",
            }.get(ev["source"], "📌")

            col_ts, col_src, col_actor, col_target, col_action, col_status = st.columns(
                [2, 1.4, 1.4, 1.4, 3, 1.4]
            )
            col_ts.markdown(
                f'<span style="font-size:0.8rem;color:#666">{_fmt(ev["timestamp"])}</span>',
                unsafe_allow_html=True,
            )
            col_src.markdown(
                f'<span style="font-size:0.82rem">{source_icon} **{ev["source"]}**</span>',
                unsafe_allow_html=True,
            )
            col_actor.markdown(
                f'<code style="font-size:0.78rem">{ev["actor"]}</code>',
                unsafe_allow_html=True,
            )
            col_target.markdown(
                f'<code style="font-size:0.78rem">{ev["target"]}</code>',
                unsafe_allow_html=True,
            )
            col_action.markdown(
                f'<span style="font-size:0.82rem">{ev["action"]}</span>',
                unsafe_allow_html=True,
            )
            col_status.markdown(
                _badge(ev["status"], ev["status_color"]),
                unsafe_allow_html=True,
            )

            # Extra detail row
            extras = []
            if ev.get("correlation_id"):
                extras.append(f"`corr: {ev['correlation_id'][:12]}…`")
            if ev.get("break_glass"):
                extras.append("🚨 **BREAK-GLASS**")
            if ev.get("reason"):
                extras.append(f"reason: _{ev['reason']}_")
            if ev.get("recommended_action"):
                extras.append(f"recommended: _{ev['recommended_action']}_")
            if ev.get("hash"):
                extras.append(f"hash: `{ev['hash']}`")
            if ev.get("amount") is not None:
                extras.append(f"amount: ₹{ev['amount']:,.2f}")
            if ev.get("approver") and ev["approver"] != "—":
                extras.append(f"approver: `{ev['approver']}`")
            if extras:
                st.markdown(
                    '<div style="padding-left:1rem;margin-bottom:0.2rem;color:#555;font-size:0.78rem">'
                    + " &nbsp;·&nbsp; ".join(extras) + "</div>",
                    unsafe_allow_html=True,
                )

            st.markdown(
                '<hr style="margin:4px 0;border:none;border-top:1px solid #eee">',
                unsafe_allow_html=True,
            )

# ── TAB 2 — Reports (stub) ────────────────────────────────────────────────────
with tab_reports:
    st.subheader("Scheduled Reports")
    st.info(
        "**Coming soon.** This pane will generate and download:\n\n"
        "- **Weekly summary** — access decisions by user/channel, top risk scores, SoD conflicts flagged, "
        "console actions taken, recon alerts by severity.\n"
        "- **Monthly report** — trend charts (risk score distribution, grant volume, alert cadence), "
        "exposure score changes, audit chain integrity status, maker-checker throughput.\n\n"
        "Reports will be exportable as PDF and CSV."
    )

    col1, col2 = st.columns(2)
    with col1:
        with st.container(border=True):
            st.markdown("### 📅 Weekly Report")
            st.markdown("Last generated: —")
            st.markdown("Coverage: last 7 days")
            st.button("Generate Weekly Report", disabled=True, key="gen_weekly")
    with col2:
        with st.container(border=True):
            st.markdown("### 📆 Monthly Report")
            st.markdown("Last generated: —")
            st.markdown("Coverage: last 30 days")
            st.button("Generate Monthly Report", disabled=True, key="gen_monthly")
