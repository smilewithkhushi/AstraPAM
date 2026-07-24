"""Phase 6 — Role model viewer + end-to-end trace by correlation ID."""
from __future__ import annotations

import json
import requests
import streamlit as st

import _sidebar
from core import roles as roles_module

st.set_page_config(page_title="AstraPAM · Roles & Trace", page_icon="🛡", layout="wide")

API = _sidebar.API_URL


def _render_trace(trace: dict) -> None:
    cid = trace["correlation_id"]
    st.markdown(f"**Correlation ID:** `{cid}`")
    st.divider()

    grants  = trace.get("grants", [])
    actions = trace.get("privileged_actions", [])
    alerts  = trace.get("recon_alerts", [])
    mc      = trace.get("maker_checker", [])
    console = trace.get("console_actions", [])
    audit   = trace.get("audit_trail", [])

    total = len(grants) + len(actions) + len(alerts) + len(mc) + len(console) + len(audit)
    if total == 0:
        st.warning("No artifacts found for this correlation ID.")
        return

    st.success(f"Found {total} artifact(s) linked to this correlation ID.")

    if grants:
        st.markdown("#### 🔑 JIT Grants")
        for g in grants:
            st.markdown(
                f"- **{g['grant_id'][:8]}…** | Actor: **{g['actor']}** | "
                f"Target: `{g['target']}` | Expires: `{g['expires_at']}` | "
                f"{'~~revoked~~' if g['revoked'] else 'active'}"
            )

    if actions:
        st.markdown("#### 💸 Privileged Actions")
        for a in actions:
            st.markdown(
                f"- `{a['action_id'][:8]}…` | Actor: **{a['actor']}** | "
                f"Channel: `{a['channel']}` | Amount: ₹`{a['amount']}` | `{a['timestamp']}`"
            )

    if alerts:
        st.markdown("#### 🚨 Reconciliation Alerts")
        for al in alerts:
            badge = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(al["severity"], "🔵")
            st.markdown(
                f"- {badge} **{al['severity'].upper()}** | {al['reason']} | "
                f"Detected: `{al['detected_at']}`"
            )

    if mc:
        st.markdown("#### ✅ Maker-Checker Requests")
        for r in mc:
            st.markdown(
                f"- `{r['request_id'][:8]}…` | Maker: **{r['maker']}** | "
                f"Checker: {r['checker'] or '_pending_'} | "
                f"Amount: ₹`{r['amount']}` | **{r['status']}**"
            )

    if console:
        st.markdown("#### 🛡 Console Actions")
        for ca in console:
            st.markdown(
                f"- **{ca['action']}** by {ca['operator']} → {ca['target']} | "
                f"Status: `{ca['status']}` | `{ca['timestamp']}`"
            )

    if audit:
        st.markdown("#### 🔐 Audit Trail")
        for rec in audit:
            try:
                payload = json.loads(rec["payload"])
                event = payload.get("event", "?")
            except Exception:
                event = rec["payload"][:60]
            st.markdown(f"- seq `{rec['seq']}` | `{event}` | hash `{rec['hash'][:16]}…`")


_sidebar.render_page_header(
    "", "Roles and Audit Trace",
    "See what each bank employee is allowed to do and why. Paste a transaction ID to pull up everything that happened around it, from access request to final audit entry.",
)

tab_roles, tab_users, tab_trace = st.tabs(["Role Definitions", "Bank Users", "Trace by Correlation ID"])

with tab_roles:
    import pandas as _pd
    st.subheader("Role / Tier Definitions")

    _role_rows = []
    for role in roles_module.ROLES.values():
        _role_rows.append({
            "Tier":           role.tier,
            "Role Name":      role.name,
            "Work Class":     role.work_class,
            "Input Limit (₹)":  f"₹{role.input_limit:,}" if role.input_limit else "—",
            "Auth Limit (₹)":   f"₹{role.auth_limit:,}"  if role.auth_limit  else "—",
            "# Entitlements": len(role.entitlements),
            "Entitlements":   ", ".join(sorted(role.entitlements)) or "none",
        })

    st.dataframe(
        _pd.DataFrame(_role_rows),
        width="stretch",
        hide_index=True,
        column_config={
            "Tier":             st.column_config.TextColumn("Tier",             width="small"),
            "Role Name":        st.column_config.TextColumn("Role Name",        width="medium"),
            "Work Class":       st.column_config.TextColumn("Work Class",       width="small"),
            "Input Limit (₹)":  st.column_config.TextColumn("Input Limit (₹)", width="small"),
            "Auth Limit (₹)":   st.column_config.TextColumn("Auth Limit (₹)",  width="small"),
            "# Entitlements":   st.column_config.NumberColumn("# Entitlements", width="small"),
            "Entitlements":     st.column_config.TextColumn("Entitlements",     width="large"),
        },
    )

with tab_users:
    import pandas as _pd
    st.subheader("Bank Users")

    try:
        resp = requests.get(f"{API}/roles/users", timeout=5)
        users = resp.json() if resp.ok else []
    except Exception:
        users = [
            {**u.model_dump(),
             "extra_entitlements": sorted(u.extra_entitlements),
             "effective_entitlements": sorted(roles_module.effective_entitlements(u))}
            for u in roles_module.get_all_users()
        ]

    _user_rows = []
    for u in users:
        role_obj = roles_module.get_role(u["role_id"])
        tier     = role_obj.tier if role_obj else "?"
        role_name = role_obj.name if role_obj else u["role_id"]
        eff_ents  = u.get("effective_entitlements", [])
        extra     = u.get("extra_entitlements", [])
        has_conflict = "ISSUE_LOU" in eff_ents and "APPROVE_LOU" in eff_ents
        login = u.get("last_login_at") or "—"
        if login and login != "—":
            login = str(login)[:10]
        _user_rows.append({
            "Flag":                  "⚠️ Conflict" if has_conflict else "✅ Clean",
            "User ID":               u["user_id"],
            "Name":                  u["name"],
            "Role":                  role_name,
            "Tier":                  tier,
            "Branch (SOL)":          u["branch_sol"],
            "Status":                u["status"],
            "Last Login":            login,
            "Extra Entitlements":    ", ".join(extra) if extra else "—",
            "Total Entitlements":    len(eff_ents),
            "Effective Entitlements": ", ".join(sorted(eff_ents)),
        })

    st.dataframe(
        _pd.DataFrame(_user_rows),
        width="stretch",
        hide_index=True,
        column_config={
            "Flag":                   st.column_config.TextColumn("Flag",                   width="small"),
            "User ID":                st.column_config.TextColumn("User ID",                width="small"),
            "Name":                   st.column_config.TextColumn("Name",                   width="medium"),
            "Role":                   st.column_config.TextColumn("Role",                   width="medium"),
            "Tier":                   st.column_config.TextColumn("Tier",                   width="small"),
            "Branch (SOL)":           st.column_config.TextColumn("Branch (SOL)",           width="small"),
            "Status":                 st.column_config.TextColumn("Status",                 width="small"),
            "Last Login":             st.column_config.TextColumn("Last Login",             width="small"),
            "Extra Entitlements":     st.column_config.TextColumn("Extra Entitlements",     width="medium"),
            "Total Entitlements":     st.column_config.NumberColumn("Total Entitlements",   width="small"),
            "Effective Entitlements": st.column_config.TextColumn("Effective Entitlements", width="large"),
        },
    )

    if any(r["Flag"] == "⚠️ Conflict" for r in _user_rows):
        st.error(
            "⚠️ **Entitlement conflict detected** — one or more bank employees hold both "
            "ISSUE_LOU and APPROVE_LOU. This combination must never exist in a single identity. "
            "The SoD engine flags it before any transaction can proceed."
        )

with tab_trace:
    st.subheader("Trace a Transaction")
    st.caption("Enter a transaction ID to see the full story behind it: which bank employee requested access, what the system decided, what happened in the core banking ledger, and what the audit log recorded.")

    cid = st.text_input("Correlation ID", placeholder="paste a correlation_id here…")

    if cid:
        try:
            resp = requests.get(f"{API}/trace/{cid}", timeout=5)
            if not resp.ok:
                st.error(f"API error: {resp.status_code}")
            else:
                trace = resp.json()
                _render_trace(trace)
        except Exception as e:
            st.error(f"Could not reach API: {e}")
