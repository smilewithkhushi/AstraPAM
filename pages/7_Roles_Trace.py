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
    "See what each user is allowed to do and why. Paste a transaction ID to pull up everything that happened around it, from access request to final audit entry.",
)

tab_roles, tab_users, tab_trace = st.tabs(["Role Definitions", "Bank Users", "Trace by Correlation ID"])

with tab_roles:
    st.subheader("Role / Tier Definitions")
    st.caption("No single role can both issue and approve Letters of Undertaking. IT admins have no financial permissions at all.")

    for role in roles_module.ROLES.values():
        with st.expander(f"**{role.tier}**: {role.name}  ({role.work_class})", expanded=False):
            c1, c2 = st.columns(2)
            c1.markdown(f"**Tier:** `{role.tier}`")
            c1.markdown(f"**Work class:** `{role.work_class}`")
            c2.markdown(f"**Input limit:** `{role.input_limit or '—'}` ₹")
            c2.markdown(f"**Auth limit:** `{role.auth_limit or '—'}` ₹")
            st.markdown("**Entitlements:**")
            badges = "  ".join(f"`{e}`" for e in sorted(role.entitlements))
            st.markdown(badges if badges else "_none_")

with tab_users:
    st.subheader("Seeded Bank Users")
    st.caption("user_007 is Gokulnath Shetty. His manager role gives him ISSUE_LOU, and someone added APPROVE_LOU on top. That combination is exactly what enabled the PNB fraud.")

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

    for u in users:
        role = roles_module.get_role(u["role_id"])
        tier = role.tier if role else "?"
        is_pnb = "user_007" in u["user_id"]
        label = f"{'⚠️ ' if is_pnb else ''}**{u['name']}** (`{u['user_id']}`) · {tier} · {u['branch_sol']}"
        with st.expander(label, expanded=is_pnb):
            c1, c2 = st.columns(2)
            c1.markdown(f"**Role:** `{u['role_id']}`")
            c1.markdown(f"**Status:** `{u['status']}`")
            c1.markdown(f"**Last login:** `{u.get('last_login_at', '—')}`")
            c2.markdown(f"**Branch:** `{u['branch_sol']}`")
            c2.markdown(f"**Extra entitlements:** {', '.join(u['extra_entitlements']) or '_none_'}")

            ents = u.get("effective_entitlements", [])
            st.markdown(f"**Effective entitlements ({len(ents)}):** " +
                        "  ".join(f"`{e}`" for e in ents))

            if is_pnb:
                st.error(
                    "Has both ISSUE_LOU and APPROVE_LOU. The system flags this as a critical conflict before any fraudulent transaction even needs to happen."
                )

with tab_trace:
    st.subheader("Trace a Transaction")
    st.caption("Enter a transaction ID to see the full story behind it: who requested access, what the system decided, what happened in the bank ledger, and what the audit log recorded.")

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
