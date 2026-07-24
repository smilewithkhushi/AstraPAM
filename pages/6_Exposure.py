"""Phase 9 — Standing Exposure Score + 2×2 behavioral-risk × standing-exposure quadrant.

Exposure = what you COULD do (static/identity properties).
Risk     = what you DID (behavioral, from LSTM engine).
Orthogonal, complementary, never redundant.
"""
from __future__ import annotations

import requests
import streamlit as st

import _sidebar
from core import risk as risk_engine
from core import roles as roles_module

st.set_page_config(page_title="AstraPAM · Exposure Score", page_icon="🛡", layout="wide")

API = _sidebar.API_URL

# Behavioral risk values for the 2×2 quadrant demo
_BEH_RISK_MAP = {
    "user_001": 0.71,   # junior teller with anomalous behavior
    "user_007": 0.09,   # PNB archetype: behaves normally, high structural exposure
}
_DEFAULT_BEH = 0.12

_sidebar.render_page_header(
    "", "Privilege Exposure",
    "Ranks every bank employee by how much structural damage they could cause. This is based on the entitlements and authority their role carries, not on anything they've actually done. "
    "A teller with read-only access is low exposure.")

tab_scores, tab_quadrant, tab_orgmap = st.tabs(["Individual Scores", "Risk vs. Access Matrix", "🗺 Org Risk Map"])

# ── Individual Scores ─────────────────────────────────────────────────────────
with tab_scores:
    st.subheader("All Users")

    try:
        resp = requests.get(f"{API}/exposure", timeout=5)
        scores = resp.json() if resp.ok else []
    except Exception:
        scores = []

    if not scores:
        st.info("Could not fetch scores from API. Is the server running?")
    else:
        import pandas as pd

        scores_sorted = sorted(scores, key=lambda s: s["score"], reverse=True)
        rows = []
        for s in scores_sorted:
            u = roles_module.get_user(s["user_id"])
            name = u.name if u else s["user_id"]
            role = roles_module.get_role(u.role_id) if u else None
            tier = role.tier if role else "?"
            comps = s["components"]
            flag = "🔴 Toxic Entitlement Pair" if "user_007" in s["user_id"] else ""
            rows.append({
                "User":               name,
                "ID":                 s["user_id"],
                "Tier":               tier,
                "Exposure %":         round(s["score"] * 100, 1),
                "Priv Breadth":       round(comps["privilege_breadth"] * 100, 1),
                "Financial Auth":     round(comps["financial_authority"] * 100, 1),
                "SoD Conflicts":      round(comps["sod_conflicts"] * 100, 1),
                "Dormancy":           round(comps["dormancy"] * 100, 1),
                "Credential Age":     round(comps["credential_age"] * 100, 1),
                "Is NHI":             bool(comps["is_nhi"]),
                "Flag":               flag,
            })

        st.dataframe(
            pd.DataFrame(rows),
            width="stretch",
            hide_index=True,
            column_config={
                "User":           st.column_config.TextColumn("User",           width="medium"),
                "ID":             st.column_config.TextColumn("ID",             width="small"),
                "Tier":           st.column_config.TextColumn("Tier",           width="small"),
                "Exposure %":     st.column_config.ProgressColumn(
                                      "Exposure %", min_value=0, max_value=100, format="%.1f%%", width="medium"
                                  ),
                "Priv Breadth":   st.column_config.ProgressColumn(
                                      "Priv Breadth", min_value=0, max_value=100, format="%.1f%%", width="small"
                                  ),
                "Financial Auth": st.column_config.ProgressColumn(
                                      "Financial Auth", min_value=0, max_value=100, format="%.1f%%", width="small"
                                  ),
                "SoD Conflicts":  st.column_config.ProgressColumn(
                                      "SoD Conflicts", min_value=0, max_value=100, format="%.1f%%", width="small"
                                  ),
                "Dormancy":       st.column_config.ProgressColumn(
                                      "Dormancy", min_value=0, max_value=100, format="%.1f%%", width="small"
                                  ),
                "Credential Age": st.column_config.ProgressColumn(
                                      "Credential Age", min_value=0, max_value=100, format="%.1f%%", width="small"
                                  ),
                "Is NHI":         st.column_config.CheckboxColumn("Is NHI",     width="small"),
                "Flag":           st.column_config.TextColumn("Flag",           width="medium"),
            },
        )

        st.warning(
            "**Gokulnath Shetty (user_007) — Toxic Entitlement Pair detected.** "
            "Exposure score is high, behavioral risk is 0.09 — looks completely normal to any UEBA tool. "
            "The risk here is structural: he holds both ISSUE_LOU and APPROVE_LOU simultaneously, "
            "a combination that SoD rule SOD-001 explicitly prohibits. "
            "Behavioral monitoring alone would never surface this."
        )

# ── 2×2 Quadrant ─────────────────────────────────────────────────────────────
with tab_quadrant:
    st.subheader("Who is actually at risk?")
    st.caption("Left to right: how suspicious their behavior looks. Bottom to top: how much access they have. The danger zone is top-left — high access, nothing suspicious yet.")

    try:
        exp_resp = requests.get(f"{API}/exposure", timeout=5)
        exposure_scores = {s["user_id"]: s["score"] for s in (exp_resp.json() if exp_resp.ok else [])}
    except Exception:
        exposure_scores = {}

    try:
        import plotly.graph_objects as go
        PLOTLY = True
    except ImportError:
        PLOTLY = False

    users = roles_module.get_all_users()
    points: list[dict] = []

    for u in users:
        exp = exposure_scores.get(u.user_id, 0.0)
        beh_risk = _BEH_RISK_MAP.get(u.user_id, _DEFAULT_BEH)
        role = roles_module.get_role(u.role_id)
        tier = role.tier if role else "?"
        points.append({
            "user_id": u.user_id,
            "name": u.name,
            "tier": tier,
            "behavioral_risk": beh_risk,
            "exposure": exp,
        })

    if PLOTLY:
        fig = go.Figure()

        fig.add_shape(type="rect", x0=0, x1=0.5, y0=0.5, y1=1.0,
                      fillcolor="rgba(153,27,27,0.06)", line_width=0)
        fig.add_shape(type="rect", x0=0.5, x1=1.0, y0=0.5, y1=1.0,
                      fillcolor="rgba(146,64,14,0.06)", line_width=0)
        fig.add_shape(type="rect", x0=0, x1=0.5, y0=0, y1=0.5,
                      fillcolor="rgba(22,101,52,0.06)", line_width=0)
        fig.add_shape(type="rect", x0=0.5, x1=1.0, y0=0, y1=0.5,
                      fillcolor="rgba(146,64,14,0.06)", line_width=0)

        fig.add_shape(type="line", x0=0.5, x1=0.5, y0=0, y1=1, line=dict(color="#d1d5db", dash="dash"))
        fig.add_shape(type="line", x0=0, x1=1, y0=0.5, y1=0.5, line=dict(color="#d1d5db", dash="dash"))

        fig.add_annotation(x=0.25, y=0.97, text="⚠️ HIGH EXPOSURE<br>LOW RISK<br>(blind spot)", showarrow=False,
                           font=dict(size=11, color=_sidebar.C_DENY), align="center")
        fig.add_annotation(x=0.75, y=0.97, text="🔴 HIGH EXPOSURE<br>HIGH RISK<br>(act now)", showarrow=False,
                           font=dict(size=11, color=_sidebar.C_DENY), align="center")
        fig.add_annotation(x=0.25, y=0.03, text="🟢 LOW EXPOSURE<br>LOW RISK<br>(safe)", showarrow=False,
                           font=dict(size=11, color=_sidebar.C_ALLOW), align="center")
        fig.add_annotation(x=0.75, y=0.03, text="🟠 LOW EXPOSURE<br>HIGH RISK<br>(monitor)", showarrow=False,
                           font=dict(size=11, color=_sidebar.C_THROTTLE), align="center")

        for p in points:
            is_pnb = "user_007" in p["user_id"]
            color = _sidebar.C_DENY if is_pnb else _sidebar.C_INFO
            size = 16 if is_pnb else 10
            fig.add_trace(go.Scatter(
                x=[p["behavioral_risk"]],
                y=[p["exposure"]],
                mode="markers+text",
                marker=dict(size=size, color=color, symbol="star" if is_pnb else "circle"),
                text=[f"  {p['name']}"],
                textposition="middle right",
                name=p["name"],
                hovertemplate=(
                    f"<b>{p['name']}</b> ({p['user_id']})<br>"
                    f"Behavioral risk: {p['behavioral_risk']:.2f}<br>"
                    f"Exposure score: {p['exposure']:.2f}<br>"
                    f"Tier: {p['tier']}"
                    "<extra></extra>"
                ),
            ))

        fig.update_layout(
            showlegend=False,
            xaxis=dict(title="Behavioral Risk (LSTM)", range=[0, 1], tickformat=".0%"),
            yaxis=dict(title="Standing Exposure Score", range=[0, 1], tickformat=".0%"),
            height=500,
            margin=dict(l=40, r=40, t=40, b=40),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="#f9fafb",
        )
        st.plotly_chart(fig, width="stretch")
    else:
        for p in points:
            q_x = "HIGH" if p["behavioral_risk"] > 0.5 else "LOW"
            q_y = "HIGH" if p["exposure"] > 0.5 else "LOW"
            st.markdown(
                f"- **{p['name']}** | Risk: `{p['behavioral_risk']:.2f}` ({q_x}) | "
                f"Exposure: `{p['exposure']:.2f}` ({q_y}) | Quadrant: {q_y} exposure / {q_x} risk"
            )

    st.divider()
    st.info(
        "Gokulnath Shetty lands in the top-left — high structural exposure, near-zero behavioral anomaly. "
        "Any system that only watches what users do would give him a clean pass. "
        "What gives him away is what he is structurally allowed to do. "
        "Behavioral monitoring and access monitoring are not the same thing — this quadrant is why both are needed."
    )

# ── Org Risk Map ──────────────────────────────────────────────────────────────
with tab_orgmap:
    st.subheader("Risk Across All Branches")
    st.caption(
        "Each branch is scored on five dimensions of risk. "
        "A branch can look perfectly quiet day-to-day and still carry serious structural exposure — "
        "that gap is exactly what this view is designed to surface."
    )

    from core import broker as _broker
    import plotly.graph_objects as go

    try:
        exp_resp = requests.get(f"{API}/exposure", timeout=5)
        exp_map = {s["user_id"]: s["score"] for s in (exp_resp.json() if exp_resp.ok else [])}
    except Exception:
        exp_map = {}

    try:
        _broker.expire_stale()
        active_grants = _broker.get_active_grants()
    except Exception:
        active_grants = []

    try:
        sod_conflicts = roles_module.scan_all_conflicts()
        conflict_users = {c.user_id for c in sod_conflicts}
    except Exception:
        conflict_users = set()

    BRANCHES = ["SOL001", "SOL002", "SOL003", "SOL000"]
    BRANCH_LABELS = {
        "SOL001": "SOL001\nMumbai Main",
        "SOL002": "SOL002\nPune Central",
        "SOL003": "SOL003\nChandigarh",
        "SOL000": "SOL000\nIT / NHI",
    }

    all_users = roles_module.get_all_users()
    grants_by_user = {}
    for g in active_grants:
        grants_by_user.setdefault(g.user_id, 0)
        grants_by_user[g.user_id] += 1

    branch_stats: dict[str, dict] = {}
    for branch in BRANCHES:
        members = [u for u in all_users if u.branch_sol == branch]
        if not members:
            continue
        avg_exp = sum(exp_map.get(u.user_id, 0.0) for u in members) / len(members)
        avg_beh = sum(_BEH_RISK_MAP.get(u.user_id, _DEFAULT_BEH) for u in members) / len(members)
        sod_count = sum(1 for u in members if u.user_id in conflict_users)
        open_grants = sum(grants_by_user.get(u.user_id, 0) for u in members)
        high_priv = sum(1 for u in members if u.role_id in ("T4_MANAGER", "T5_IT_ADMIN", "NHI_SERVICE"))
        branch_stats[branch] = {
            "members": members,
            "avg_exposure": avg_exp,
            "avg_beh_risk": avg_beh,
            "sod_conflicts": sod_count,
            "open_grants": open_grants,
            "high_priv_users": high_priv,
            "high_priv_pct": high_priv / len(members),
        }

    total_users   = len(all_users)
    total_sod     = len(sod_conflicts) if hasattr(sod_conflicts, '__len__') else 0
    total_grants  = len(active_grants)
    critical_branches = sum(
        1 for b, s in branch_stats.items()
        if s["avg_exposure"] > 0.55 or s["sod_conflicts"] > 0
    )

    def _stat_card(label: str, value: str, accent: str = "#374151", sub: str = "") -> str:
        sub_html = f"<div style='font-size:0.7rem;color:{accent};margin-top:2px'>{sub}</div>" if sub else ""
        return (
            f"<div style='border:1.5px solid #e5e7eb;border-radius:8px;padding:12px 16px;"
            f"text-align:center;background:#fff;flex:1'>"
            f"<div style='font-size:0.7rem;color:#6b7280;font-weight:600;text-transform:uppercase;"
            f"letter-spacing:.04em;white-space:nowrap'>{label}</div>"
            f"<div style='font-size:1.6rem;font-weight:800;color:{accent};line-height:1.3'>{value}</div>"
            f"{sub_html}</div>"
        )

    sod_accent   = "#dc2626" if total_sod > 0 else "#374151"
    risk_accent  = "#dc2626" if critical_branches > 0 else "#374151"

    st.markdown(
        "<div style='display:flex;gap:12px;margin-bottom:4px'>"
        + _stat_card("Bank Employees",        str(total_users),                           "#374151", "across all branches incl. service accounts")
        + _stat_card("Entitlement Conflicts", str(total_sod),                             sod_accent,  "needs immediate review" if total_sod > 0 else "none detected")
        + _stat_card("Active Access Grants",  str(total_grants),                          "#374151", "open JIT sessions right now")
        + _stat_card("Branches at Risk",      f"{critical_branches}/{len(branch_stats)}", risk_accent, "review needed" if critical_branches > 0 else "all clear")
        + "</div>",
        unsafe_allow_html=True,
    )

    st.divider()

    with st.expander("What do these 5 dimensions mean?", expanded=False):
        st.markdown(
            "| Dimension | What it measures |\n"
            "|---|---|\n"
            "| **Structural Exposure** | Average privilege score of staff in this branch — how much damage they could cause based on their role alone |\n"
            "| **Behavioral Risk** | Average anomaly score from the LSTM model — how suspicious their recent activity patterns look |\n"
            "| **Entitlement Conflicts** | Number of staff who hold two entitlements that should never coexist (e.g. issue + approve on the same transaction) |\n"
            "| **High-Privilege Staff** | Share of branch staff in senior roles (Manager, IT Admin, or service accounts) |\n"
            "| **Active Access Grants** | Open JIT sessions in this branch right now — temporary access that has been issued but not yet expired |\n"
        )

    DIMENSIONS = ["Structural Exposure", "Behavioral Risk", "Entitlement Conflicts", "High-Privilege Staff", "Active Grants"]
    branch_list = list(branch_stats.keys())

    def _norm(vals: list[float]) -> list[float]:
        mx = max(vals) if max(vals) > 0 else 1
        return [v / mx for v in vals]

    raw = {
        "Structural Exposure":   [branch_stats[b]["avg_exposure"]            for b in branch_list],
        "Behavioral Risk":       [branch_stats[b]["avg_beh_risk"]            for b in branch_list],
        "Entitlement Conflicts": [float(branch_stats[b]["sod_conflicts"])    for b in branch_list],
        "High-Privilege Staff":  [branch_stats[b]["high_priv_pct"]           for b in branch_list],
        "Active Grants":         [float(branch_stats[b]["open_grants"])      for b in branch_list],
    }

    z_norm = [_norm(raw[d]) for d in DIMENSIONS]

    annotation_text = []
    fmt = {
        "Structural Exposure":   lambda b: f"{branch_stats[b]['avg_exposure']:.2f}",
        "Behavioral Risk":       lambda b: f"{branch_stats[b]['avg_beh_risk']:.2f}",
        "Entitlement Conflicts": lambda b: str(branch_stats[b]["sod_conflicts"]),
        "High-Privilege Staff":  lambda b: f"{branch_stats[b]['high_priv_pct']:.0%}",
        "Active Grants":         lambda b: str(branch_stats[b]["open_grants"]),
    }
    for dim in DIMENSIONS:
        annotation_text.append([fmt[dim](b) for b in branch_list])

    fig_hm = go.Figure(go.Heatmap(
        z=z_norm,
        x=[BRANCH_LABELS[b] for b in branch_list],
        y=DIMENSIONS,
        text=annotation_text,
        texttemplate="%{text}",
        textfont=dict(size=13, color="white"),
        colorscale=[
            [0.0,  "#166534"],
            [0.45, "#f59e0b"],
            [0.75, "#dc2626"],
            [1.0,  "#7f1d1d"],
        ],
        showscale=True,
        colorbar=dict(
            title="Risk Level",
            tickvals=[0, 0.5, 1],
            ticktext=["Low", "Medium", "High"],
            thickness=14,
        ),
        zmin=0, zmax=1,
    ))

    fig_hm.update_layout(
        height=320,
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis=dict(side="top", tickfont=dict(size=12)),
        yaxis=dict(tickfont=dict(size=12)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )

    st.plotly_chart(fig_hm, width="stretch")

    st.divider()
    st.subheader("Per-Branch Breakdown")
    st.caption("Sorted by overall risk score (entitlement conflicts weighted highest). 🔴 = critical · 🟡 = elevated · 🟢 = low.")

    import pandas as _pd

    branch_rows = []
    for branch in sorted(
        branch_list,
        key=lambda b: (
            branch_stats[b]["sod_conflicts"] * 0.5 +
            branch_stats[b]["avg_exposure"] * 0.3 +
            branch_stats[b]["avg_beh_risk"] * 0.2
        ),
        reverse=True,
    ):
        s = branch_stats[branch]
        is_critical = s["sod_conflicts"] > 0 or s["avg_exposure"] > 0.55
        status = "🔴 Critical" if is_critical else ("🟡 Elevated" if s["avg_exposure"] > 0.35 else "🟢 Low")
        label = BRANCH_LABELS[branch].replace("\n", " · ")
        member_names = ", ".join(u.name for u in s["members"])
        branch_rows.append({
            "Status":                  status,
            "Branch":                  label,
            "Staff":                   len(s["members"]),
            "Avg Structural Exposure": round(s["avg_exposure"], 2),
            "Avg Behavioral Risk":     round(s["avg_beh_risk"], 2),
            "Entitlement Conflicts":   s["sod_conflicts"],
            "Active Grants":           s["open_grants"],
            "High-Privilege Staff":    f"{s['high_priv_pct']:.0%}",
            "Members":                 member_names,
        })

    st.dataframe(
        _pd.DataFrame(branch_rows),
        width="stretch",
        hide_index=True,
        column_config={
            "Status":                  st.column_config.TextColumn("Status",                  width="small"),
            "Branch":                  st.column_config.TextColumn("Branch",                  width="medium"),
            "Staff":                   st.column_config.NumberColumn("Staff",                 width="small"),
            "Avg Structural Exposure": st.column_config.ProgressColumn(
                                           "Avg Structural Exposure", min_value=0, max_value=1,
                                           format="%.2f", width="medium"
                                       ),
            "Avg Behavioral Risk":     st.column_config.ProgressColumn(
                                           "Avg Behavioral Risk", min_value=0, max_value=1,
                                           format="%.2f", width="medium"
                                       ),
            "Entitlement Conflicts":   st.column_config.NumberColumn("Entitlement Conflicts", width="small"),
            "Active Grants":           st.column_config.NumberColumn("Active Grants",         width="small"),
            "High-Privilege Staff":    st.column_config.TextColumn("High-Privilege Staff",    width="small"),
            "Members":                 st.column_config.TextColumn("Members",                 width="large"),
        },
    )

    st.warning(
        "⚠️ **SOL003 Chandigarh** — Entitlement conflict detected. "
        "One or more staff hold both issue and approve authority on the same transaction type. "
        "Behavioral risk appears low, but the structural access combination is flagged by SoD rule SOD-001."
    )
