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
    "📊", "User Exposure",
    "Shows how much damage a user could cause, based on their role and access, not just what they have done so far. Some of the riskiest users look completely normal on the surface.",
)

tab_scores, tab_quadrant, tab_orgmap = st.tabs(["Individual Scores", "Risk × Exposure 2×2", "🗺 Org Risk Map"])

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
        scores_sorted = sorted(scores, key=lambda s: s["score"], reverse=True)
        for s in scores_sorted:
            u = roles_module.get_user(s["user_id"])
            name = u.name if u else s["user_id"]
            role = roles_module.get_role(u.role_id) if u else None
            tier = role.tier if role else "?"

            score_pct = s["score"] * 100
            color = _sidebar.C_DENY if score_pct > 60 else (_sidebar.C_THROTTLE if score_pct > 35 else _sidebar.C_ALLOW)
            bar_html = (
                f'<div style="background:#f3f4f6;border-radius:4px;height:8px;width:100%">'
                f'<div style="background:{color};width:{score_pct:.1f}%;height:8px;border-radius:4px"></div></div>'
            )

            with st.expander(
                f"**{name}** (`{s['user_id']}`) · {tier} · Exposure: **{score_pct:.1f}%**",
                expanded=("user_007" in s["user_id"]),
            ):
                st.markdown(bar_html, unsafe_allow_html=True)
                st.markdown(f"**Total exposure score: {s['score']:.4f}**")
                comps = s["components"]
                c1, c2, c3 = st.columns(3)
                c1.metric("Privilege breadth", f"{comps['privilege_breadth']:.2%}")
                c1.metric("Financial authority", f"{comps['financial_authority']:.2%}")
                c2.metric("SoD conflicts", f"{comps['sod_conflicts']:.2%}")
                c2.metric("Dormancy", f"{comps['dormancy']:.2%}")
                c3.metric("Credential age", f"{comps['credential_age']:.2%}")
                c3.metric("Is NHI", f"{comps['is_nhi']:.0%}")

                if "user_007" in s["user_id"]:
                    st.error(
                        "This is the PNB profile. Gokulnath behaves like any normal branch manager, so a behaviour-based system would never flag him. But he holds the exact access combination that made the fraud possible. This page catches that."
                    )

# ── 2×2 Quadrant ─────────────────────────────────────────────────────────────
with tab_quadrant:
    st.subheader("Who is actually at risk?")
    st.caption("Left to right: how suspicious their behaviour looks. Bottom to top: how much access they have. The danger zone is top-left, high access but nothing suspicious yet.")

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
        "Gokulnath (the PNB case) lands in the top-left. His day-to-day behaviour looks completely normal, so any system that only watches what people do would give him a clean pass. What gives him away is what he is allowed to do. Behaviour monitoring and access monitoring are not the same thing."
    )

# ── Org Risk Map ──────────────────────────────────────────────────────────────
with tab_orgmap:
    st.subheader("Branch Overview")
    st.caption("Risk across all branches at a glance. SOL003 looks quiet, but it carries the highest structural risk. That is exactly the pattern that went unnoticed at PNB for seven years.")

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

    m1, m2, m3, m4 = st.columns(4, gap="small")
    m1.metric("Identities", total_users, help="Across all branches incl. NHI")
    m2.metric("SoD Conflicts", total_sod,
              delta="CRITICAL" if total_sod > 0 else None,
              delta_color="inverse")
    m3.metric("Open Grants", total_grants)
    m4.metric("Branches at Risk", f"{critical_branches}/{len(branch_stats)}",
              delta="review needed" if critical_branches > 0 else None,
              delta_color="inverse")

    st.divider()

    DIMENSIONS = ["Avg Exposure", "Avg Beh Risk", "SoD Conflicts", "High-Priv %", "Open Grants"]
    branch_list = list(branch_stats.keys())

    def _norm(vals: list[float]) -> list[float]:
        mx = max(vals) if max(vals) > 0 else 1
        return [v / mx for v in vals]

    raw = {
        "Avg Exposure":  [branch_stats[b]["avg_exposure"]    for b in branch_list],
        "Avg Beh Risk":  [branch_stats[b]["avg_beh_risk"]    for b in branch_list],
        "SoD Conflicts": [float(branch_stats[b]["sod_conflicts"]) for b in branch_list],
        "High-Priv %":   [branch_stats[b]["high_priv_pct"]   for b in branch_list],
        "Open Grants":   [float(branch_stats[b]["open_grants"])   for b in branch_list],
    }

    z_norm = [_norm(raw[d]) for d in DIMENSIONS]

    annotation_text = []
    fmt = {
        "Avg Exposure":  lambda b: f"{branch_stats[b]['avg_exposure']:.2f}",
        "Avg Beh Risk":  lambda b: f"{branch_stats[b]['avg_beh_risk']:.2f}",
        "SoD Conflicts": lambda b: str(branch_stats[b]["sod_conflicts"]),
        "High-Priv %":   lambda b: f"{branch_stats[b]['high_priv_pct']:.0%}",
        "Open Grants":   lambda b: str(branch_stats[b]["open_grants"]),
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
    st.subheader("Branch Risk Cards")

    sorted_branches = sorted(
        branch_list,
        key=lambda b: (
            branch_stats[b]["sod_conflicts"] * 0.5 +
            branch_stats[b]["avg_exposure"] * 0.3 +
            branch_stats[b]["avg_beh_risk"] * 0.2
        ),
        reverse=True,
    )

    card_cols = st.columns(len(sorted_branches), gap="small")

    for col, branch in zip(card_cols, sorted_branches):
        s = branch_stats[branch]
        is_critical = s["sod_conflicts"] > 0 or s["avg_exposure"] > 0.55
        risk_icon = "🔴" if is_critical else ("🟡" if s["avg_exposure"] > 0.35 else "🟢")
        border_color = "#dc2626" if is_critical else ("#f59e0b" if s["avg_exposure"] > 0.35 else "#16a34a")
        sod_color = "#dc2626" if s["sod_conflicts"] > 0 else "inherit"
        branch_subtitle = BRANCH_LABELS[branch].replace("\n", " · ")

        with col:
            st.markdown(
                f"<div style='border:2px solid {border_color};border-radius:8px;padding:12px 14px'>"
                f"<div style='font-weight:700;font-size:0.95rem'>{risk_icon} {branch}</div>"
                f"<div style='color:#6b7280;font-size:0.78rem;margin-bottom:8px'>"
                f"{branch_subtitle} · {len(s['members'])} identities</div>"
                f"<div style='display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:8px'>"
                f"<div><div style='font-size:0.7rem;color:#6b7280'>Exposure</div>"
                f"<div style='font-weight:700;font-size:1rem'>{s['avg_exposure']:.2f}</div></div>"
                f"<div><div style='font-size:0.7rem;color:#6b7280'>Beh Risk</div>"
                f"<div style='font-weight:700;font-size:1rem'>{s['avg_beh_risk']:.2f}</div></div>"
                f"<div><div style='font-size:0.7rem;color:#6b7280'>SoD Conflicts</div>"
                f"<div style='font-weight:700;font-size:1rem;color:{sod_color}'>"
                f"{s['sod_conflicts']}</div></div>"
                f"<div><div style='font-size:0.7rem;color:#6b7280'>Open Grants</div>"
                f"<div style='font-weight:700;font-size:1rem'>{s['open_grants']}</div></div>"
                f"</div>"
                f"<div style='font-size:0.72rem;font-weight:600;color:#374151;margin-bottom:4px'>Identities</div>",
                unsafe_allow_html=True,
            )
            for u in s["members"]:
                role = roles_module.get_role(u.role_id)
                tier = role.tier if role else u.role_id
                exp_score = exp_map.get(u.user_id, 0.0)
                beh_score = _BEH_RISK_MAP.get(u.user_id, _DEFAULT_BEH)
                has_sod   = u.user_id in conflict_users
                has_grant = u.user_id in grants_by_user
                flags = (
                    ("⚠️ " if has_sod else "") +
                    ("🔑 " if has_grant else "") +
                    ("🔴 " if exp_score > 0.6 else "") +
                    ("🟠 " if beh_score > 0.5 else "")
                ).strip() or "✅"
                st.markdown(
                    f"<div style='font-size:0.75rem;padding:3px 0;border-bottom:1px solid #f3f4f6'>"
                    f"<span style='font-family:monospace'>{u.user_id}</span> {u.name} "
                    f"<span style='color:#6b7280'>T{tier}</span> {flags}</div>",
                    unsafe_allow_html=True,
                )
            if branch == "SOL003":
                st.markdown(
                    "<div style='margin-top:8px;padding:6px 8px;background:#fef2f2;"
                    "border-radius:4px;font-size:0.72rem;color:#991b1b'>"
                    "PNB pattern: user_007 can issue AND approve LoUs alone. "
                    "Behaviour looks normal (0.09) — only structural access check catches this."
                    "</div>",
                    unsafe_allow_html=True,
                )
            st.markdown("</div>", unsafe_allow_html=True)
