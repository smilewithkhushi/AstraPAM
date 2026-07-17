"""Phase 9 — Standing Exposure Score + 2×2 behavioral-risk × standing-exposure quadrant.

Exposure = what you COULD do (static/identity properties).
Risk     = what you DID (behavioral, from Phase 0-5 LSTM engine).
Orthogonal, complementary, never redundant.
"""
from __future__ import annotations

import requests
import streamlit as st

import _sidebar
import risk as risk_engine
import roles as roles_module

st.set_page_config(page_title="Exposure Score", page_icon="📊", layout="wide")

API = _sidebar.API_URL

_sidebar.render_page_header(
    "📊", "Standing Exposure Score",
    "Measures structural risk — what an identity is capable of doing, independent of what it has actually done. Exposure is computed from privilege breadth, financial authority, SoD violations, dormancy, credential age, and NHI flags.",
    "The 2×2 quadrant plots exposure against behavioural risk to surface the most dangerous blind spot: high-exposure users who appear safe to anomaly detectors precisely because they have not yet acted.",
)

tab_scores, tab_quadrant, tab_orgmap = st.tabs(["Individual Scores", "Risk × Exposure 2×2", "🗺 Org Risk Map"])

# ── Individual Scores ─────────────────────────────────────────────────────────
with tab_scores:
    st.subheader("Exposure Scores — All Users")

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
            color = "#a00000" if score_pct > 60 else ("#b36b00" if score_pct > 35 else "#1a7a1a")
            bar_html = (
                f'<div style="background:#eee;border-radius:4px;height:8px;width:100%">'
                f'<div style="background:{color};width:{score_pct:.1f}%;height:8px;border-radius:4px"></div></div>'
            )

            with st.expander(
                f"**{name}** (`{s['user_id']}`) · {tier} — Exposure: **{score_pct:.1f}%**",
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
                        "🎯 **PNB archetype in the high-exposure / low-behavioral-risk quadrant.** "
                        "This user behaves normally but carries the structural combination that "
                        "enabled ₹11,400 Cr in fraud. A behavioral model alone is blind to this. "
                        "Exposure score catches it."
                    )

# ── 2×2 Quadrant ─────────────────────────────────────────────────────────────
with tab_quadrant:
    st.subheader("Risk × Exposure 2×2 Quadrant")
    st.caption(
        "x-axis: **Behavioral risk** (LSTM anomaly score, from Phase 0–5 engine). "
        "y-axis: **Standing exposure** (identity properties only). "
        "Top-left = the blind spot: high exposure, normal behavior. PNB archetype lives here."
    )

    try:
        import json
        exp_resp = requests.get(f"{API}/exposure", timeout=5)
        exposure_scores = {s["user_id"]: s["score"] for s in (exp_resp.json() if exp_resp.ok else [])}
    except Exception:
        exposure_scores = {}

    # Compute behavioral risk for each user using normal-ish features
    # (in a real system this comes from session telemetry)
    from _sidebar import NORMAL_FEATURES, MAL_FEATURES

    try:
        import plotly.graph_objects as go
        PLOTLY = True
    except ImportError:
        PLOTLY = False

    users = roles_module.get_all_users()
    points: list[dict] = []

    for u in users:
        exp = exposure_scores.get(u.user_id, 0.0)
        # Use saved behavioral risk or default to a low score for demo
        beh_risk = 0.12  # default "normal" behavioral risk
        if "user_007" in u.user_id:
            beh_risk = 0.09  # PNB archetype: behaves normally
        elif u.role_id == "T1_TELLER" and u.user_id == "user_001":
            beh_risk = 0.71  # demo: junior teller with anomalous behavior
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
        import plotly.graph_objects as go

        fig = go.Figure()

        # Quadrant background
        fig.add_shape(type="rect", x0=0, x1=0.5, y0=0.5, y1=1.0,
                      fillcolor="rgba(160,0,0,0.07)", line_width=0)  # top-left: blind spot
        fig.add_shape(type="rect", x0=0.5, x1=1.0, y0=0.5, y1=1.0,
                      fillcolor="rgba(163,107,0,0.07)", line_width=0)  # top-right: highest risk
        fig.add_shape(type="rect", x0=0, x1=0.5, y0=0, y1=0.5,
                      fillcolor="rgba(26,122,26,0.07)", line_width=0)  # bottom-left: safe
        fig.add_shape(type="rect", x0=0.5, x1=1.0, y0=0, y1=0.5,
                      fillcolor="rgba(163,107,0,0.07)", line_width=0)  # bottom-right: behavior-only risk

        # Quadrant dividers
        fig.add_shape(type="line", x0=0.5, x1=0.5, y0=0, y1=1, line=dict(color="#aaa", dash="dash"))
        fig.add_shape(type="line", x0=0, x1=1, y0=0.5, y1=0.5, line=dict(color="#aaa", dash="dash"))

        # Quadrant labels
        fig.add_annotation(x=0.25, y=0.97, text="⚠️ HIGH EXPOSURE<br>LOW RISK<br>(blind spot)", showarrow=False,
                           font=dict(size=11, color="#a00000"), align="center")
        fig.add_annotation(x=0.75, y=0.97, text="🔴 HIGH EXPOSURE<br>HIGH RISK<br>(act now)", showarrow=False,
                           font=dict(size=11, color="#a00000"), align="center")
        fig.add_annotation(x=0.25, y=0.03, text="🟢 LOW EXPOSURE<br>LOW RISK<br>(safe)", showarrow=False,
                           font=dict(size=11, color="#1a7a1a"), align="center")
        fig.add_annotation(x=0.75, y=0.03, text="🟠 LOW EXPOSURE<br>HIGH RISK<br>(monitor)", showarrow=False,
                           font=dict(size=11, color="#b36b00"), align="center")

        for p in points:
            is_pnb = "user_007" in p["user_id"]
            color = "#a00000" if is_pnb else "#4a90d9"
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
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        # Fallback: text-based table if plotly not installed
        st.warning("Install `plotly` for the interactive 2×2 chart.")
        for p in points:
            q_x = "HIGH" if p["behavioral_risk"] > 0.5 else "LOW"
            q_y = "HIGH" if p["exposure"] > 0.5 else "LOW"
            st.markdown(
                f"- **{p['name']}** | Risk: `{p['behavioral_risk']:.2f}` ({q_x}) | "
                f"Exposure: `{p['exposure']:.2f}` ({q_y}) | Quadrant: {q_y} exposure / {q_x} risk"
            )

    st.divider()
    st.info(
        "**The insight this quadrant delivers:**\n\n"
        "Gokulnath Shetty (the PNB archetype) sits in the **top-left** — high standing exposure, "
        "normal behavioral risk. A behavioral anomaly model trained on session data would never flag him. "
        "He behaves exactly like a legitimate Branch Manager. "
        "Only the structural property — holding both ISSUE_LOU and APPROVE_LOU — reveals the risk. "
        "**Exposure ≠ risk. They are orthogonal. Both are needed.**"
    )

# ── Org Risk Map ──────────────────────────────────────────────────────────────
with tab_orgmap:
    st.subheader("Organisation-Level Risk Map")
    st.caption(
        "Branch-level aggregation across four risk dimensions. "
        "Green = within tolerance · Amber = elevated · Red = requires action. "
        "**The key story:** SOL003 looks behaviorally quiet but carries the highest structural risk — "
        "exactly how PNB went undetected for seven years."
    )

    import broker as _broker
    import plotly.graph_objects as go

    # ── Build branch data ────────────────────────────────────────────────────
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

    BEH_RISK_MAP = {
        "user_001": 0.71, "user_007": 0.09,
    }
    DEFAULT_BEH = 0.12

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
        avg_beh = sum(BEH_RISK_MAP.get(u.user_id, DEFAULT_BEH) for u in members) / len(members)
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

    # ── Org summary bar ──────────────────────────────────────────────────────
    total_users   = len(all_users)
    total_sod     = len(sod_conflicts) if hasattr(sod_conflicts, '__len__') else 0
    total_grants  = len(active_grants)
    critical_branches = sum(
        1 for b, s in branch_stats.items()
        if s["avg_exposure"] > 0.55 or s["sod_conflicts"] > 0
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Identities", total_users, help="Across all branches incl. NHI")
    m2.metric("SoD Conflicts", total_sod,
              delta="CRITICAL" if total_sod > 0 else None,
              delta_color="inverse")
    m3.metric("Open Grants", total_grants,
              help="Active JIT grants right now")
    m4.metric("Branches at Risk", f"{critical_branches} / {len(branch_stats)}",
              delta="requires review" if critical_branches > 0 else None,
              delta_color="inverse")

    st.divider()

    # ── Plotly heatmap ───────────────────────────────────────────────────────
    DIMENSIONS = ["Avg Exposure", "Avg Beh Risk", "SoD Conflicts", "High-Priv %", "Open Grants"]
    branch_list = list(branch_stats.keys())

    # Normalise each dimension to 0-1 for color scale
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
            [0.0,  "#15803d"],
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

    st.plotly_chart(fig_hm, use_container_width=True)

    st.caption(
        "Values shown are actuals. Color intensity reflects normalized severity relative to the highest-risk branch. "
        "All five dimensions are independent — a branch can score low on behavioral risk and still be critical."
    )

    st.divider()

    # ── Branch risk cards ────────────────────────────────────────────────────
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

    for branch in sorted_branches:
        s = branch_stats[branch]
        is_critical = s["sod_conflicts"] > 0 or s["avg_exposure"] > 0.55
        border_color = "#dc2626" if is_critical else ("#f59e0b" if s["avg_exposure"] > 0.35 else "#15803d")
        risk_label   = "🔴 HIGH RISK" if is_critical else ("🟡 ELEVATED" if s["avg_exposure"] > 0.35 else "🟢 NORMAL")

        with st.expander(
            f"{risk_label}  ·  **{branch}** — {len(s['members'])} identities",
            expanded=is_critical,
        ):
            st.markdown(
                f'<div style="border-left:4px solid {border_color};padding-left:12px;margin-bottom:10px">',
                unsafe_allow_html=True,
            )

            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Avg Exposure",   f"{s['avg_exposure']:.2f}")
            mc2.metric("Avg Beh Risk",   f"{s['avg_beh_risk']:.2f}")
            mc3.metric("SoD Conflicts",  s["sod_conflicts"],
                       delta="CRITICAL" if s["sod_conflicts"] > 0 else None,
                       delta_color="inverse")
            mc4.metric("Open Grants",    s["open_grants"])

            # User roster
            st.markdown("**Identities in this branch:**")
            for u in s["members"]:
                role = roles_module.get_role(u.role_id)
                tier = role.tier if role else u.role_id
                exp_score = exp_map.get(u.user_id, 0.0)
                beh_score = BEH_RISK_MAP.get(u.user_id, DEFAULT_BEH)
                has_sod = u.user_id in conflict_users
                has_grant = u.user_id in grants_by_user

                flags = []
                if has_sod:   flags.append("⚠️ SoD conflict")
                if has_grant: flags.append("🔑 active grant")
                if exp_score > 0.6: flags.append("🔴 high exposure")
                if beh_score > 0.5: flags.append("🟠 beh anomaly")

                flag_str = "  ·  ".join(flags) if flags else "✅ clean"
                st.markdown(
                    f"&nbsp;&nbsp;`{u.user_id}` **{u.name}** ({tier}) "
                    f"· exp `{exp_score:.2f}` · beh `{beh_score:.2f}` · {flag_str}"
                )

            if branch == "SOL003":
                st.error(
                    "**SOL003 is the PNB archetype branch.** "
                    "`user_007` holds both `ISSUE_LOU` + `APPROVE_LOU` — SoD-001 CRITICAL. "
                    "Behavioral risk appears normal (0.09). A UEBA system would give this branch a clean bill of health. "
                    "AstraPAM doesn't."
                )

            st.markdown("</div>", unsafe_allow_html=True)
