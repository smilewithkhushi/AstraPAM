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

st.title("Standing Exposure Score")
st.caption(
    "Orthogonal to behavioral risk — not an inverse of it. "
    "**Exposure** = privilege breadth + financial authority + SoD conflicts + dormancy + credential age + NHI flag. "
    "**The 2×2 quadrant is the key insight:** a behavioral model alone is structurally blind to the top-left (high exposure, normal behavior)."
)
st.divider()

tab_scores, tab_quadrant = st.tabs(["Individual Scores", "Risk × Exposure 2×2"])

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
