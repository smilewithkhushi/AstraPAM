"""AstraPAM — Risk Engine page."""
from __future__ import annotations

import json

import _sidebar
import pandas as pd
import streamlit as st

from core import risk as risk_engine
from core.schemas import init_db

init_db()

_FEAT_CFG: dict[str, dict] = {
    "logon_count":   {"label": "Logon Count",         "min": 0,   "max": 30,  "step": 1,    "unit": "sessions", "tag_thresh": None, "normal": 5,   "mal": 1},
    "after_hours":   {"label": "After-Hours Ratio",   "min": 0.0, "max": 1.0, "step": 0.01, "unit": "0–1",      "tag_thresh": 0.30, "normal": 0.0, "mal": 0.9},
    "unique_pcs":    {"label": "Unique PCs Accessed", "min": 0,   "max": 10,  "step": 1,    "unit": "machines", "tag_thresh": 2.0,  "normal": 1,   "mal": 4},
    "device_events": {"label": "Device / USB Events", "min": 0,   "max": 20,  "step": 1,    "unit": "events",   "tag_thresh": 2.0,  "normal": 0,   "mal": 8},
    "file_events":   {"label": "File Events",         "min": 0,   "max": 300, "step": 1,    "unit": "events",   "tag_thresh": 50.0, "normal": 12,  "mal": 150},
    "http_events":   {"label": "HTTP Events",         "min": 0,   "max": 200, "step": 1,    "unit": "events",   "tag_thresh": None, "normal": 60,  "mal": 2},
    "email_events":  {"label": "Email Events",        "min": 0,   "max": 50,  "step": 1,    "unit": "events",   "tag_thresh": None, "normal": 10,  "mal": 0},
}

_TAG_LABEL = {
    "OFF_HOURS_ACTIVITY":   ("🌙 Off-Hours Activity",   _sidebar.C_INFO),
    "ANOMALOUS_LOCATION":   ("📍 Anomalous Location",   _sidebar.C_THROTTLE),
    "MASS_DATA_EXPORT":     ("📤 Mass Data Export",     _sidebar.C_DENY),
    "PRIVILEGE_ESCALATION": ("⚡ Privilege Escalation", _sidebar.C_DENY),
}

_sidebar.render_page_header(
    "", "Risk Scoring",
    "Monitors session activity for bank staff including tellers, branch officers, finance managers, and IT admins. "
    "Scores risk based on CBS access patterns, after-hours logins, file movement, and device events. "
    "Trained on real insider-threat data and explains exactly which signals drove the decision.",
)

# ── Three-scenario comparison ─────────────────────────────────────────────────
_SCENARIOS = [
    (
        "Branch Officer — Regular Day",
        "Routine access during business hours from a single workstation. No anomalies.",
        {"logon_count": 5, "after_hours": 0.0, "unique_pcs": 1,
         "device_events": 0, "file_events": 12, "http_events": 60, "email_events": 10},
    ),
    (
        "Finance Manager — After-Hours Access",
        "Late-night login from three machines with elevated file activity. Gets a step-up challenge before access is granted.",
        {"logon_count": 4, "after_hours": 0.45, "unique_pcs": 3,
         "device_events": 1, "file_events": 60, "http_events": 25, "email_events": 3},
    ),
    (
        "Rogue Admin — Data Exfiltration",
        "Off-hours, mass file export, USB events, near-zero email and HTTP. Classic insider exfiltration — access denied.",
        {"logon_count": 1, "after_hours": 0.9, "unique_pcs": 4,
         "device_events": 8, "file_events": 150, "http_events": 2, "email_events": 0},
    ),
]


@st.cache_data(show_spinner=False)
def _cached_score(features_tuple: tuple) -> object:
    return risk_engine.score(dict(features_tuple))


tab_scenarios, tab_scorer = st.tabs(["Session Scenarios", "Score a Session"])

# ── Tab 1: Session Scenarios ──────────────────────────────────────────────────
with tab_scenarios:
    st.subheader("Three Sessions. Three Outcomes.")
    st.caption(
        "The risk engine evaluates each session independently. "
        "Behavior determines the decision, not the employee's title or role."
    )

    _card_parts = []
    for name, desc, feats in _SCENARIOS:
        res = _cached_score(tuple(sorted(feats.items())))
        clr = _sidebar.DECISION_COLOR.get(res.decision, _sidebar.C_INFO)
        bdg = _sidebar.DECISION_BADGE.get(res.decision, res.decision.upper())
        top = max(res.top_factors, key=lambda f: abs(f.contribution)) if res.top_factors else None
        top_html = ""
        if top:
            top_lbl = _FEAT_CFG.get(top.feature, {}).get("label", top.feature)
            top_html = (
                f"<p style='font-size:0.75rem;color:#6b7280;margin:6px 0 0'>"
                f"Top signal: <code>{top_lbl}</code> ({top.contribution:+.4f})</p>"
            )
        flags_html = ""
        if res.attack_tags:
            flags_str = " · ".join(_TAG_LABEL.get(t, (t, ""))[0] for t in res.attack_tags)
            flags_html = f"<p style='font-size:0.75rem;color:#6b7280;margin:4px 0 0'>Flags: {flags_str}</p>"
        _card_parts.append(
            f"<div style='border:1.5px solid #e5e7eb;border-radius:8px;padding:16px;background:#fff'>"
            f"<div style='background:{clr};color:#fff;padding:6px 12px;border-radius:6px;"
            f"font-size:0.8rem;font-weight:700;text-align:center;margin-bottom:10px'>"
            f"{bdg} · {res.score:.3f}</div>"
            f"<p style='font-weight:600;margin:0 0 6px;font-size:0.9rem'>{name}</p>"
            f"<p style='font-size:0.8rem;color:#6b7280;margin:0'>{desc}</p>"
            f"{top_html}{flags_html}"
            f"</div>"
        )
    st.markdown(
        "<div style='display:grid;grid-template-columns:repeat(3,1fr);gap:16px'>"
        + "".join(_card_parts)
        + "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    with st.expander("How scoring works"):
        st.image("preview/scoring_pipeline.png", width="stretch")

# ── Tab 2: Score a Session ────────────────────────────────────────────────────
with tab_scorer:
    with st.container(border=True):
        st.markdown("##### Session Mode")

        m_col, btn_col = st.columns([3, 1])
        with m_col:
            mode = st.radio(
                "mode", ["Normal", "Malicious", "Custom"],
                horizontal=True,
                label_visibility="collapsed",
            )
        with btn_col:
            score_clicked = st.button("▶ Score Session", width="stretch", type="primary")

    custom_features: dict[str, float] = {}

    # Sample scenario: suspicious finance analyst session with multiple attack flags
    _SAMPLE_FEATURES: dict[str, float] = {
        "logon_count":   2,
        "after_hours":   0.72,
        "unique_pcs":    3,
        "device_events": 5,
        "file_events":   110,
        "http_events":   8,
        "email_events":  1,
    }

    if mode == "Custom":
        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("Configure custom session", expanded=True):
            up_col, sample_col = st.columns([2, 1])
            with up_col:
                uploaded = st.file_uploader(
                    "Upload log file to pre-fill (CSV or JSON)",
                    type=["csv", "json"],
                )
            with sample_col:
                st.markdown("&nbsp;", unsafe_allow_html=True)
                if st.button("Load sample data", width="stretch", key="load_sample", help="Fills in a suspicious finance analyst scenario — off-hours access, bulk file export, and USB activity — so you can see how the risk engine flags real-world behaviour."):
                    st.session_state["custom_from_sample"] = True
                st.caption("Loads a pre-built example with multiple risk flags triggered.")

            prefill: dict[str, float] = {}
            if uploaded:
                try:
                    if uploaded.name.endswith(".json"):
                        raw_data = json.load(uploaded)
                        if isinstance(raw_data, list):
                            raw_data = raw_data[0]
                        prefill = {k: float(v) for k, v in raw_data.items() if k in _FEAT_CFG}
                    else:
                        df_up = pd.read_csv(uploaded)
                        row = df_up.iloc[0].to_dict()
                        prefill = {k: float(row[k]) for k in _FEAT_CFG if k in row}
                    st.session_state.pop("custom_from_sample", None)
                    st.success(f"✅ Loaded {len(prefill)} features from **{uploaded.name}**")
                except Exception as e:
                    st.error(f"Parse error: {e}")
            elif st.session_state.get("custom_from_sample"):
                prefill = _SAMPLE_FEATURES
                st.info("Sample data loaded — a suspicious finance analyst session with off-hours access, bulk file export, and USB events. Click **▶ Score Session** to score it.")

            defaults = prefill or _sidebar.NORMAL_FEATURES
            st.markdown("**Session feature values**")
            row1 = st.columns(4)
            row2 = st.columns(3)
            feat_list = list(_FEAT_CFG.items())

            for idx, (feat, cfg) in enumerate(feat_list):
                col = (row1 + row2)[idx]
                val = defaults.get(feat, cfg["normal"])
                tip = f"Attack tag triggers above {cfg['tag_thresh']}" if cfg["tag_thresh"] else None
                with col:
                    if cfg["step"] == 1:
                        custom_features[feat] = float(st.number_input(
                            cfg["label"], int(cfg["min"]), int(cfg["max"]),
                            value=int(val), step=1, help=tip,
                        ))
                    else:
                        custom_features[feat] = st.number_input(
                            cfg["label"], float(cfg["min"]), float(cfg["max"]),
                            value=float(val), step=cfg["step"], format="%.2f", help=tip,
                        )

        flagged_preview = [
            f"`{cfg['label']}` = **{custom_features.get(feat, 0)}** (threshold {cfg['tag_thresh']})"
            for feat, cfg in _FEAT_CFG.items()
            if cfg["tag_thresh"] and custom_features.get(feat, 0) >= cfg["tag_thresh"]
        ]
        if flagged_preview:
            st.warning("⚠️ These features will trigger attack tags: " + " · ".join(flagged_preview))

    if score_clicked:
        features = (
            _sidebar.NORMAL_FEATURES if mode == "Normal"
            else _sidebar.MAL_FEATURES if mode == "Malicious"
            else custom_features
        )
        with st.spinner("Scoring…"):
            st.session_state["last_risk"]     = risk_engine.score(features)
            st.session_state["last_features"] = features

    r   = st.session_state.get("last_risk")
    raw = st.session_state.get("last_features")

    if r is None:
        st.markdown("<br>", unsafe_allow_html=True)
        st.info("Select a session mode above and click **▶ Score Session** to see results.")
        st.stop()

    try:
        import plotly.graph_objects as go
        PLOTLY = True
    except ImportError:
        PLOTLY = False

    color = _sidebar.DECISION_COLOR.get(r.decision, _sidebar.C_INFO)
    badge = _sidebar.DECISION_BADGE.get(r.decision, r.decision.upper())

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown(
        f"<div style='background:{color};color:white;padding:14px 22px;"
        f"border-radius:6px;font-size:20px;font-weight:700;text-align:center;"
        f"margin-bottom:18px'>{badge}</div>",
        unsafe_allow_html=True,
    )

    col_metrics, col_gauge, col_thresh = st.columns([1.4, 1.8, 1.4])

    with col_metrics:
        st.metric("Risk Score",  f"{r.score:.3f}")
        st.metric("Decision",    r.decision.upper())
        st.metric("Attack Tags", len(r.attack_tags))

    with col_gauge:
        if PLOTLY:
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=r.score,
                number={"font": {"size": 40, "color": color}, "valueformat": ".3f"},
                gauge={
                    "axis": {"range": [0, 1], "tickformat": ".1f", "tickwidth": 1},
                    "bar":  {"color": color, "thickness": 0.22},
                    "steps": [
                        {"range": [0.00, 0.40], "color": "#d1fae5"},
                        {"range": [0.40, 0.65], "color": "#fef3c7"},
                        {"range": [0.65, 0.80], "color": "#fed7aa"},
                        {"range": [0.80, 1.00], "color": "#fee2e2"},
                    ],
                    "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.7, "value": r.score},
                },
                title={"text": "Risk Score", "font": {"size": 14}},
            ))
            fig_gauge.update_layout(
                height=240,
                margin=dict(l=10, r=10, t=30, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig_gauge, width="stretch")

    with col_thresh:
        st.markdown("**Decision thresholds**")
        for zone, rng, icon in [
            ("Allow",    "< 0.40",      "🟢"),
            ("Throttle", "0.40 – 0.65", "🟡"),
            ("Step-Up",  "0.65 – 0.80", "🟠"),
            ("Deny",     "≥ 0.80",      "🔴"),
        ]:
            active = " ◀" if r.decision.replace("_", " ").lower() in zone.lower() else ""
            st.markdown(f"{icon} **{zone}**: {rng}{active}")

    st.markdown("<br>", unsafe_allow_html=True)

    col_shap, col_tags = st.columns([3, 2])

    with col_shap:
        st.subheader("What drove the score")
        st.caption("Each bar shows how much that behavior raised the risk 🔴 or lowered it 🟢.")
        if r.top_factors and PLOTLY:
            factors_sorted = sorted(r.top_factors, key=lambda x: x.contribution)
            labels = [_FEAT_CFG.get(f.feature, {}).get("label", f.feature) for f in factors_sorted]
            values = [f.contribution for f in factors_sorted]
            colors = [_sidebar.C_ALLOW if v < 0 else _sidebar.C_DENY for v in values]

            fig_shap = go.Figure(go.Bar(
                x=values, y=labels, orientation="h",
                marker_color=colors,
                text=[f"{v:+.4f}" for v in values],
                textposition="outside",
            ))
            fig_shap.update_layout(
                height=200, margin=dict(l=10, r=70, t=10, b=10),
                xaxis=dict(title="SHAP contribution", zeroline=True, zerolinecolor="#d1d5db", zerolinewidth=2),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="#f9fafb",
            )
            st.plotly_chart(fig_shap, width="stretch")
            for f in sorted(r.top_factors, key=lambda x: abs(x.contribution), reverse=True):
                lbl  = _FEAT_CFG.get(f.feature, {}).get("label", f.feature)
                sign = "▲ raises" if f.contribution > 0 else "▼ lowers"
                st.caption(f"`{lbl}`: {f.contribution:+.4f} ({sign} risk)")
        else:
            st.info("No SHAP data available.")

    with col_tags:
        st.subheader("Warning Flags")
        st.caption("Fixed rules that fire when certain behaviors cross a threshold, separate from the score.")
        if r.attack_tags:
            for tag in r.attack_tags:
                lbl, clr = _TAG_LABEL.get(tag, (tag, _sidebar.C_INFO))
                st.markdown(
                    f'<div style="background:{clr};color:#fff;padding:9px 14px;border-radius:6px;'
                    f'font-weight:600;margin-bottom:6px">{lbl}</div>',
                    unsafe_allow_html=True,
                )
                for rule_tag, feat, thresh in risk_engine._TAG_RULES:
                    if rule_tag == tag and raw:
                        val = raw.get(feat, 0)
                        st.caption(f"`{_FEAT_CFG[feat]['label']}` = **{val}** · threshold {thresh}")
        else:
            st.success("✅ No attack patterns triggered.")

    st.markdown("<br>", unsafe_allow_html=True)

    with st.expander("Session breakdown and comparison"):
        col_radar, col_table = st.columns([3, 2])

        with col_radar:
            st.caption("Shows this session compared to what normal and suspicious employees typically look like.")
            if raw and PLOTLY:
                feats       = list(_FEAT_CFG.keys())
                feat_labels = [_FEAT_CFG[f]["label"] for f in feats]
                maxes       = [max(_FEAT_CFG[f]["max"], 1) for f in feats]

                def _norm(d: dict) -> list[float]:
                    return [min(d.get(k, 0) / m, 1.0) for k, m in zip(feats, maxes)]

                def _hex_rgba(hex_color: str, alpha: float = 0.08) -> str:
                    h = hex_color.lstrip("#")
                    r2, g2, b2 = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
                    return f"rgba({r2},{g2},{b2},{alpha})"

                def _trace(vals, name, clr, dash="solid"):
                    v = vals + [vals[0]]
                    l = feat_labels + [feat_labels[0]]
                    return go.Scatterpolar(
                        r=v, theta=l, name=name,
                        line=dict(color=clr, dash=dash, width=2),
                        fill="toself",
                        fillcolor=_hex_rgba(clr),
                    )

                fig_r = go.Figure([
                    _trace(_norm(_sidebar.NORMAL_FEATURES), "Normal baseline",    _sidebar.C_ALLOW, "dot"),
                    _trace(_norm(_sidebar.MAL_FEATURES),    "Malicious baseline", _sidebar.C_DENY, "dot"),
                    _trace(_norm(raw),                       "This session",       color),
                ])
                fig_r.update_layout(
                    polar=dict(radialaxis=dict(visible=True, range=[0, 1], tickformat=".0%")),
                    showlegend=True, height=360, margin=dict(l=30, r=30, t=30, b=30),
                    paper_bgcolor="rgba(0,0,0,0)",
                )
                st.plotly_chart(fig_r, width="stretch")

        with col_table:
            if raw:
                rows = []
                for feat, cfg in _FEAT_CFG.items():
                    val = raw.get(feat, 0)
                    flagged = cfg["tag_thresh"] is not None and val >= cfg["tag_thresh"]
                    rows.append({
                        "Feature":   cfg["label"],
                        "Value":     val,
                        "Threshold": str(cfg["tag_thresh"]) if cfg["tag_thresh"] else "—",
                        "Status":    "⚠️ Flagged" if flagged else "✅ OK",
                    })
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=300)

    with st.expander("What patterns does the system look for?"):
        t1, t2, t3, t4 = st.columns(4)
        for col, icon, title, desc in [
            (t1, "🌙", "Off-Hours Activity",   "Working mostly outside business hours. A common early sign before something goes wrong."),
            (t2, "📍", "Unusual Devices",      "Logging in from multiple machines or using USB drives. Could mean moving data around."),
            (t3, "📤", "Bulk Data Movement",   "Copying or moving a large number of files in one session."),
            (t4, "⚡", "Privilege Misuse",     "USB activity combined with multi-machine access. Looks like credential harvesting."),
        ]:
            with col:
                st.markdown(f"**{icon} {title}**")
                st.caption(desc)

    st.markdown("<br>", unsafe_allow_html=True)
