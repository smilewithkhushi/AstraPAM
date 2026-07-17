"""AstraPAM — Risk Engine page."""
from __future__ import annotations

import json

import _sidebar
import pandas as pd
import streamlit as st

import risk as risk_engine
from schemas import init_db

st.set_page_config(
    page_title="AstraPAM · Risk Engine",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

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
    "OFF_HOURS_ACTIVITY":   ("🌙 Off-Hours Activity",   "#6a0dad"),
    "ANOMALOUS_LOCATION":   ("📍 Anomalous Location",   "#b36b00"),
    "MASS_DATA_EXPORT":     ("📤 Mass Data Export",     "#a00000"),
    "PRIVILEGE_ESCALATION": ("⚡ Privilege Escalation", "#a00000"),
}

# ── sidebar — refresh only ────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("&nbsp;")
    if st.button("↺ Refresh", use_container_width=True):
        st.rerun()

# ── header ────────────────────────────────────────────────────────────────────
st.title("Risk Engine")
st.markdown(
    "Session-level behavioural anomaly scoring via an LSTM autoencoder trained on the "
    "CERT Insider Threat dataset. Score, contributing features, and named attack patterns "
    "are surfaced together. Choose a session mode below, configure inputs if needed, then score."
)

st.markdown("<br>", unsafe_allow_html=True)

# ── scoring pipeline infographic ──────────────────────────────────────────────
st.image("preview/scoring_pipeline.png", use_container_width=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── feature category cards ────────────────────────────────────────────────────
_CARDS_HTML = """
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:4px">

  <div style="border:1px solid #c8e6c9;border-radius:10px;padding:14px 16px;background:#f1f8f1">
    <div style="font-size:0.7rem;font-weight:700;letter-spacing:.07em;color:#1a7a1a;margin-bottom:8px">🕐 TEMPORAL PATTERNS</div>
    <div style="font-size:0.82rem;color:#333;line-height:1.7">
      <b>Logon Count</b> — sessions in the window<br>
      <b>After-Hours Ratio</b> — fraction of activity outside business hours
    </div>
    <div style="margin-top:8px;font-size:0.7rem;color:#777">Flags: off-hours spikes, dormant accounts suddenly active</div>
  </div>

  <div style="border:1px solid #fff3cd;border-radius:10px;padding:14px 16px;background:#fffdf0">
    <div style="font-size:0.7rem;font-weight:700;letter-spacing:.07em;color:#b36b00;margin-bottom:8px">🖥️ LATERAL MOVEMENT</div>
    <div style="font-size:0.82rem;color:#333;line-height:1.7">
      <b>Unique PCs Accessed</b> — distinct machines touched<br>
      <b>Device / USB Events</b> — removable media activity
    </div>
    <div style="margin-top:8px;font-size:0.7rem;color:#777">Flags: multi-PC access (≥ 2), USB exfil attempts (≥ 2 events)</div>
  </div>

  <div style="border:1px solid #f8d7da;border-radius:10px;padding:14px 16px;background:#fff8f8">
    <div style="font-size:0.7rem;font-weight:700;letter-spacing:.07em;color:#a00000;margin-bottom:8px">📤 DATA MOVEMENT</div>
    <div style="font-size:0.82rem;color:#333;line-height:1.7">
      <b>File Events</b> — copies, moves, renames, deletes<br>
      <b>HTTP Events</b> — outbound web traffic volume<br>
      <b>Email Events</b> — messages sent in window
    </div>
    <div style="margin-top:8px;font-size:0.7rem;color:#777">Flags: mass export ≥ 50 file events</div>
  </div>

</div>
"""
st.markdown(_CARDS_HTML, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── session mode + score panel ────────────────────────────────────────────────
with st.container(border=True):
    st.markdown("##### Session Mode")
    st.caption(
        "**Normal** — typical low-risk baseline from the CERT dataset. "
        "**Malicious** — after-hours, multi-PC, mass file-export pattern. "
        "**Custom** — enter values manually or upload a CSV/JSON log file."
    )

    m_col, btn_col = st.columns([3, 1])
    with m_col:
        mode = st.radio(
            "mode", ["Normal", "Malicious", "Custom"],
            horizontal=True,
            label_visibility="collapsed",
        )
    with btn_col:
        score_clicked = st.button("▶ Score Session", use_container_width=True, type="primary")

# ── custom session input (only when needed) ───────────────────────────────────
custom_features: dict[str, float] = {}

if mode == "Custom":
    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("⚙️ Configure custom session", expanded=True):
        up_col, _ = st.columns([2, 1])
        with up_col:
            uploaded = st.file_uploader(
                "Upload a log file to pre-fill fields (CSV or JSON)",
                type=["csv", "json"],
                help="CSV: one row with column names matching feature keys. JSON: object or list of objects.",
            )
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
                st.success(f"✅ Loaded {len(prefill)} features from **{uploaded.name}**")
            except Exception as e:
                st.error(f"Parse error: {e}")

        defaults = prefill or _sidebar.NORMAL_FEATURES
        st.markdown("**Session feature values** — drag sliders or type a number")
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

# ── score on button click ─────────────────────────────────────────────────────
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

color = _sidebar.DECISION_COLOR.get(r.decision, "#555")
badge = _sidebar.DECISION_BADGE.get(r.decision, r.decision.upper())

st.markdown("<br>", unsafe_allow_html=True)

# ── decision banner ───────────────────────────────────────────────────────────
st.markdown(
    f"<div style='background:{color};color:white;padding:14px 22px;"
    f"border-radius:8px;font-size:20px;font-weight:700;text-align:center;"
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
                    {"range": [0.00, 0.40], "color": "#d4edda"},
                    {"range": [0.40, 0.65], "color": "#fff3cd"},
                    {"range": [0.65, 0.80], "color": "#ffe0b2"},
                    {"range": [0.80, 1.00], "color": "#f8d7da"},
                ],
                "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.7, "value": r.score},
            },
            title={"text": "Risk Score", "font": {"size": 14}},
        ))
        fig_gauge.update_layout(height=240, margin=dict(l=10, r=10, t=30, b=0))
        st.plotly_chart(fig_gauge, use_container_width=True)

with col_thresh:
    st.markdown("**Decision thresholds**")
    for zone, rng, icon in [
        ("Allow",    "< 0.40",      "🟢"),
        ("Throttle", "0.40 – 0.65", "🟡"),
        ("Step-Up",  "0.65 – 0.80", "🟠"),
        ("Deny",     "≥ 0.80",      "🔴"),
    ]:
        active = " ◀" if r.decision.replace("_", " ").lower() in zone.lower() else ""
        st.markdown(f"{icon} **{zone}** — {rng}{active}")

st.markdown("<br>", unsafe_allow_html=True)

# ── SHAP + attack tags ────────────────────────────────────────────────────────
col_shap, col_tags = st.columns([3, 2])

with col_shap:
    st.subheader("SHAP Feature Attribution")
    st.caption("Each bar shows how much a feature pushed the score **up** 🔴 or **down** 🟢.")
    if r.top_factors and PLOTLY:
        factors_sorted = sorted(r.top_factors, key=lambda x: x.contribution)
        labels = [_FEAT_CFG.get(f.feature, {}).get("label", f.feature) for f in factors_sorted]
        values = [f.contribution for f in factors_sorted]
        colors = ["#1a7a1a" if v < 0 else "#a00000" for v in values]

        fig_shap = go.Figure(go.Bar(
            x=values, y=labels, orientation="h",
            marker_color=colors,
            text=[f"{v:+.4f}" for v in values],
            textposition="outside",
        ))
        fig_shap.update_layout(
            height=200, margin=dict(l=10, r=70, t=10, b=10),
            xaxis=dict(title="SHAP contribution", zeroline=True, zerolinecolor="#bbb", zerolinewidth=2),
            plot_bgcolor="#fafafa",
        )
        st.plotly_chart(fig_shap, use_container_width=True)
        for f in sorted(r.top_factors, key=lambda x: abs(x.contribution), reverse=True):
            lbl  = _FEAT_CFG.get(f.feature, {}).get("label", f.feature)
            sign = "▲ raises" if f.contribution > 0 else "▼ lowers"
            st.caption(f"`{lbl}` — {f.contribution:+.4f} ({sign} risk)")
    else:
        st.info("No SHAP data available.")

with col_tags:
    st.subheader("Attack Pattern Tags")
    st.caption("Rule-based checks on raw feature values — named, not inferred by the model.")
    if r.attack_tags:
        for tag in r.attack_tags:
            lbl, clr = _TAG_LABEL.get(tag, (tag, "#555"))
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
        st.success("✅ No attack patterns triggered for this session.")

st.markdown("<br>", unsafe_allow_html=True)

# ── radar + feature table ─────────────────────────────────────────────────────
st.subheader("Session Feature Profile")
st.caption("Radar overlays this session against normal and malicious baselines (values normalised 0–1).")

col_radar, col_table = st.columns([3, 2])

with col_radar:
    if raw and PLOTLY:
        feats       = list(_FEAT_CFG.keys())
        feat_labels = [_FEAT_CFG[f]["label"] for f in feats]
        maxes       = [max(_FEAT_CFG[f]["max"], 1) for f in feats]

        def _norm(d: dict) -> list[float]:
            return [min(d.get(k, 0) / m, 1.0) for k, m in zip(feats, maxes)]

        def _hex_rgba(hex_color: str, alpha: float = 0.09) -> str:
            h = hex_color.lstrip("#")
            r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
            return f"rgba({r},{g},{b},{alpha})"

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
            _trace(_norm(_sidebar.NORMAL_FEATURES), "Normal baseline",    "#1a7a1a", "dot"),
            _trace(_norm(_sidebar.MAL_FEATURES),    "Malicious baseline", "#a00000", "dot"),
            _trace(_norm(raw),                       "This session",       color),
        ])
        fig_r.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 1], tickformat=".0%")),
            showlegend=True, height=380, margin=dict(l=30, r=30, t=30, b=30),
        )
        st.plotly_chart(fig_r, use_container_width=True)

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
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True, height=300)

st.markdown("<br>", unsafe_allow_html=True)

# ── threat taxonomy reference ─────────────────────────────────────────────────
st.subheader("Threat Taxonomy")
st.caption("The four named attack patterns the engine can surface — each triggered by specific feature thresholds, not model inference.")

_TAXONOMY_HTML = """
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px">

  <div style="border-radius:10px;padding:14px;background:#f5eeff;border:1px solid #d4b8f0">
    <div style="font-size:1.3rem">🌙</div>
    <div style="font-weight:700;color:#6a0dad;margin:6px 0 4px;font-size:0.85rem">Off-Hours Activity</div>
    <div style="font-size:0.75rem;color:#555;line-height:1.5">After-hours ratio ≥ 0.30 — user is predominantly active outside business hours. Classic precursor to insider data theft.</div>
  </div>

  <div style="border-radius:10px;padding:14px;background:#fff8ec;border:1px solid #f0d48a">
    <div style="font-size:1.3rem">📍</div>
    <div style="font-weight:700;color:#b36b00;margin:6px 0 4px;font-size:0.85rem">Anomalous Location</div>
    <div style="font-size:0.75rem;color:#555;line-height:1.5">Unique PCs ≥ 2 or USB events ≥ 2 — lateral movement across multiple machines or external storage use.</div>
  </div>

  <div style="border-radius:10px;padding:14px;background:#fff0f0;border:1px solid #f0b8b8">
    <div style="font-size:1.3rem">📤</div>
    <div style="font-weight:700;color:#a00000;margin:6px 0 4px;font-size:0.85rem">Mass Data Export</div>
    <div style="font-size:0.75rem;color:#555;line-height:1.5">File events ≥ 50 in a single session — bulk file movement consistent with exfiltration before departure.</div>
  </div>

  <div style="border-radius:10px;padding:14px;background:#fff0f0;border:1px solid #f0b8b8">
    <div style="font-size:1.3rem">⚡</div>
    <div style="font-weight:700;color:#a00000;margin:6px 0 4px;font-size:0.85rem">Privilege Escalation</div>
    <div style="font-size:0.75rem;color:#555;line-height:1.5">USB events ≥ 2 combined with multi-PC access — pattern consistent with credential harvesting or tool deployment.</div>
  </div>

</div>
"""
st.markdown(_TAXONOMY_HTML, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)
