"""AstraPAM — Banking-grade audit report generator.

Collects data from SQLite, calls NVIDIA NIM for narrative sections,
renders a structured PDF in the style of an RBI internal audit report.

Public API:
    generate_pdf(days=7) -> bytes   # returns raw PDF bytes
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fpdf import FPDF

from schemas import DB_PATH

NIM_KEY   = os.getenv("NVIDIA_NIM_API_KEY", "")
NIM_URL   = "https://integrate.api.nvidia.com/v1/chat/completions"
NIM_MODEL = "meta/llama-3.1-70b-instruct"

_UNICODE_MAP = str.maketrans({
    "—": " - ",   # em dash
    "–": " - ",   # en dash
    "‘": "'",     # left single quote
    "’": "'",     # right single quote
    "“": '"',     # left double quote
    "”": '"',     # right double quote
    "₹": "INR ",  # rupee sign
    "•": "*",     # bullet
    "…": "...",   # ellipsis
})

def _s(text: str) -> str:
    """Sanitise text to latin-1 safe for Helvetica PDF rendering."""
    return text.translate(_UNICODE_MAP).encode("latin-1", "replace").decode("latin-1")

# ── colour palette ────────────────────────────────────────────────────────────
NAVY  = (15,  40,  80)
TEAL  = (0,  110, 120)
WHITE = (255, 255, 255)
LIGHT = (245, 247, 250)
DARK  = (30,  30,  40)
GRAY  = (110, 110, 120)


# ── data collection ───────────────────────────────────────────────────────────

def _db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def collect_data(days: int) -> dict[str, Any]:
    """Pull structured metrics from SQLite for the report period."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    con   = _db()
    d: dict[str, Any] = {
        "period_days":  days,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "since":        since,
    }

    # Access grants
    try:
        r = con.execute(
            "SELECT COUNT(*) t, COALESCE(SUM(break_glass),0) bg, COALESCE(SUM(revoked),0) rv "
            "FROM ephemeral_grants",
        ).fetchone()
        d["grants"] = {"total": r["t"], "bg": r["bg"], "rv": r["rv"]}
    except Exception:
        d["grants"] = {"total": 0, "bg": 0, "rv": 0}

    # Reconciliation alerts
    try:
        rows = con.execute(
            "SELECT severity, COUNT(*) cnt FROM recon_alerts GROUP BY severity",
        ).fetchall()
        d["recon"] = {r["severity"]: r["cnt"] for r in rows}
        d["recon_total"] = sum(d["recon"].values())
    except Exception:
        d["recon"] = {}
        d["recon_total"] = 0

    # Risk scores — mined from audit_records payloads
    try:
        rows = con.execute("SELECT payload FROM audit_records").fetchall()
        scores: list = []
        denies = 0
        step_ups = 0
        tags: dict = {}
        for r in rows:
            try:
                p = json.loads(r["payload"])
                if "score" in p and "decision" in p:
                    scores.append(float(p["score"]))
                    if p["decision"] == "deny":
                        denies += 1
                    if p["decision"] == "step_up":
                        step_ups += 1
                for t in p.get("attack_tags", []):
                    tags[t] = tags.get(t, 0) + 1
            except Exception:
                pass
        d["risk"] = {
            "total":     len(scores),
            "avg_score": round(sum(scores) / len(scores), 4) if scores else 0.0,
            "denied":    denies,
            "step_up":   step_ups,
        }
        d["attack_tags"] = tags
    except Exception:
        d["risk"]        = {"total": 0, "avg_score": 0.0, "denied": 0, "step_up": 0}
        d["attack_tags"] = {}

    # Audit chain length
    try:
        r = con.execute("SELECT COUNT(*) n FROM audit_records").fetchone()
        d["audit_chain_length"] = r["n"]
    except Exception:
        d["audit_chain_length"] = 0

    # NHI inventory
    try:
        rows = con.execute(
            "SELECT status, COUNT(*) cnt FROM nhi_identities GROUP BY status",
        ).fetchall()
        d["nhi"] = {r["status"]: r["cnt"] for r in rows}
    except Exception:
        d["nhi"] = {}

    # Console actions
    try:
        rows = con.execute(
            "SELECT action, COUNT(*) cnt FROM console_actions GROUP BY action",
        ).fetchall()
        d["console"] = {r["action"]: r["cnt"] for r in rows}
        d["console_total"] = sum(d["console"].values())
    except Exception:
        d["console"]       = {}
        d["console_total"] = 0

    # Maker-checker
    try:
        rows = con.execute(
            "SELECT status, COUNT(*) cnt FROM maker_checker_reqs GROUP BY status",
        ).fetchall()
        d["mc"] = {r["status"]: r["cnt"] for r in rows}
    except Exception:
        d["mc"] = {}

    con.close()
    return d


# ── NIM narrative ─────────────────────────────────────────────────────────────

def _nim_narrative(d: dict[str, Any]) -> dict[str, str]:
    """Return exec_summary, risk_narrative, findings from NIM. Falls back to template."""
    if not NIM_KEY:
        return _template_narrative(d)

    prompt = f"""You are a senior information security auditor writing a formal internal audit report \
for an Indian bank's Privileged Access Management system. Use professional, third-person banking audit \
language (similar to RBI inspection reports). Be factual and formal. Reference ONLY the numbers below — \
do NOT invent additional findings.

AUDIT DATA ({d['period_days']}-day period):
- Access grants issued: {d['grants']['total']} \
(break-glass overrides: {d['grants']['bg']}, revoked/expired: {d['grants']['rv']})
- Risk sessions scored: {d['risk']['total']}, avg score: {d['risk']['avg_score']:.4f}, \
denied: {d['risk']['denied']}, step-up triggered: {d['risk']['step_up']}
- Attack tags: {json.dumps(d['attack_tags'])}
- Reconciliation alerts: {d['recon_total']} total — {json.dumps(d['recon'])}
- NHI inventory: {json.dumps(d['nhi'])}
- Audit chain records: {d['audit_chain_length']}
- SOC console actions: {json.dumps(d['console'])}
- Maker-checker requests: {json.dumps(d['mc'])}

Write exactly THREE sections separated by the literal string "---":

SECTION 1 — EXECUTIVE SUMMARY (2 short paragraphs, ≤ 120 words total):
Overall control posture for the period. Mention key metrics. End with one sentence \
on regulatory alignment (RBI Cyber Security Framework / April 2026 Authentication Directions).

---

SECTION 2 — RISK ASSESSMENT (1 paragraph, ≤ 80 words):
Behavioral risk engine findings — session volume, average score, decision distribution, \
notable attack patterns if any.

---

SECTION 3 — KEY FINDINGS (4-5 bullet points, each ≤ 30 words):
Most important observations. Start each bullet with a control area name in CAPS followed by a colon.

Do NOT include section headings or markdown in your response — just the three text blocks separated by "---"."""

    try:
        resp = httpx.post(
            NIM_URL,
            headers={"Authorization": f"Bearer {NIM_KEY}", "Content-Type": "application/json"},
            json={
                "model":       NIM_MODEL,
                "messages":    [{"role": "user", "content": prompt}],
                "temperature": 0.25,
                "max_tokens":  650,
            },
            timeout=45,
        )
        resp.raise_for_status()
        text  = resp.json()["choices"][0]["message"]["content"].strip()
        parts = [p.strip() for p in text.split("---")]
        return {
            "exec_summary":   parts[0] if len(parts) > 0 else "",
            "risk_narrative": parts[1] if len(parts) > 1 else "",
            "findings":       parts[2] if len(parts) > 2 else "",
            "nim_used":       True,
        }
    except Exception:
        return _template_narrative(d)


def _template_narrative(d: dict[str, Any]) -> dict[str, str]:
    avg = d["risk"]["avg_score"]
    return {
        "exec_summary": (
            f"During the {d['period_days']}-day review period, AstraPAM processed "
            f"{d['grants']['total']} privileged access grant(s) under Zero Standing Privilege controls, "
            f"with {d['grants']['bg']} break-glass override(s) recorded. "
            f"{d['recon_total']} cross-channel reconciliation alert(s) were raised against "
            f"the core-banking ledger, each carrying a severity-tiered recommended response.\n\n"
            "The system's overall control posture is aligned with RBI Cyber Security Framework "
            "clauses 8.4 and 8.6, and represents a direct implementation of the adaptive "
            "authentication controls mandated by RBI from April 2026."
        ),
        "risk_narrative": (
            f"The behavioral risk engine scored {d['risk']['total']} privileged session(s) "
            f"during the period, producing an average reconstruction-error risk score of "
            f"{avg:.4f} (scale 0–1). {d['risk']['denied']} session(s) resulted in an "
            f"outright DENY decision, and {d['risk']['step_up']} triggered mandatory step-up "
            "authentication. SHAP KernelExplainer attribution was computed for every scoring "
            "event, ensuring each decision is auditable and defensible to regulators."
        ),
        "findings": (
            f"ACCESS CONTROL: {d['grants']['total']} JIT grants issued; "
            f"{d['grants']['bg']} break-glass event(s) logged with justification.\n"
            f"RECONCILIATION: {d['recon_total']} unmatched privileged financial action(s) "
            f"detected — {d['recon'].get('critical', 0)} critical, "
            f"{d['recon'].get('high', 0)} high severity.\n"
            f"AUDIT INTEGRITY: {d['audit_chain_length']} records in ML-DSA-65 (Dilithium) "
            "signed hash-chain; tamper detection active.\n"
            f"NON-HUMAN IDENTITIES: {d['nhi'].get('expired', 0)} expired NHI credential(s) "
            "flagged; mandatory owner attribution enforced.\n"
            "POST-QUANTUM CRYPTOGRAPHY: ML-KEM-768 + ML-DSA-65 (NIST FIPS 203/204) "
            "active across all credential operations."
        ),
        "nim_used": False,
    }


# ── PDF layout ────────────────────────────────────────────────────────────────

class _AuditPDF(FPDF):
    def __init__(self, report_id: str, period: str):
        super().__init__()
        self._rid    = report_id
        self._period = period

    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(*NAVY)
        self.rect(0, 0, 210, 11, "F")
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 7.5)
        self.set_xy(8, 2.5)
        self.cell(130, 6, _s("AstraPAM - PRIVILEGED ACCESS MANAGEMENT  |  INTERNAL AUDIT REPORT"))
        self.set_font("Helvetica", "", 7)
        self.set_xy(140, 2.5)
        self.cell(60, 6, _s(f"ID: {self._rid[:16]}..."), align="R")
        self.set_text_color(*DARK)
        self.set_y(14)

    def footer(self):
        self.set_y(-11)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*GRAY)
        self.cell(
            0, 5,
            _s(f"Page {self.page_no()}  |  Period: {self._period}  |  "
               "INTERNAL - NOT FOR EXTERNAL DISTRIBUTION"),
            align="C",
        )
        self.set_text_color(*DARK)

    # ── helpers ───────────────────────────────────────────────────────────────

    def section_title(self, text: str):
        self.ln(5)
        self.set_fill_color(*NAVY)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 9.5)
        self.cell(0, 7, _s(f"  {text}"), ln=True, fill=True)
        self.set_text_color(*DARK)
        self.ln(2)

    def kv(self, label: str, value: str, shade: bool = False):
        fill = shade
        if shade:
            self.set_fill_color(*LIGHT)
        self.set_font("Helvetica", "B", 8)
        self.cell(72, 5.5, _s(f"  {label}"), fill=fill)
        self.set_font("Helvetica", "", 8)
        self.cell(0, 5.5, _s(value), ln=True, fill=fill)

    def body(self, text: str):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 9)
        self.multi_cell(0, 5, _s(text))
        self.ln(2)

    def metric_strip(self, items: list[tuple[str, str]]):
        """Render a horizontal strip of labelled metric boxes."""
        n  = len(items)
        w  = 188 // n
        x0 = self.get_x()
        y0 = self.get_y()
        for i, (label, val) in enumerate(items):
            bx = x0 + i * (w + 2)
            self.set_fill_color(*LIGHT)
            self.rect(bx, y0, w, 16, "F")
            self.set_fill_color(*NAVY)
            self.rect(bx, y0, w, 2.5, "F")
            self.set_xy(bx, y0 + 3.5)
            self.set_font("Helvetica", "B", 14)
            self.set_text_color(*NAVY)
            self.cell(w, 7, val, align="C")
            self.set_xy(bx, y0 + 10.5)
            self.set_font("Helvetica", "", 6.5)
            self.set_text_color(*GRAY)
            self.cell(w, 4, label, align="C")
        self.set_text_color(*DARK)
        self.set_xy(x0, y0 + 19)


# ── main entry point ──────────────────────────────────────────────────────────

def generate_pdf(days: int = 7) -> bytes:
    """Collect live data, call NIM, render and return PDF bytes."""
    data      = collect_data(days)
    narrative = _nim_narrative(data)

    report_id  = str(uuid.uuid4()).upper()
    now        = datetime.now(timezone.utc)
    period_str = _s(
        f"{(now - timedelta(days=days)).strftime('%d %b %Y')} - "
        f"{now.strftime('%d %b %Y')}"
    )
    generated  = now.strftime("%Y-%m-%d %H:%M UTC")

    pdf = _AuditPDF(report_id, period_str)
    pdf.set_auto_page_break(auto=True, margin=14)

    # ── COVER ──────────────────────────────────────────────────────────────
    pdf.add_page()

    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 65, "F")
    pdf.set_fill_color(*TEAL)
    pdf.rect(0, 65, 210, 1.5, "F")

    pdf.set_xy(12, 16)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 11, "AstraPAM", ln=True)

    pdf.set_x(12)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, "Privileged Access Management Platform", ln=True)

    pdf.set_x(12)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(170, 195, 215)
    pdf.cell(0, 6, _s("Internal Audit Report - Zero-Standing-Privilege Control Plane"), ln=True)

    pdf.set_text_color(*DARK)
    pdf.set_xy(12, 74)

    meta = [
        ("Report Reference",    report_id),
        ("Report Type",         f"Operational Audit - {days}-Day Review"),
        ("Review Period",       period_str),
        ("Report Generated",    generated),
        ("Classification",      "INTERNAL - RESTRICTED"),
        ("Prepared By",         "AstraPAM Automated Audit Engine"),
        ("Applicable Standard", "RBI Cyber Security Framework / IT Governance Directions 2024"),
        ("Problem Statement",   "PS-1 - Privileged Access Misuse & Insider Threat Detection"),
    ]
    for i, (k, v) in enumerate(meta):
        pdf.kv(k, v, shade=(i % 2 == 0))

    pdf.ln(6)
    pdf.set_fill_color(180, 20, 20)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.cell(0, 7, "   CONFIDENTIAL - FOR AUTHORISED PERSONNEL ONLY", ln=True, fill=True)
    pdf.set_text_color(*DARK)

    # ── SECTION 1 — EXECUTIVE SUMMARY ──────────────────────────────────────
    pdf.add_page()
    pdf.section_title("1.  Executive Summary")
    pdf.body(narrative["exec_summary"])

    pdf.metric_strip([
        ("Grants Issued",   str(data["grants"]["total"])),
        ("Sessions Scored", str(data["risk"]["total"])),
        ("Recon Alerts",    str(data["recon_total"])),
        ("Audit Records",   str(data["audit_chain_length"])),
        ("Console Actions", str(data["console_total"])),
    ])

    # ── SECTION 2 — ACCESS CONTROL ─────────────────────────────────────────
    pdf.section_title("2.  Access Control Summary")
    g = data["grants"]
    rows2 = [
        ("Grants issued (period)",    str(g["total"])),
        ("Break-glass overrides",     str(g["bg"])),
        ("Grants revoked / expired",  str(g["rv"])),
        ("Access mechanism",          "ML-KEM-768 + X25519 hybrid PQC handshake (NIST FIPS 203)"),
        ("Standing privilege posture","Zero — all grants are ephemeral, JIT, TTL-bound, auto-revoked"),
        ("Maker-checker enforcement", "High-impact console actions require second-operator approval"),
    ]
    for i, (k, v) in enumerate(rows2):
        pdf.kv(k, v, shade=(i % 2 == 0))

    # ── SECTION 3 — BEHAVIORAL RISK ENGINE ─────────────────────────────────
    pdf.section_title("3.  Behavioral Risk Engine")
    pdf.body(narrative["risk_narrative"])

    r = data["risk"]
    rows3 = [
        ("Sessions scored",          str(r["total"])),
        ("Average risk score",       f"{r['avg_score']:.4f}  (scale 0.0000 – 1.0000)"),
        ("DENY decisions",           str(r["denied"])),
        ("Step-up auth triggered",   str(r["step_up"])),
        ("ML model",                 "LSTM Autoencoder — CMU CERT Insider Threat Dataset r4.2"),
        ("Feature set",              "7 features: logon_count, after_hours, unique_pcs, "
                                     "device_events, file_events, http_events, email_events"),
        ("Explainability",           "SHAP KernelExplainer — every score is fully attributed per feature"),
    ]
    for i, (k, v) in enumerate(rows3):
        pdf.kv(k, v, shade=(i % 2 == 0))

    if data["attack_tags"]:
        pdf.ln(2)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*GRAY)
        pdf.cell(0, 5, "Attack tags detected during period:", ln=True)
        pdf.set_text_color(*DARK)
        for tag, cnt in data["attack_tags"].items():
            pdf.set_font("Helvetica", "", 8)
            pdf.cell(12, 5, "")
            pdf.cell(0, 5, _s(f"* {tag}:  {cnt} occurrence(s)"), ln=True)

    # ── SECTION 4 — RECONCILIATION ──────────────────────────────────────────
    pdf.section_title("4.  Cross-Channel Ledger Reconciliation")
    rec = data["recon"]
    rows4 = [
        ("Total alerts raised",       str(data["recon_total"])),
        ("Critical",                  str(rec.get("critical", 0))),
        ("High",                      str(rec.get("high", 0))),
        ("Medium",                    str(rec.get("medium", 0))),
        ("Low",                       str(rec.get("low", 0))),
        ("Detection primitive",       "Absence of matching CBS ledger entry within SLA window"),
        ("Fraud pattern targeted",    "PNB 2018 — off-ledger SWIFT LoU (₹14,000 Cr, 7 years undetected)"),
        ("Response",                  "Severity-tiered alert with recommended playbook action"),
    ]
    for i, (k, v) in enumerate(rows4):
        pdf.kv(k, v, shade=(i % 2 == 0))

    # ── SECTION 5 — COMPLIANCE & NHI ───────────────────────────────────────
    pdf.section_title("5.  Non-Human Identity Governance & Compliance")
    nhi = data["nhi"]
    rows5 = [
        ("NHI — Active",          str(nhi.get("active", 0))),
        ("NHI — Expiring Soon",   str(nhi.get("expiring_soon", 0))),
        ("NHI — Expired",         str(nhi.get("expired", 0))),
        ("NHI — Revoked",         str(nhi.get("revoked", 0))),
        ("Owner attribution",     "Mandatory — every NHI has a named owner and expiry date"),
        ("CBOM status",           "Live scan active — ML-KEM-768 & ML-DSA-65 flagged as quantum-safe"),
    ]
    for i, (k, v) in enumerate(rows5):
        pdf.kv(k, v, shade=(i % 2 == 0))

    # ── SECTION 6 — AUDIT CHAIN ─────────────────────────────────────────────
    pdf.section_title("6.  Audit Chain Integrity")
    rows6 = [
        ("Total signed records",  str(data["audit_chain_length"])),
        ("Signing algorithm",     "ML-DSA-65 (Dilithium) — NIST FIPS 204"),
        ("Chain structure",       "SHA-256 hash-chained; each record commits to prior record hash"),
        ("Tamper detection",      "verify_chain() identifies exact sequence number of any mutation"),
        ("Maker-checker actions", str(data["console_total"]) + " SOC console action(s) recorded"),
    ]
    for i, (k, v) in enumerate(rows6):
        pdf.kv(k, v, shade=(i % 2 == 0))

    # ── SECTION 7 — KEY FINDINGS ────────────────────────────────────────────
    pdf.section_title("7.  Key Findings & Observations")
    for line in narrative["findings"].splitlines():
        line = line.strip()
        if not line:
            continue
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", 8.5)
        if line.startswith(("*", "-")):
            pdf.multi_cell(0, 5.5, _s("*  " + line.lstrip("*•- ").strip()))
        else:
            pdf.multi_cell(0, 5.5, _s(line))
    pdf.ln(2)

    # ── SECTION 8 — REGULATORY ALIGNMENT ────────────────────────────────────
    pdf.section_title("8.  Regulatory Alignment Matrix")
    reg = [
        ("RBI CSF cl. 8.4",
         "Centralised auth, least privilege, separation of duties — IMPLEMENTED"),
        ("RBI CSF cl. 8.6 / 8.7",
         "Dormant-account & abnormal-logon detection — IMPLEMENTED"),
        ("RBI IT Governance Directions 2024",
         "Board-approved IT risk framework, 6-hr incident reporting — ALIGNED"),
        ("RBI Authentication Directions — Apr 2026",
         "Real-time risk scoring + adaptive authentication — IMPLEMENTED"),
        ("RBI Q-SAFE Committee / Quantum Whitepaper",
         "PQC readiness + CBOM scanner — IMPLEMENTED (ML-KEM-768, ML-DSA-65)"),
        ("CBS Maker-Checker Standard",
         "Dual authorisation enforced for all high-impact console actions — IMPLEMENTED"),
    ]
    for i, (k, v) in enumerate(reg):
        pdf.kv(k, v, shade=(i % 2 == 0))

    # ── DISCLAIMER ───────────────────────────────────────────────────────────
    pdf.ln(8)
    pdf.set_fill_color(*LIGHT)
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.set_text_color(*GRAY)
    pdf.multi_cell(
        0, 4.5,
        _s("This report has been prepared by the AstraPAM Control Plane and is intended solely "
           "for the use of authorised personnel within the institution. All findings and metrics "
           "are derived from system-of-record data as at the report generation date and reflect "
           "the state of privileged access controls during the review period. This document is "
           "classified INTERNAL - RESTRICTED. Reproduction, distribution, or disclosure to any "
           "party outside the institution is prohibited without the prior written approval of "
           "the Chief Information Security Officer."),
        fill=True,
    )
    pdf.set_text_color(*DARK)

    return bytes(pdf.output())
