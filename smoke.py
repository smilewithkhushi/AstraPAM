#!/usr/bin/env python3
"""AegisPAM end-to-end smoke test.

Spins up mock_cbs (:8001) and the control API (:8000) as subprocesses using a
throwaway database (database/aegispam_smoke.db), runs every phase acceptance
criterion, then tears everything down cleanly.

Exit 0 = all assertions pass.
Exit 1 = at least one assertion failed.

Usage:
    python smoke.py          # from project root with .venv active
"""
from __future__ import annotations

import os
import pathlib
import sqlite3
import subprocess
import sys
import time

import httpx

# ── output helpers ────────────────────────────────────────────────────────────

PASS = "\033[32m PASS\033[0m"
FAIL = "\033[31m FAIL\033[0m"
HEAD = "\033[1m\033[34m"
RST  = "\033[0m"

_failures: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"{PASS}  {label}")
    else:
        msg = f"  ({detail})" if detail else ""
        print(f"{FAIL}  {label}{msg}")
        _failures.append(label)


def wait_healthy(url: str, timeout: int = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=2).json().get("ok"):
                return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


# ── service lifecycle ─────────────────────────────────────────────────────────

SMOKE_DB = "database/aegispam_smoke.db"
CBS_URL  = "http://127.0.0.1:8001"
API_URL  = "http://127.0.0.1:8000"

_env    = {**os.environ, "AEGISPAM_DB": SMOKE_DB, "CBS_URL": CBS_URL}
_procs: list[subprocess.Popen] = []


def start_services() -> bool:
    pathlib.Path("database").mkdir(exist_ok=True)
    # clean slate
    pathlib.Path(SMOKE_DB).unlink(missing_ok=True)

    cbs = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "mock_cbs:app",
         "--host", "127.0.0.1", "--port", "8001", "--log-level", "error"],
        env=_env,
    )
    api = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app",
         "--host", "127.0.0.1", "--port", "8000", "--log-level", "error"],
        env=_env,
    )
    _procs.extend([cbs, api])
    return (wait_healthy(f"{CBS_URL}/health") and
            wait_healthy(f"{API_URL}/health"))


def stop_services() -> None:
    for p in _procs:
        p.terminate()
    for p in _procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    pathlib.Path(SMOKE_DB).unlink(missing_ok=True)


# ── test phases ───────────────────────────────────────────────────────────────

def test_phase0_foundation() -> None:
    print(f"\n{HEAD}Phase 0 — Foundation{RST}")
    check("mock_cbs /health", httpx.get(f"{CBS_URL}/health").json().get("ok") is True)
    check("control API /health", httpx.get(f"{API_URL}/health").json().get("ok") is True)

    con = sqlite3.connect(SMOKE_DB)
    tables = {r[0] for r in
              con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    con.close()
    for t in ("ephemeral_grants", "privileged_actions", "ledger_entries",
              "recon_alerts", "audit_records"):
        check(f"table exists: {t}", t in tables)


def test_phase1_reconciliation() -> None:
    print(f"\n{HEAD}Phase 1 — Reconciliation (the PNB fix){RST}")

    # out-of-band SWIFT action — no ledger entry is ever created
    r = httpx.post(f"{CBS_URL}/swift/action",
                   json={"user_id": "rogue", "amount": 14000.0,
                         "description": "Fake LoU"}).json()
    action_id = r.get("action_id", "")
    check("SWIFT action issued (out-of-band)", bool(action_id))

    # SLA=0 makes the brand-new action immediately past deadline
    r2 = httpx.post(f"{API_URL}/reconcile/run?sla_seconds=0").json()
    alerts = r2.get("new_alerts", [])
    check("reconciliation fires ≥1 new alert", len(alerts) >= 1)

    critical = [a for a in alerts if a.get("severity") == "critical"]
    check("SWIFT-like action → critical severity", len(critical) >= 1, str(alerts))
    check("critical alert has recommended_action string",
          any(a.get("recommended_action") for a in critical))


def test_phase2_risk() -> None:
    print(f"\n{HEAD}Phase 2 — Behavioral risk AI + SHAP + attack tags{RST}")

    normal = httpx.post(f"{API_URL}/access/request", json={
        "user_id": "alice", "target": "core_banking", "action_type": "read",
        "features": {
            "logon_count": 5.0, "after_hours": 0.0, "unique_pcs": 1.0,
            "device_events": 0.0, "file_events": 12.0,
            "http_events": 60.0, "email_events": 10.0,
        },
    }).json()
    check("normal session → granted (allow/throttle)",
          normal.get("status") in ("granted", "granted_throttled"),
          str(normal.get("status")))

    mal = httpx.post(f"{API_URL}/access/request", json={
        "user_id": "rogue", "target": "core_banking", "action_type": "financial",
        "features": {
            "logon_count": 1.0, "after_hours": 0.9, "unique_pcs": 4.0,
            "device_events": 8.0, "file_events": 150.0,
            "http_events": 2.0, "email_events": 0.0,
        },
    }).json()
    check("malicious session → denied or step_up",
          mal.get("status") in ("denied", "step_up_required"),
          str(mal.get("status")))

    risk_block = mal.get("risk") or {}
    tags    = risk_block.get("attack_tags") or mal.get("attack_tags") or []
    factors = risk_block.get("top_factors") or mal.get("top_factors") or []
    check("malicious session carries ≥1 attack tag",  len(tags) >= 1,    str(tags))
    check("risk result has SHAP top_factors",          len(factors) >= 1)

    if normal.get("risk") and mal.get("risk"):
        ns, ms = normal["risk"]["score"], mal["risk"]["score"]
        check("normal score < malicious score", ns < ms,
              f"normal={ns:.3f} mal={ms:.3f}")


def test_phase3_broker() -> None:
    print(f"\n{HEAD}Phase 3 — JIT broker + graduated decision{RST}")

    r = httpx.post(f"{API_URL}/access/request", json={
        "user_id": "bob", "target": "payments", "action_type": "financial",
        "features": {
            "logon_count": 4.0, "after_hours": 0.0, "unique_pcs": 1.0,
            "device_events": 0.0, "file_events": 10.0,
            "http_events": 50.0, "email_events": 8.0,
        },
    }).json()
    check("low-risk financial request → granted",
          r.get("status") in ("granted", "granted_throttled"),
          str(r.get("status")))

    # grant_id from grant, check TTL field present
    grant = r.get("grant", {})
    check("grant has grant_id",   bool(grant.get("grant_id")))
    check("grant has expires_at", bool(grant.get("expires_at")))

    grants = httpx.get(f"{API_URL}/access/grants").json()
    check("active grants endpoint returns list", isinstance(grants, list))

    expire_r = httpx.post(f"{API_URL}/access/expire").json()
    check("expire endpoint returns expired list", "expired" in expire_r)


def test_phase4_crypto() -> None:
    print(f"\n{HEAD}Phase 4 — PQC credential + ML-DSA-65 audit chain{RST}")

    r = httpx.post(f"{API_URL}/crypto/credential/grant-smoke?user_id=demo").json()
    check("credential endpoint responds",        "pubkey_bytes" in r, str(r))
    check("ML-KEM-768 pubkey  = 1184 B",         r.get("pubkey_bytes")      == 1184)
    check("ML-KEM-768 ciphertext = 1088 B",      r.get("ciphertext_bytes")  == 1088)
    check("shared secret = 32 B",                r.get("shared_secret_bytes") == 32)
    check("algorithm string mentions ML-KEM-768","ML-KEM-768" in r.get("algorithm", ""))

    v = httpx.get(f"{API_URL}/crypto/verify").json()
    check("audit chain valid after credential issue", v.get("valid") is True,
          str(v))
    check("audit chain has ≥1 record", v.get("length", 0) >= 1)

    # tamper directly in the smoke DB then verify chain detects it
    con = sqlite3.connect(SMOKE_DB)
    rows = con.execute("SELECT seq FROM audit_records LIMIT 1").fetchall()
    if rows:
        con.execute("UPDATE audit_records SET payload='[TAMPERED]' WHERE seq=1")
        con.commit()
    con.close()

    v2 = httpx.get(f"{API_URL}/crypto/verify").json()
    check("tampered chain → valid=False",          v2.get("valid") is False)
    check("first_bad_seq points to tampered record", v2.get("first_bad_seq") == 1)


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print(f"\n{HEAD}AegisPAM — end-to-end smoke test{RST}")
    print("Starting services…")

    if not start_services():
        print(f"{FAIL}  services failed to come up — check that ports 8000/8001 are free")
        stop_services()
        sys.exit(1)

    print("Services healthy.\n")

    try:
        test_phase0_foundation()
        test_phase1_reconciliation()
        test_phase2_risk()
        test_phase3_broker()
        test_phase4_crypto()
    finally:
        print("\nStopping services…")
        stop_services()

    print()
    if _failures:
        print(f"\033[31mFAILED — {len(_failures)} assertion(s):\033[0m")
        for f in _failures:
            print(f"  • {f}")
        sys.exit(1)
    else:
        print(f"\033[32mALL PASS\033[0m")
        sys.exit(0)


if __name__ == "__main__":
    main()
