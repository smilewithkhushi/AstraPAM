"""Cross-channel reconciliation engine — detects privileged financial actions with no matching
ledger entry (the exact PNB LoU failure mode: authorised-looking action, absent CBS record).
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone

_UTC = timezone.utc
_now = lambda: datetime.now(_UTC).replace(tzinfo=None)

import httpx

from schemas import DB_PATH, SEVERITY_PLAYBOOK, LedgerEntry, PrivilegedAction, ReconAlert

CBS_URL = os.getenv("CBS_URL", "http://localhost:8001")


# ── sync ─────────────────────────────────────────────────────────────────────

def sync_from_cbs() -> tuple[int, int]:
    """Pull SWIFT-like actions and ledger entries from mock_cbs into SQLite.

    Returns (swift_rows_added, ledger_rows_added).
    Only inserts; never mutates existing rows (INSERT OR IGNORE).
    """
    swift_actions: list[dict] = httpx.get(f"{CBS_URL}/swift/actions", timeout=5).json()
    ledger_entries: list[dict] = httpx.get(f"{CBS_URL}/ledger", timeout=5).json()

    con = sqlite3.connect(DB_PATH)

    sw = 0
    for a in swift_actions:
        cur = con.execute(
            "INSERT OR IGNORE INTO privileged_actions"
            " (action_id, user_id, channel, amount, timestamp) VALUES (?,?,?,?,?)",
            (a["action_id"], a["user_id"], a["channel"], a["amount"], a["timestamp"]),
        )
        sw += cur.rowcount

    le = 0
    for e in ledger_entries:
        cur = con.execute(
            "INSERT OR IGNORE INTO ledger_entries"
            " (entry_id, action_id, amount, timestamp) VALUES (?,?,?,?)",
            (e["entry_id"], e.get("action_id"), e["amount"], e["timestamp"]),
        )
        le += cur.rowcount

    con.commit()
    con.close()
    return sw, le


# ── core reconciliation ───────────────────────────────────────────────────────

def _unmatched(con: sqlite3.Connection, sla_seconds: int) -> list[dict]:
    """Financial privileged actions past the SLA window that have no ledger entry
    and have not already triggered an alert.
    """
    cutoff = (_now() - timedelta(seconds=sla_seconds)).isoformat()
    rows = con.execute(
        """
        SELECT pa.action_id, pa.user_id, pa.channel, pa.amount, pa.timestamp
        FROM   privileged_actions pa
        WHERE  pa.amount IS NOT NULL
          AND  pa.timestamp <= :cutoff
          AND  pa.action_id NOT IN (
                   SELECT action_id FROM ledger_entries WHERE action_id IS NOT NULL
               )
          AND  pa.action_id NOT IN (SELECT action_id FROM recon_alerts)
        """,
        {"cutoff": cutoff},
    ).fetchall()
    cols = ("action_id", "user_id", "channel", "amount", "timestamp")
    return [dict(zip(cols, r)) for r in rows]


def _severity(channel: str) -> tuple[str, str]:
    # swift_like with no ledger entry = the PNB pattern → critical
    key = "critical" if channel == "swift_like" else "high"
    return key, SEVERITY_PLAYBOOK[key]


def run(sla_seconds: int = 30) -> list[ReconAlert]:
    """Reconcile and persist new alerts. Returns only the alerts raised this run."""
    con = sqlite3.connect(DB_PATH)
    unmatched = _unmatched(con, sla_seconds)
    now = _now()
    alerts: list[ReconAlert] = []

    for row in unmatched:
        severity, recommended_action = _severity(row["channel"])
        alert = ReconAlert(
            action_id=row["action_id"],
            reason=(
                f"No ledger entry for {row['channel']} financial action "
                f"(amount={row['amount']}) after {sla_seconds}s SLA."
            ),
            severity=severity,
            recommended_action=recommended_action,
            detected_at=now,
        )
        con.execute(
            """INSERT OR IGNORE INTO recon_alerts
               (action_id, reason, severity, recommended_action, detected_at)
               VALUES (?,?,?,?,?)""",
            (
                alert.action_id,
                alert.reason,
                alert.severity,
                alert.recommended_action,
                alert.detected_at.isoformat(),
            ),
        )
        alerts.append(alert)

    con.commit()
    con.close()
    return alerts


# ── queries ───────────────────────────────────────────────────────────────────

def get_all_alerts() -> list[ReconAlert]:
    """All persisted alerts, most recent first."""
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT action_id, reason, severity, recommended_action, detected_at"
        " FROM recon_alerts ORDER BY detected_at DESC"
    ).fetchall()
    con.close()
    return [
        ReconAlert(
            action_id=r[0],
            reason=r[1],
            severity=r[2],
            recommended_action=r[3],
            detected_at=datetime.fromisoformat(r[4]),
        )
        for r in rows
    ]
