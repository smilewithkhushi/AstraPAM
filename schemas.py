from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from typing import Literal

from pydantic import BaseModel

DB_PATH = os.getenv("AEGISPAM_DB", "database/aegispam.db")

Decision = Literal["allow", "throttle", "step_up", "deny"]
Severity = Literal["critical", "high", "medium", "low"]
Channel = Literal["cbs", "swift_like"]
ActionType = Literal["read", "admin", "financial"]
AttackTag = Literal[
    "OFF_HOURS_ACTIVITY",
    "ANOMALOUS_LOCATION",
    "MASS_DATA_EXPORT",
    "PRIVILEGE_ESCALATION",
]

SEVERITY_PLAYBOOK: dict[str, str] = {
    "critical": "Isolate session, notify security team immediately, preserve audit log.",
    "high": "Suspend grant, escalate to SOC, request manual review.",
    "medium": "Flag for next-business-hour review, increase monitoring frequency.",
    "low": "Log for weekly compliance review.",
}


class AccessRequest(BaseModel):
    user_id: str
    target: str
    action_type: ActionType
    requested_at: datetime


class RiskFactor(BaseModel):
    feature: str
    contribution: float


class RiskResult(BaseModel):
    score: float  # 0–1
    decision: Decision
    top_factors: list[RiskFactor]
    attack_tags: list[AttackTag]


class EphemeralGrant(BaseModel):
    grant_id: str
    user_id: str
    target: str
    expires_at: datetime
    revoked: bool
    rate_cap: float | None = None  # non-null when decision is throttle


class PrivilegedAction(BaseModel):
    action_id: str
    user_id: str
    channel: Channel
    amount: float | None = None
    timestamp: datetime


class LedgerEntry(BaseModel):
    entry_id: str
    action_id: str | None = None  # null = the PNB red-flag
    amount: float
    timestamp: datetime


class ReconAlert(BaseModel):
    action_id: str
    reason: str
    severity: Severity
    recommended_action: str
    detected_at: datetime


class AuditRecord(BaseModel):
    seq: int
    prev_hash: str
    payload: str
    signature: str
    hash: str


class CryptoArtifact(BaseModel):
    """Display-only: byte counts from a real KEM call prove PQC is not mocked."""
    pubkey_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    algorithm: str  # "ML-KEM-768"


def init_db() -> None:
    parent = os.path.dirname(DB_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS ephemeral_grants (
            grant_id            TEXT PRIMARY KEY,
            user_id             TEXT NOT NULL,
            target              TEXT NOT NULL,
            expires_at          TEXT NOT NULL,
            revoked             INTEGER NOT NULL DEFAULT 0,
            rate_cap            REAL
        );
        CREATE TABLE IF NOT EXISTS privileged_actions (
            action_id           TEXT PRIMARY KEY,
            user_id             TEXT NOT NULL,
            channel             TEXT NOT NULL,
            amount              REAL,
            timestamp           TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ledger_entries (
            entry_id            TEXT PRIMARY KEY,
            action_id           TEXT,
            amount              REAL NOT NULL,
            timestamp           TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recon_alerts (
            action_id           TEXT PRIMARY KEY,
            reason              TEXT NOT NULL,
            severity            TEXT NOT NULL,
            recommended_action  TEXT NOT NULL,
            detected_at         TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_records (
            seq                 INTEGER PRIMARY KEY,
            prev_hash           TEXT NOT NULL,
            payload             TEXT NOT NULL,
            signature           TEXT NOT NULL,
            hash                TEXT NOT NULL
        );
    """)
    con.commit()
    con.close()
