from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel

DB_PATH = os.getenv("AEGISPAM_DB", "database/aegispam.db")

Decision   = Literal["allow", "throttle", "step_up", "deny"]
Severity   = Literal["critical", "high", "medium", "low"]
Channel    = Literal["cbs", "swift_like"]
ActionType = Literal["read", "admin", "financial"]
NHIType    = Literal["service_account", "api_key", "ai_agent"]
NHIStatus  = Literal["active", "expiring_soon", "expired", "revoked"]
AttackTag  = Literal[
    "OFF_HOURS_ACTIVITY",
    "ANOMALOUS_LOCATION",
    "MASS_DATA_EXPORT",
    "PRIVILEGE_ESCALATION",
]

# v3 additions
UserStatus         = Literal["ACTIVE", "FROZEN", "BLOCKED", "HELD"]
WorkClass          = Literal["MANAGER", "OFFICER", "CLERK", "IT_ADMIN", "SERVICE"]
Tier               = Literal["T1", "T2", "T3", "T4", "T5", "NHI"]
SoDSeverity        = Literal["critical", "high", "medium"]
MakerCheckerStatus = Literal["PENDING", "APPROVED", "REJECTED", "SELF_APPROVAL_BLOCKED"]
ConsoleActionType  = Literal["FREEZE", "BLOCK", "UNBLOCK", "HOLD", "REVOKE_SESSION", "REQUIRE_STEPUP"]
ConsoleActionStatus = Literal["PENDING", "APPLIED", "REJECTED"]
SessionStatus      = Literal["ACTIVE", "EXPIRED", "REVOKED"]

SEVERITY_PLAYBOOK: dict[str, str] = {
    "critical": "Isolate session, notify security team immediately, preserve audit log.",
    "high": "Suspend grant, escalate to SOC, request manual review.",
    "medium": "Flag for next-business-hour review, increase monitoring frequency.",
    "low": "Log for weekly compliance review.",
}


# ── existing models (correlation_id added) ─────────────────────────────────────

class AccessRequest(BaseModel):
    user_id: str
    target: str
    action_type: ActionType
    requested_at: datetime
    break_glass: bool = False
    correlation_id: str = ""


class RiskFactor(BaseModel):
    feature: str
    contribution: float


class RiskResult(BaseModel):
    score: float  # 0–1
    decision: Decision
    top_factors: list[RiskFactor]
    attack_tags: list[AttackTag]
    correlation_id: str = ""


class EphemeralGrant(BaseModel):
    grant_id: str
    user_id: str
    target: str
    expires_at: datetime
    revoked: bool
    rate_cap: float | None = None
    break_glass: bool = False
    correlation_id: str = ""


class PrivilegedAction(BaseModel):
    action_id: str
    user_id: str
    channel: Channel
    amount: float | None = None
    timestamp: datetime
    correlation_id: str = ""


class LedgerEntry(BaseModel):
    entry_id: str
    action_id: str | None = None  # null = the PNB red-flag
    amount: float
    timestamp: datetime
    correlation_id: str = ""


class ReconAlert(BaseModel):
    action_id: str
    reason: str
    severity: Severity
    recommended_action: str
    detected_at: datetime
    correlation_id: str = ""


class AuditRecord(BaseModel):
    seq: int
    prev_hash: str
    payload: str
    signature: str
    hash: str
    correlation_id: str = ""


class CryptoArtifact(BaseModel):
    """Display-only: byte counts from a real KEM call prove PQC is not mocked."""
    pubkey_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    algorithm: str  # "ML-KEM-768"


class NHIIdentity(BaseModel):
    nhi_id:      str
    name:        str
    nhi_type:    NHIType
    owner:       str
    description: str = ""
    created_at:  datetime
    expires_at:  datetime
    last_used:   datetime | None = None
    status:      NHIStatus = "active"


# ── v3 models (all phases) ─────────────────────────────────────────────────────

class Role(BaseModel):
    role_id: str
    name: str
    work_class: WorkClass
    tier: Tier
    entitlements: set[str]
    input_limit: Decimal | None = None   # max amount user can initiate
    auth_limit: Decimal | None = None    # max amount user can approve


class BankUser(BaseModel):
    user_id: str
    name: str
    role_id: str
    branch_sol: str
    status: UserStatus = "ACTIVE"
    created_at: datetime
    last_login_at: datetime | None = None
    extra_entitlements: set[str] = set()  # privilege creep lives here


class SoDConflict(BaseModel):
    user_id: str
    entitlement_a: str
    entitlement_b: str
    rule_id: str
    severity: SoDSeverity
    detected_at: datetime


class MakerCheckerReq(BaseModel):
    request_id: str
    correlation_id: str
    maker_id: str
    checker_id: str | None = None
    action_type: str
    amount: float | None = None
    status: MakerCheckerStatus = "PENDING"
    created_at: datetime
    decided_at: datetime | None = None


class ConsoleAction(BaseModel):
    action_id: str
    correlation_id: str
    operator_id: str
    target_user_id: str
    action: ConsoleActionType
    reason: str
    approver_id: str | None = None
    status: ConsoleActionStatus = "PENDING"
    timestamp: datetime


class ExposureScore(BaseModel):
    user_id: str
    score: float  # 0–1
    components: dict[str, float]
    computed_at: datetime


class Session(BaseModel):
    session_id: str
    correlation_id: str
    user_id: str
    started_at: datetime
    last_seen_at: datetime
    source_ip: str
    status: SessionStatus = "ACTIVE"


class LoginEvent(BaseModel):
    event_id: str
    user_id: str
    timestamp: datetime
    success: bool
    source_ip: str
    failure_reason: str | None = None


# ── database ───────────────────────────────────────────────────────────────────

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
            rate_cap            REAL,
            break_glass         INTEGER NOT NULL DEFAULT 0,
            correlation_id      TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS privileged_actions (
            action_id           TEXT PRIMARY KEY,
            user_id             TEXT NOT NULL,
            channel             TEXT NOT NULL,
            amount              REAL,
            timestamp           TEXT NOT NULL,
            correlation_id      TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS ledger_entries (
            entry_id            TEXT PRIMARY KEY,
            action_id           TEXT,
            amount              REAL NOT NULL,
            timestamp           TEXT NOT NULL,
            correlation_id      TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS recon_alerts (
            action_id           TEXT PRIMARY KEY,
            reason              TEXT NOT NULL,
            severity            TEXT NOT NULL,
            recommended_action  TEXT NOT NULL,
            detected_at         TEXT NOT NULL,
            correlation_id      TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS audit_records (
            seq                 INTEGER PRIMARY KEY,
            prev_hash           TEXT NOT NULL,
            payload             TEXT NOT NULL,
            signature           TEXT NOT NULL,
            hash                TEXT NOT NULL,
            correlation_id      TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS nhi_identities (
            nhi_id              TEXT PRIMARY KEY,
            name                TEXT NOT NULL,
            nhi_type            TEXT NOT NULL,
            owner               TEXT NOT NULL,
            description         TEXT NOT NULL DEFAULT '',
            created_at          TEXT NOT NULL,
            expires_at          TEXT NOT NULL,
            last_used           TEXT,
            status              TEXT NOT NULL DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS maker_checker_reqs (
            request_id          TEXT PRIMARY KEY,
            correlation_id      TEXT NOT NULL DEFAULT '',
            maker_id            TEXT NOT NULL,
            checker_id          TEXT,
            action_type         TEXT NOT NULL,
            amount              REAL,
            status              TEXT NOT NULL DEFAULT 'PENDING',
            created_at          TEXT NOT NULL,
            decided_at          TEXT
        );
        CREATE TABLE IF NOT EXISTS console_actions (
            action_id           TEXT PRIMARY KEY,
            correlation_id      TEXT NOT NULL DEFAULT '',
            operator_id         TEXT NOT NULL,
            target_user_id      TEXT NOT NULL,
            action              TEXT NOT NULL,
            reason              TEXT NOT NULL,
            approver_id         TEXT,
            status              TEXT NOT NULL DEFAULT 'PENDING',
            timestamp           TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            session_id          TEXT PRIMARY KEY,
            correlation_id      TEXT NOT NULL DEFAULT '',
            user_id             TEXT NOT NULL,
            started_at          TEXT NOT NULL,
            last_seen_at        TEXT NOT NULL,
            source_ip           TEXT NOT NULL DEFAULT '',
            status              TEXT NOT NULL DEFAULT 'ACTIVE'
        );
        CREATE TABLE IF NOT EXISTS login_events (
            event_id            TEXT PRIMARY KEY,
            user_id             TEXT NOT NULL,
            timestamp           TEXT NOT NULL,
            success             INTEGER NOT NULL DEFAULT 1,
            source_ip           TEXT NOT NULL DEFAULT '',
            failure_reason      TEXT
        );
        CREATE TABLE IF NOT EXISTS access_request_log (
            log_id          TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL,
            target          TEXT NOT NULL,
            action_type     TEXT NOT NULL DEFAULT '',
            decision        TEXT NOT NULL,
            risk_score      REAL NOT NULL,
            attack_tags     TEXT NOT NULL DEFAULT '[]',
            grant_id        TEXT,
            break_glass     INTEGER NOT NULL DEFAULT 0,
            correlation_id  TEXT NOT NULL DEFAULT '',
            requested_at    TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sod_conflicts (
            rule_id             TEXT NOT NULL,
            user_id             TEXT NOT NULL,
            entitlement_a       TEXT NOT NULL,
            entitlement_b       TEXT NOT NULL,
            severity            TEXT NOT NULL,
            status              TEXT NOT NULL DEFAULT 'UNRESOLVED',
            first_detected_at   TEXT NOT NULL,
            last_scanned_at     TEXT NOT NULL,
            resolved_at         TEXT,
            PRIMARY KEY (rule_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS cbom_scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at      TEXT NOT NULL,
            files_scanned   INTEGER NOT NULL,
            quantum_safe    INTEGER NOT NULL,
            hybrid_pqc      INTEGER NOT NULL,
            classical       INTEGER NOT NULL,
            vulnerable      INTEGER NOT NULL,
            verdict         TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS report_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at    TEXT NOT NULL,
            report_type     TEXT NOT NULL,
            period_days     INTEGER NOT NULL,
            file_name       TEXT NOT NULL,
            file_size_kb    REAL NOT NULL,
            status          TEXT NOT NULL DEFAULT 'SUCCESS'
        );
    """)
    con.commit()

    # migrate existing DBs — add missing columns without dropping data
    _migrate(con, "ephemeral_grants",   "break_glass",    "INTEGER NOT NULL DEFAULT 0")
    _migrate(con, "ephemeral_grants",   "correlation_id",  "TEXT NOT NULL DEFAULT ''")
    _migrate(con, "privileged_actions", "correlation_id",  "TEXT NOT NULL DEFAULT ''")
    _migrate(con, "ledger_entries",     "correlation_id",  "TEXT NOT NULL DEFAULT ''")
    _migrate(con, "recon_alerts",       "correlation_id",  "TEXT NOT NULL DEFAULT ''")
    _migrate(con, "audit_records",      "correlation_id",  "TEXT NOT NULL DEFAULT ''")

    con.close()


def _migrate(con: sqlite3.Connection, table: str, column: str, typedef: str) -> None:
    try:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {typedef}")
        con.commit()
    except sqlite3.OperationalError:
        pass  # column already exists
