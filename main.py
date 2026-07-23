from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any
import os
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core import broker
from core import cbom as cbom_scanner
from core import crypto
from core import nhi as nhi_module
from core import reconcile
from core import roles as roles_module
from core.schemas import ActionType, ConsoleActionType, init_db

_now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AstraPAM", version="0", lifespan=lifespan)

_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
_origins = ["*"] if _raw_origins == "*" else [o.strip() for o in _raw_origins.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── request bodies ────────────────────────────────────────────────────────────

class AccessRequestBody(BaseModel):
    user_id: str
    target: str
    action_type: ActionType
    features: dict[str, float] = {}
    correlation_id: str = ""  # generated here if not supplied


class FinancialActionBody(BaseModel):
    grant_id: str
    user_id: str
    amount: float
    correlation_id: str = ""


class BreakGlassBody(BaseModel):
    user_id: str
    target: str
    justification: str
    features: dict[str, float] = {}


class ConsoleActionBody(BaseModel):
    operator_id: str
    target_user_id: str
    action: ConsoleActionType
    reason: str
    approver_id: str | None = None
    correlation_id: str = ""


class MakerCheckerBody(BaseModel):
    request_id: str
    checker_id: str
    approve: bool


# ── health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    return {"ok": True}


# ── access (broker) ───────────────────────────────────────────────────────────

@app.post("/access/request")
def access_request(body: AccessRequestBody) -> Any:
    from schemas import AccessRequest
    cid = body.correlation_id or str(uuid.uuid4())
    req = AccessRequest(
        user_id=body.user_id,
        target=body.target,
        action_type=body.action_type,
        requested_at=_now(),
        correlation_id=cid,
    )
    result = broker.request_access(req, body.features)
    result["correlation_id"] = cid
    return result


@app.post("/access/revoke/{grant_id}")
def access_revoke(grant_id: str) -> dict:
    broker.revoke(grant_id)
    return {"revoked": grant_id}


@app.post("/access/break-glass")
def access_break_glass(body: BreakGlassBody) -> Any:
    """Emergency access — bypasses risk gating, but logs score + justification to audit chain."""
    return broker.break_glass_access(
        user_id=body.user_id,
        target=body.target,
        justification=body.justification,
        session_features=body.features,
    )


@app.post("/access/expire")
def access_expire() -> dict:
    """Trigger stale-grant cleanup — call this periodically or after each demo step."""
    revoked = broker.expire_stale()
    return {"expired": revoked, "count": len(revoked)}


@app.get("/access/grants")
def access_grants() -> list:
    return [g.model_dump() for g in broker.get_active_grants()]


# ── reconciliation ────────────────────────────────────────────────────────────

@app.post("/reconcile/run")
def reconcile_run(sla_seconds: int = 30) -> dict:
    """Sync from CBS then run reconciliation. Returns new alerts from this run."""
    sw, le = reconcile.sync_from_cbs()
    alerts = reconcile.run(sla_seconds=sla_seconds)
    return {
        "synced": {"swift_actions": sw, "ledger_entries": le},
        "new_alerts": [a.model_dump() for a in alerts],
    }


@app.get("/reconcile/alerts")
def reconcile_alerts() -> list:
    return [a.model_dump() for a in reconcile.get_all_alerts()]


# ── crypto / audit ────────────────────────────────────────────────────────────

@app.post("/crypto/credential/{grant_id}")
def credential_issue(grant_id: str, user_id: str) -> dict:
    """Perform hybrid ML-KEM-768 + X25519 handshake for a grant credential.
    Returns CryptoArtifact with real byte-counts — proof the KEM ran.
    """
    artifact = crypto.issue_credential(user_id=user_id, grant_id=grant_id)
    return artifact.model_dump()


@app.get("/crypto/verify")
def audit_verify() -> dict:
    """Verify the entire audit chain. Tampered records surface here."""
    return crypto.verify_chain()


@app.get("/crypto/audit")
def audit_log() -> list:
    return [r.model_dump() for r in crypto.get_audit_log()]


# ── CBOM ──────────────────────────────────────────────────────────────────────

# ── NHI governance ────────────────────────────────────────────────────────────

class NHIRegisterBody(BaseModel):
    name:        str
    nhi_type:    str
    owner:       str
    ttl_days:    int = 90
    description: str = ""


@app.post("/nhi/register", status_code=201)
def nhi_register(body: NHIRegisterBody) -> dict:
    return nhi_module.register(**body.model_dump()).model_dump()


@app.get("/nhi/list")
def nhi_list() -> list:
    return [n.model_dump() for n in nhi_module.list_all()]


@app.post("/nhi/rotate/{nhi_id}")
def nhi_rotate(nhi_id: str, ttl_days: int = 90) -> dict:
    return nhi_module.rotate(nhi_id, ttl_days).model_dump()


@app.post("/nhi/revoke/{nhi_id}")
def nhi_revoke(nhi_id: str) -> dict:
    return nhi_module.revoke(nhi_id).model_dump()


@app.get("/nhi/scan")
def nhi_scan() -> dict:
    expired = nhi_module.scan_expired()
    return {"newly_expired": [n.model_dump() for n in expired], "count": len(expired)}


# ── CBOM ──────────────────────────────────────────────────────────────────────

@app.get("/cbom/scan")
def cbom_scan() -> dict:
    """Scan project .py files for cryptographic algorithm usage.
    Classifies findings as quantum_safe / hybrid_pqc / quantum_vulnerable / classical_symmetric.
    """
    return cbom_scanner.scan().model_dump()


# ── roles (Phase 6) ───────────────────────────────────────────────────────────

@app.get("/roles")
def list_roles() -> list:
    return [
        {**r.model_dump(), "entitlements": sorted(r.entitlements),
         "input_limit": str(r.input_limit) if r.input_limit else None,
         "auth_limit": str(r.auth_limit) if r.auth_limit else None}
        for r in roles_module.ROLES.values()
    ]


@app.get("/roles/users")
def list_users() -> list:
    return [
        {**u.model_dump(), "extra_entitlements": sorted(u.extra_entitlements),
         "effective_entitlements": sorted(roles_module.effective_entitlements(u))}
        for u in roles_module.get_all_users()
    ]


@app.get("/roles/users/{user_id}")
def get_user(user_id: str) -> dict:
    u = roles_module.get_user(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    role = roles_module.get_role(u.role_id)
    return {
        **u.model_dump(),
        "extra_entitlements": sorted(u.extra_entitlements),
        "effective_entitlements": sorted(roles_module.effective_entitlements(u)),
        "role": role.model_dump() if role else None,
    }


# ── SoD (Phase 7) ─────────────────────────────────────────────────────────────

@app.get("/sod/conflicts")
def sod_conflicts() -> list:
    return [c.model_dump() for c in roles_module.scan_all_conflicts()]


@app.get("/sod/conflicts/{user_id}")
def sod_conflicts_for_user(user_id: str) -> list:
    u = roles_module.get_user(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return [c.model_dump() for c in roles_module.scan_sod_conflicts(u)]


# ── maker-checker (Phase 7) ───────────────────────────────────────────────────

import json as _json
import sqlite3 as _sqlite3


@app.post("/maker-checker/submit")
def maker_checker_submit(body: FinancialActionBody) -> dict:
    """Submit a financial action for maker-checker approval.

    If the acting user has no auth_limit or the amount is below it, the action
    is auto-approved (single-user flow). Otherwise it enters PENDING state.
    """
    from schemas import MakerCheckerReq
    cid = body.correlation_id or str(uuid.uuid4())
    req_id = str(uuid.uuid4())
    now = _now()

    actor = roles_module.get_user(body.user_id)
    role = roles_module.get_role(actor.role_id) if actor else None
    auth_limit = role.auth_limit if role else None

    # amounts at or below auth_limit are within the maker's own authority
    needs_checker = auth_limit is None or body.amount > float(auth_limit)

    status = "PENDING" if needs_checker else "APPROVED"

    req = MakerCheckerReq(
        request_id=req_id,
        correlation_id=cid,
        maker_id=body.user_id,
        checker_id=None,
        action_type="financial_transfer",
        amount=body.amount,
        status=status,
        created_at=now,
        decided_at=now if not needs_checker else None,
    )
    from schemas import DB_PATH as _DB
    con = _sqlite3.connect(_DB)
    con.execute(
        "INSERT INTO maker_checker_reqs"
        " (request_id, correlation_id, maker_id, checker_id, action_type, amount, status, created_at, decided_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (req.request_id, req.correlation_id, req.maker_id, req.checker_id,
         req.action_type, req.amount, req.status,
         req.created_at.isoformat(), req.decided_at.isoformat() if req.decided_at else None),
    )
    con.commit()
    con.close()

    crypto.append_audit(_json.dumps({
        "event": "maker_checker_submitted",
        "correlation_id": cid,
        "request_id": req_id,
        "maker_id": body.user_id,
        "amount": body.amount,
        "status": status,
    }))

    return req.model_dump()


@app.post("/maker-checker/decide")
def maker_checker_decide(body: MakerCheckerBody) -> dict:
    """Checker approves or rejects a pending maker-checker request.

    Self-approval (checker_id == maker_id) is blocked with SELF_APPROVAL_BLOCKED.
    """
    from schemas import DB_PATH as _DB
    con = _sqlite3.connect(_DB)
    row = con.execute(
        "SELECT request_id, correlation_id, maker_id, action_type, amount, status, created_at"
        " FROM maker_checker_reqs WHERE request_id=?",
        (body.request_id,),
    ).fetchone()
    if not row:
        con.close()
        raise HTTPException(status_code=404, detail="Request not found")

    req_id, cid, maker_id, action_type, amount, current_status, created_at = row
    if current_status != "PENDING":
        con.close()
        raise HTTPException(status_code=409, detail=f"Request already in state: {current_status}")

    if body.checker_id == maker_id:
        new_status = "SELF_APPROVAL_BLOCKED"
    else:
        new_status = "APPROVED" if body.approve else "REJECTED"

    now = _now()
    con.execute(
        "UPDATE maker_checker_reqs SET checker_id=?, status=?, decided_at=? WHERE request_id=?",
        (body.checker_id, new_status, now.isoformat(), body.request_id),
    )
    con.commit()
    con.close()

    crypto.append_audit(_json.dumps({
        "event": "maker_checker_decided",
        "correlation_id": cid,
        "request_id": req_id,
        "checker_id": body.checker_id,
        "new_status": new_status,
    }))

    return {"request_id": req_id, "correlation_id": cid, "status": new_status}


@app.get("/maker-checker/list")
def maker_checker_list() -> list:
    from schemas import DB_PATH as _DB
    con = _sqlite3.connect(_DB)
    rows = con.execute(
        "SELECT request_id, correlation_id, maker_id, checker_id, action_type, amount, status, created_at, decided_at"
        " FROM maker_checker_reqs ORDER BY created_at DESC"
    ).fetchall()
    con.close()
    cols = ("request_id", "correlation_id", "maker_id", "checker_id",
            "action_type", "amount", "status", "created_at", "decided_at")
    return [dict(zip(cols, r)) for r in rows]


# ── console (Phase 8) ─────────────────────────────────────────────────────────

# In-memory user status store (bridges roles.py immutable data + console actions)
_user_status_overrides: dict[str, str] = {}


def _get_effective_status(user_id: str) -> str:
    return _user_status_overrides.get(user_id, "ACTIVE")


@app.post("/console/action")
def console_action(body: ConsoleActionBody) -> dict:
    """Apply a mitigation action to a target user.

    BLOCK requires an approver_id (maker-checker). FREEZE is single-operator
    but flagged. All actions are written to the signed audit chain.
    """
    from schemas import ConsoleAction, DB_PATH as _DB

    if body.action == "BLOCK" and not body.approver_id:
        raise HTTPException(
            status_code=422,
            detail="BLOCK requires approver_id (maker-checker mandatory for permanent block).",
        )
    if body.approver_id and body.approver_id == body.operator_id:
        raise HTTPException(
            status_code=422,
            detail="Self-approval not permitted. approver_id must differ from operator_id.",
        )

    cid = body.correlation_id or str(uuid.uuid4())
    action_id = str(uuid.uuid4())
    now = _now()

    # PENDING for BLOCK (needs explicit approve step), APPLIED for the rest
    status: str = "PENDING" if (body.action == "BLOCK" and body.approver_id) else "APPLIED"

    action = ConsoleAction(
        action_id=action_id,
        correlation_id=cid,
        operator_id=body.operator_id,
        target_user_id=body.target_user_id,
        action=body.action,
        reason=body.reason,
        approver_id=body.approver_id,
        status=status,
        timestamp=now,
    )

    con = _sqlite3.connect(_DB)
    con.execute(
        "INSERT INTO console_actions"
        " (action_id, correlation_id, operator_id, target_user_id, action, reason, approver_id, status, timestamp)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (action.action_id, action.correlation_id, action.operator_id,
         action.target_user_id, action.action, action.reason,
         action.approver_id, action.status, action.timestamp.isoformat()),
    )
    con.commit()
    con.close()

    if status == "APPLIED":
        _apply_console_action(body.target_user_id, body.action)

    crypto.append_audit(_json.dumps({
        "event": "console_action",
        "correlation_id": cid,
        "action_id": action_id,
        "operator_id": body.operator_id,
        "target_user_id": body.target_user_id,
        "action": body.action,
        "reason": body.reason,
        "approver_id": body.approver_id,
        "status": status,
    }))

    return action.model_dump()


def _apply_console_action(user_id: str, action: str) -> None:
    """Apply the in-memory status change for the target user."""
    if action == "FREEZE":
        _user_status_overrides[user_id] = "FROZEN"
    elif action == "BLOCK":
        _user_status_overrides[user_id] = "BLOCKED"
    elif action == "UNBLOCK":
        _user_status_overrides.pop(user_id, None)
    elif action == "HOLD":
        _user_status_overrides[user_id] = "HELD"
    # REVOKE_SESSION and REQUIRE_STEPUP are logged; grant revocation handled separately


@app.get("/console/actions")
def console_actions_list() -> list:
    from schemas import DB_PATH as _DB
    con = _sqlite3.connect(_DB)
    rows = con.execute(
        "SELECT action_id, correlation_id, operator_id, target_user_id, action,"
        "       reason, approver_id, status, timestamp"
        " FROM console_actions ORDER BY timestamp DESC"
    ).fetchall()
    con.close()
    cols = ("action_id", "correlation_id", "operator_id", "target_user_id",
            "action", "reason", "approver_id", "status", "timestamp")
    return [dict(zip(cols, r)) for r in rows]


@app.get("/console/status/{user_id}")
def console_user_status(user_id: str) -> dict:
    return {"user_id": user_id, "effective_status": _get_effective_status(user_id)}


# ── exposure score (Phase 9) ──────────────────────────────────────────────────

@app.get("/exposure/{user_id}")
def exposure_score(user_id: str) -> dict:
    from schemas import ExposureScore, DB_PATH as _DB
    u = roles_module.get_user(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    role = roles_module.get_role(u.role_id)
    all_roles = list(roles_module.ROLES.values())
    max_ents = max(len(r.entitlements) for r in all_roles)
    max_limit = max(
        (float(r.auth_limit) for r in all_roles if r.auth_limit), default=1.0
    )

    ents = roles_module.effective_entitlements(u)
    conflicts = roles_module.scan_sod_conflicts(u)
    now = _now()
    days_dormant = (now - u.last_login_at).days if u.last_login_at else 365
    days_created = (now - u.created_at).days

    # weights — fixed and documented
    w1, w2, w3, w4, w5, w6 = 0.20, 0.20, 0.25, 0.15, 0.10, 0.10

    privilege_breadth  = len(ents) / max_ents if max_ents else 0.0
    financial_auth     = float(role.auth_limit) / max_limit if (role and role.auth_limit) else 0.0
    conflict_weight    = sum(0.5 if c.severity == "high" else 1.0 for c in conflicts)
    sod_score          = min(conflict_weight / 3, 1.0)
    dormancy           = min(days_dormant / 180, 1.0)
    credential_age     = min(days_created / 1825, 1.0)   # 5-year max
    is_nhi             = 1.0 if (role and role.tier == "NHI") else 0.0

    score = (w1 * privilege_breadth + w2 * financial_auth + w3 * sod_score
             + w4 * dormancy + w5 * credential_age + w6 * is_nhi)
    score = round(min(score, 1.0), 4)

    components = {
        "privilege_breadth": round(privilege_breadth, 4),
        "financial_authority": round(financial_auth, 4),
        "sod_conflicts": round(sod_score, 4),
        "dormancy": round(dormancy, 4),
        "credential_age": round(credential_age, 4),
        "is_nhi": is_nhi,
    }
    return ExposureScore(
        user_id=user_id, score=score, components=components, computed_at=now
    ).model_dump()


@app.get("/exposure")
def all_exposure_scores() -> list:
    return [exposure_score(u.user_id) for u in roles_module.get_all_users()]


# ── trace view (Phase 6) ──────────────────────────────────────────────────────

@app.get("/trace/{correlation_id}")
def trace_correlation(correlation_id: str) -> dict:
    """Return every artifact linked to a correlation_id across all modules."""
    from schemas import DB_PATH as _DB
    con = _sqlite3.connect(_DB)

    grants = con.execute(
        "SELECT grant_id, user_id, target, expires_at, revoked, rate_cap, break_glass, correlation_id"
        " FROM ephemeral_grants WHERE correlation_id=?", (correlation_id,)
    ).fetchall()

    actions = con.execute(
        "SELECT action_id, user_id, channel, amount, timestamp, correlation_id"
        " FROM privileged_actions WHERE correlation_id=?", (correlation_id,)
    ).fetchall()

    alerts = con.execute(
        "SELECT action_id, reason, severity, recommended_action, detected_at, correlation_id"
        " FROM recon_alerts WHERE correlation_id=?", (correlation_id,)
    ).fetchall()

    mc_reqs = con.execute(
        "SELECT request_id, maker_id, checker_id, amount, status, created_at"
        " FROM maker_checker_reqs WHERE correlation_id=?", (correlation_id,)
    ).fetchall()

    console_acts = con.execute(
        "SELECT action_id, operator_id, target_user_id, action, status, timestamp"
        " FROM console_actions WHERE correlation_id=?", (correlation_id,)
    ).fetchall()

    # pull matching audit records by correlation_id in payload JSON
    audit_rows = con.execute(
        "SELECT seq, payload, hash FROM audit_records WHERE payload LIKE ?",
        (f'%"correlation_id": "{correlation_id}"%',)
    ).fetchall()
    # also try without space (json.dumps compact)
    audit_rows2 = con.execute(
        "SELECT seq, payload, hash FROM audit_records WHERE payload LIKE ?",
        (f'%"correlation_id":"{correlation_id}"%',)
    ).fetchall()
    seen = {r[0] for r in audit_rows}
    audit_rows = audit_rows + [r for r in audit_rows2 if r[0] not in seen]

    con.close()

    def _user_label(uid: str) -> str:
        u = roles_module.get_user(uid)
        if not u:
            return uid
        role = roles_module.get_role(u.role_id)
        rname = role.name if role else u.role_id
        return f"{u.name} ({rname} @ {u.branch_sol})"

    return {
        "correlation_id": correlation_id,
        "grants": [
            {"grant_id": r[0], "actor": _user_label(r[1]), "target": r[2],
             "expires_at": r[3], "revoked": bool(r[4])}
            for r in grants
        ],
        "privileged_actions": [
            {"action_id": r[0], "actor": _user_label(r[1]), "channel": r[2],
             "amount": r[3], "timestamp": r[4]}
            for r in actions
        ],
        "recon_alerts": [
            {"action_id": r[0], "reason": r[1], "severity": r[2],
             "recommended_action": r[3], "detected_at": r[4]}
            for r in alerts
        ],
        "maker_checker": [
            {"request_id": r[0], "maker": _user_label(r[1]),
             "checker": _user_label(r[2]) if r[2] else None,
             "amount": r[3], "status": r[4], "created_at": r[5]}
            for r in mc_reqs
        ],
        "console_actions": [
            {"action_id": r[0], "operator": _user_label(r[1]),
             "target": _user_label(r[2]), "action": r[3],
             "status": r[4], "timestamp": r[5]}
            for r in console_acts
        ],
        "audit_trail": [
            {"seq": r[0], "payload": r[1], "hash": r[2]}
            for r in sorted(audit_rows, key=lambda x: x[0])
        ],
    }
