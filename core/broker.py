"""JIT access broker — ephemeral grant lifecycle with graduated risk-adaptive decisions.

Public API:
    request_access(req, session_features) -> dict
    revoke(grant_id) -> None
    expire_stale() -> list[str]
    get_active_grants() -> list[EphemeralGrant]
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from . import crypto
from . import risk as risk_engine
from .roles import get_user
from .schemas import DB_PATH, AccessRequest, EphemeralGrant, RiskResult

CBS_URL           = os.getenv("CBS_URL", "http://localhost:8001")
GRANT_TTL         = int(os.getenv("GRANT_TTL_SECONDS", "300"))
BREAK_GLASS_TTL   = int(os.getenv("BREAK_GLASS_TTL_SECONDS", "60"))
THROTTLE_CAP      = float(os.getenv("THROTTLE_RATE_CAP", "1000.0"))

_now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)


# ── CBS interaction ───────────────────────────────────────────────────────────

def _provision(grant_id: str, user_id: str, rate_cap: float | None) -> None:
    httpx.post(
        f"{CBS_URL}/accounts/provision",
        json={"grant_id": grant_id, "user_id": user_id, "rate_cap": rate_cap},
        timeout=5,
    ).raise_for_status()


def _revoke_on_cbs(grant_id: str) -> None:
    try:
        httpx.delete(f"{CBS_URL}/accounts/{grant_id}", timeout=5).raise_for_status()
    except Exception:
        pass  # best-effort; SQLite record is the source of truth


# ── persistence ───────────────────────────────────────────────────────────────

def _save(con: sqlite3.Connection, g: EphemeralGrant) -> None:
    con.execute(
        "INSERT INTO ephemeral_grants"
        " (grant_id, user_id, target, expires_at, revoked, rate_cap, break_glass, correlation_id)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (g.grant_id, g.user_id, g.target, g.expires_at.isoformat(),
         int(g.revoked), g.rate_cap, int(g.break_glass), g.correlation_id),
    )


# ── public API ────────────────────────────────────────────────────────────────

def request_access(req: AccessRequest, session_features: dict[str, float]) -> dict:
    """Score the requester and issue a grant, step-up challenge, or denial.

    Returns a dict (not a Pydantic model) so main.py can return it directly as JSON.
    """
    # Phase 8: honour freeze/block status — no new grants for locked users
    bank_user = get_user(req.user_id)
    if bank_user and bank_user.status in ("FROZEN", "BLOCKED"):
        return {
            "status": "denied",
            "reason": f"User {req.user_id} is {bank_user.status}. No new grants permitted.",
            "score": 1.0,
            "attack_tags": [],
            "top_factors": [],
        }

    result: RiskResult = risk_engine.score(session_features)

    if result.decision == "deny":
        return {
            "status": "denied",
            "score": result.score,
            "attack_tags": result.attack_tags,
            "top_factors": [f.model_dump() for f in result.top_factors],
        }

    if result.decision == "step_up":
        # Production: trigger MFA / out-of-band approval flow.
        # Demo: return challenge; grant is not issued until /access/approve.
        return {
            "status": "step_up_required",
            "score": result.score,
            "attack_tags": result.attack_tags,
            "message": "Elevated risk — additional authentication required before grant is issued.",
        }

    rate_cap = THROTTLE_CAP if result.decision == "throttle" else None
    now      = _now()
    cid      = req.correlation_id
    grant    = EphemeralGrant(
        grant_id=str(uuid.uuid4()),
        user_id=req.user_id,
        target=req.target,
        expires_at=now + timedelta(seconds=GRANT_TTL),
        revoked=False,
        rate_cap=rate_cap,
        correlation_id=cid,
    )

    _provision(grant.grant_id, grant.user_id, rate_cap)

    con = sqlite3.connect(DB_PATH)
    _save(con, grant)
    con.commit()
    con.close()

    from . import roles as _roles
    role_name = ""
    branch = ""
    if bank_user:
        role = _roles.get_role(bank_user.role_id)
        role_name = role.name if role else bank_user.role_id
        branch = bank_user.branch_sol

    crypto.append_audit(json.dumps({
        "event": "grant_issued",
        "correlation_id": cid,
        "grant_id": grant.grant_id,
        "user_id": grant.user_id,
        "role": role_name,
        "branch": branch,
        "decision": result.decision,
        "score": result.score,
        "expires_at": grant.expires_at.isoformat(),
    }))

    return {
        "status": "granted" if result.decision == "allow" else "granted_throttled",
        "grant": grant.model_dump(),
        "risk": {"score": result.score, "decision": result.decision,
                 "attack_tags": result.attack_tags,
                 "top_factors": [f.model_dump() for f in result.top_factors]},
        "actor": {"role": role_name, "branch": branch},
    }


def revoke(grant_id: str) -> None:
    """Manually revoke a grant — removes from CBS and marks in DB."""
    _revoke_on_cbs(grant_id)
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE ephemeral_grants SET revoked=1 WHERE grant_id=?", (grant_id,))
    con.commit()
    con.close()


def expire_stale() -> list[str]:
    """Auto-revoke all grants whose TTL has elapsed. Returns revoked grant_ids."""
    cutoff = _now().isoformat()
    con    = sqlite3.connect(DB_PATH)
    rows   = con.execute(
        "SELECT grant_id FROM ephemeral_grants WHERE revoked=0 AND expires_at <= ?",
        (cutoff,),
    ).fetchall()
    revoked = []
    for (gid,) in rows:
        _revoke_on_cbs(gid)
        con.execute("UPDATE ephemeral_grants SET revoked=1 WHERE grant_id=?", (gid,))
        revoked.append(gid)
    con.commit()
    con.close()
    return revoked


def get_active_grants() -> list[EphemeralGrant]:
    cutoff = _now().isoformat()
    con    = sqlite3.connect(DB_PATH)
    rows   = con.execute(
        "SELECT grant_id, user_id, target, expires_at, revoked, rate_cap, break_glass, correlation_id"
        " FROM ephemeral_grants WHERE revoked=0 AND expires_at > ?",
        (cutoff,),
    ).fetchall()
    con.close()
    return [
        EphemeralGrant(
            grant_id=r[0], user_id=r[1], target=r[2],
            expires_at=datetime.fromisoformat(r[3]),
            revoked=bool(r[4]), rate_cap=r[5], break_glass=bool(r[6]),
            correlation_id=r[7] or "",
        )
        for r in rows
    ]


def break_glass_access(user_id: str, target: str, justification: str,
                       session_features: dict[str, float]) -> dict:
    """Emergency bypass — issues a grant regardless of risk score.

    Risk is still scored and written to the tamper-evident audit chain so the
    decision can be reviewed forensically. TTL is capped at BREAK_GLASS_TTL
    to limit the exposure window.
    """
    result: RiskResult = risk_engine.score(session_features)
    now    = _now()
    cid    = str(uuid.uuid4())  # break-glass always starts a fresh correlation
    grant  = EphemeralGrant(
        grant_id       = str(uuid.uuid4()),
        user_id        = user_id,
        target         = target,
        expires_at     = now + timedelta(seconds=BREAK_GLASS_TTL),
        revoked        = False,
        rate_cap       = None,
        break_glass    = True,
        correlation_id = cid,
    )

    _provision(grant.grant_id, grant.user_id, None)

    con = sqlite3.connect(DB_PATH)
    _save(con, grant)
    con.commit()
    con.close()

    crypto.append_audit(json.dumps({
        "event":           "break_glass_grant",
        "correlation_id":  cid,
        "grant_id":        grant.grant_id,
        "user_id":         user_id,
        "target":          target,
        "justification":   justification,
        "risk_score":      result.score,
        "risk_decision":   result.decision,
        "attack_tags":     result.attack_tags,
        "expires_at":      grant.expires_at.isoformat(),
    }))

    return {
        "status":          "break_glass_granted",
        "correlation_id":  cid,
        "grant":           grant.model_dump(),
        "risk_at_issue": {
            "score":        result.score,
            "decision":     result.decision,
            "attack_tags":  result.attack_tags,
            "top_factors":  [f.model_dump() for f in result.top_factors],
        },
        "warning": (
            f"Break-glass overrides risk decision '{result.decision}' "
            f"(score={result.score:.3f}). "
            "This event is cryptographically signed in the audit chain."
        ),
    }
