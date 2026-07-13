from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import broker
import crypto
import reconcile
from schemas import ActionType, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AegisPAM", version="0", lifespan=lifespan)


# ── request bodies ────────────────────────────────────────────────────────────

class AccessRequestBody(BaseModel):
    user_id: str
    target: str
    action_type: ActionType
    # session behavioural features fed to the risk engine
    features: dict[str, float] = {}


class FinancialActionBody(BaseModel):
    grant_id: str
    user_id: str
    amount: float


# ── health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    return {"ok": True}


# ── access (broker) ───────────────────────────────────────────────────────────

@app.post("/access/request")
def access_request(body: AccessRequestBody) -> Any:
    from schemas import AccessRequest
    req = AccessRequest(
        user_id=body.user_id,
        target=body.target,
        action_type=body.action_type,
        requested_at=datetime.utcnow(),
    )
    return broker.request_access(req, body.features)


@app.post("/access/revoke/{grant_id}")
def access_revoke(grant_id: str) -> dict:
    broker.revoke(grant_id)
    return {"revoked": grant_id}


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
