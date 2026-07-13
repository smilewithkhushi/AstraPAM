"""Mock Core Banking System — privileged target + ledger. Run on port 8001."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

_now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Mock CBS", version="0")

_accounts: dict[str, dict] = {}
_ledger: list[dict] = []
_swift_actions: list[dict] = []


class ProvisionRequest(BaseModel):
    grant_id: str
    user_id: str
    rate_cap: float | None = None


class LedgerRequest(BaseModel):
    action_id: str
    amount: float


class SwiftRequest(BaseModel):
    user_id: str
    amount: float
    description: str = ""


@app.get("/health")
def health() -> dict:
    return {"ok": True}


# --- account lifecycle ---

@app.post("/accounts/provision", status_code=201)
def provision_account(req: ProvisionRequest) -> dict:
    _accounts[req.grant_id] = {
        "user_id": req.user_id,
        "rate_cap": req.rate_cap,
        "active": True,
        "provisioned_at": _now().isoformat(),
    }
    return {"grant_id": req.grant_id, "active": True}


@app.delete("/accounts/{grant_id}")
def revoke_account(grant_id: str) -> dict:
    if grant_id not in _accounts:
        raise HTTPException(status_code=404, detail="Grant not found")
    _accounts[grant_id]["active"] = False
    _accounts[grant_id]["revoked_at"] = _now().isoformat()
    return {"grant_id": grant_id, "active": False}


@app.get("/accounts")
def list_accounts() -> dict:
    return {k: v for k, v in _accounts.items() if v["active"]}


# --- CBS-routed ledger (matched financial actions) ---

@app.post("/ledger/entry", status_code=201)
def add_ledger_entry(req: LedgerRequest) -> dict:
    entry = {
        "entry_id": str(uuid.uuid4()),
        "action_id": req.action_id,
        "amount": req.amount,
        "timestamp": _now().isoformat(),
    }
    _ledger.append(entry)
    return entry


@app.get("/ledger")
def get_ledger() -> list:
    return _ledger


# --- SWIFT-like channel (out-of-band, no ledger entry — the PNB pattern) ---

@app.post("/swift/action", status_code=201)
def swift_action(req: SwiftRequest) -> dict:
    action = {
        "action_id": str(uuid.uuid4()),
        "user_id": req.user_id,
        "channel": "swift_like",
        "amount": req.amount,
        "description": req.description,
        "timestamp": _now().isoformat(),
    }
    _swift_actions.append(action)
    return action


@app.get("/swift/actions")
def get_swift_actions() -> list:
    return _swift_actions
