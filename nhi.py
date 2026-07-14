"""Non-Human Identity (NHI) governance — inventory, ownership, auto-expiry.

Governs service accounts, API keys, and AI-agent credentials:
  - every identity has a named owner and a mandatory expiry date
  - scan_expired() auto-marks stale identities and writes to the audit chain
  - rotate() resets the expiry window; revoke() permanently kills an identity
  - "expiring soon" flag surfaces credentials within 30 days of expiry

Public API:
    register(name, nhi_type, owner, ttl_days, description) -> NHIIdentity
    rotate(nhi_id, ttl_days)  -> NHIIdentity
    revoke(nhi_id)            -> NHIIdentity
    scan_expired()            -> list[NHIIdentity]   # newly expired
    list_all()                -> list[NHIIdentity]
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import crypto
from schemas import DB_PATH, NHIIdentity

_now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)
_EXPIRING_SOON_DAYS = 30


def _row_to_nhi(r: tuple) -> NHIIdentity:
    return NHIIdentity(
        nhi_id=r[0], name=r[1], nhi_type=r[2], owner=r[3], description=r[4],
        created_at=datetime.fromisoformat(r[5]),
        expires_at=datetime.fromisoformat(r[6]),
        last_used=datetime.fromisoformat(r[7]) if r[7] else None,
        status=r[8],
    )


def _fetch_one(con: sqlite3.Connection, nhi_id: str) -> NHIIdentity:
    row = con.execute(
        "SELECT nhi_id, name, nhi_type, owner, description,"
        " created_at, expires_at, last_used, status"
        " FROM nhi_identities WHERE nhi_id=?", (nhi_id,)
    ).fetchone()
    if not row:
        raise KeyError(f"NHI {nhi_id!r} not found")
    return _row_to_nhi(row)


def register(
    name: str,
    nhi_type: str,
    owner: str,
    ttl_days: int = 90,
    description: str = "",
) -> NHIIdentity:
    """Register a new NHI. ttl_days < 0 creates an already-expired identity (for seeding demos)."""
    now        = _now()
    expires_at = now + timedelta(days=ttl_days)
    soon_limit = now + timedelta(days=_EXPIRING_SOON_DAYS)

    if ttl_days <= 0:
        status = "expired"
    elif expires_at <= soon_limit:
        status = "expiring_soon"
    else:
        status = "active"

    nhi = NHIIdentity(
        nhi_id=str(uuid.uuid4()),
        name=name, nhi_type=nhi_type, owner=owner, description=description,
        created_at=now, expires_at=expires_at, last_used=None, status=status,
    )
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO nhi_identities"
        " (nhi_id, name, nhi_type, owner, description, created_at, expires_at, last_used, status)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (nhi.nhi_id, nhi.name, nhi.nhi_type, nhi.owner, nhi.description,
         nhi.created_at.isoformat(), nhi.expires_at.isoformat(), None, nhi.status),
    )
    con.commit()
    con.close()
    crypto.append_audit(json.dumps({
        "event":      "nhi_registered",
        "nhi_id":     nhi.nhi_id,
        "name":       nhi.name,
        "type":       nhi.nhi_type,
        "owner":      nhi.owner,
        "expires_at": nhi.expires_at.isoformat(),
        "status":     nhi.status,
    }))
    return nhi


def rotate(nhi_id: str, ttl_days: int = 90) -> NHIIdentity:
    """Renew an NHI's expiry window. Updates last_used and logs to audit chain."""
    now        = _now()
    new_expiry = now + timedelta(days=ttl_days)
    soon_limit = now + timedelta(days=_EXPIRING_SOON_DAYS)
    status     = "expiring_soon" if new_expiry <= soon_limit else "active"

    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE nhi_identities SET expires_at=?, status=?, last_used=? WHERE nhi_id=?",
        (new_expiry.isoformat(), status, now.isoformat(), nhi_id),
    )
    con.commit()
    nhi = _fetch_one(con, nhi_id)
    con.close()
    crypto.append_audit(json.dumps({
        "event":       "nhi_rotated",
        "nhi_id":      nhi_id,
        "name":        nhi.name,
        "new_expires": new_expiry.isoformat(),
    }))
    return nhi


def revoke(nhi_id: str) -> NHIIdentity:
    """Permanently revoke an NHI — cannot be un-revoked."""
    con = sqlite3.connect(DB_PATH)
    con.execute("UPDATE nhi_identities SET status='revoked' WHERE nhi_id=?", (nhi_id,))
    con.commit()
    nhi = _fetch_one(con, nhi_id)
    con.close()
    crypto.append_audit(json.dumps({
        "event":  "nhi_revoked",
        "nhi_id": nhi_id,
        "name":   nhi.name,
        "owner":  nhi.owner,
    }))
    return nhi


def scan_expired() -> list[NHIIdentity]:
    """Auto-mark active NHIs past their expiry as expired. Returns newly-expired list."""
    now        = _now()
    soon_limit = (now + timedelta(days=_EXPIRING_SOON_DAYS)).isoformat()
    cutoff     = now.isoformat()

    con = sqlite3.connect(DB_PATH)
    # mark truly expired
    expired_ids = [r[0] for r in con.execute(
        "SELECT nhi_id FROM nhi_identities WHERE status='active' AND expires_at <= ?",
        (cutoff,),
    ).fetchall()]
    if expired_ids:
        con.execute(
            f"UPDATE nhi_identities SET status='expired'"
            f" WHERE nhi_id IN ({','.join('?'*len(expired_ids))})",
            expired_ids,
        )
    # mark expiring-soon (active, expires within 30 days)
    con.execute(
        "UPDATE nhi_identities SET status='expiring_soon'"
        " WHERE status='active' AND expires_at <= ?",
        (soon_limit,),
    )
    con.commit()

    result = [_fetch_one(con, nid) for nid in expired_ids]
    con.close()

    if result:
        crypto.append_audit(json.dumps({
            "event":   "nhi_scan_expired",
            "count":   len(result),
            "names":   [n.name for n in result],
        }))
    return result


def list_all() -> list[NHIIdentity]:
    """Return all NHIs, auto-marking expired/expiring-soon statuses first."""
    scan_expired()
    con  = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT nhi_id, name, nhi_type, owner, description,"
        " created_at, expires_at, last_used, status"
        " FROM nhi_identities ORDER BY expires_at ASC"
    ).fetchall()
    con.close()
    return [_row_to_nhi(r) for r in rows]
