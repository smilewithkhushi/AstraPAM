import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from core import broker
from core.schemas import AccessRequest, BankUser, RiskFactor, RiskResult


_ALLOW = RiskResult(score=0.10, decision="allow",    top_factors=[], attack_tags=[])
_DENY  = RiskResult(score=0.92, decision="deny",     top_factors=[], attack_tags=[])
_STEP  = RiskResult(score=0.70, decision="step_up",  top_factors=[], attack_tags=[])

_REQ = AccessRequest(
    user_id="user_001",
    target="core_banking_prod",
    action_type="read",
    requested_at=datetime.now(timezone.utc),
    correlation_id="test-cid-001",
)


def test_frozen_user_denied_without_risk_scoring(db):
    frozen = BankUser(
        user_id="user_frozen", name="Frozen", role_id="T1_TELLER",
        branch_sol="SOL001", created_at=datetime(2024, 1, 1), status="FROZEN",
    )
    req = AccessRequest(
        user_id="user_frozen", target="core_banking_prod",
        action_type="read", requested_at=datetime.now(timezone.utc),
    )
    with patch("core.broker.get_user", return_value=frozen):
        with patch("core.broker.risk_engine.score") as mock_score:
            result = broker.request_access(req, {})
    assert result["status"] == "denied"
    mock_score.assert_not_called()


def test_allow_decision_issues_grant(db):
    with patch("core.broker.risk_engine.score", return_value=_ALLOW):
        result = broker.request_access(_REQ, {})
    assert result["status"] == "granted"
    grant_id = result["grant"]["grant_id"]
    con = sqlite3.connect(db)
    row = con.execute(
        "SELECT revoked FROM ephemeral_grants WHERE grant_id=?", (grant_id,)
    ).fetchone()
    con.close()
    assert row is not None and row[0] == 0


def test_deny_decision_issues_no_grant(db):
    with patch("core.broker.risk_engine.score", return_value=_DENY):
        result = broker.request_access(_REQ, {})
    assert result["status"] == "denied"
    con = sqlite3.connect(db)
    count = con.execute("SELECT COUNT(*) FROM ephemeral_grants").fetchone()[0]
    con.close()
    assert count == 0


def test_step_up_decision_issues_no_grant(db):
    with patch("core.broker.risk_engine.score", return_value=_STEP):
        result = broker.request_access(_REQ, {})
    assert result["status"] == "step_up_required"


def test_revoke_marks_grant_revoked(db):
    with patch("core.broker.risk_engine.score", return_value=_ALLOW):
        result = broker.request_access(_REQ, {})
    grant_id = result["grant"]["grant_id"]
    broker.revoke(grant_id)
    con = sqlite3.connect(db)
    row = con.execute(
        "SELECT revoked FROM ephemeral_grants WHERE grant_id=?", (grant_id,)
    ).fetchone()
    con.close()
    assert row[0] == 1


def test_expire_stale_revokes_past_ttl_grants(db):
    past = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=600)).isoformat()
    con = sqlite3.connect(db)
    con.execute(
        "INSERT INTO ephemeral_grants (grant_id, user_id, target, expires_at, revoked, correlation_id)"
        " VALUES (?,?,?,?,0,?)",
        ("stale-001", "user_001", "core_banking_prod", past, "cid-stale"),
    )
    con.commit()
    con.close()
    revoked = broker.expire_stale()
    assert "stale-001" in revoked
    con = sqlite3.connect(db)
    row = con.execute(
        "SELECT revoked FROM ephemeral_grants WHERE grant_id='stale-001'"
    ).fetchone()
    con.close()
    assert row[0] == 1


def test_break_glass_issues_grant_regardless_of_risk(db):
    with patch("core.broker.risk_engine.score", return_value=_DENY):
        result = broker.break_glass_access(
            "user_001", "core_banking_prod", "Emergency override", {}
        )
    assert result["status"] == "break_glass_granted"
    assert result["grant"]["break_glass"] is True
