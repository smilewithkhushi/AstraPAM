import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

from core import reconcile


_now = lambda: datetime.now(timezone.utc).replace(tzinfo=None)


def _insert_action(con, action_id, channel, amount, seconds_ago=60):
    ts = (_now() - timedelta(seconds=seconds_ago)).isoformat()
    con.execute(
        "INSERT INTO privileged_actions (action_id, user_id, channel, amount, timestamp)"
        " VALUES (?,?,?,?,?)",
        (action_id, "user_007", channel, amount, ts),
    )


def _insert_ledger(con, action_id, amount):
    con.execute(
        "INSERT INTO ledger_entries (entry_id, action_id, amount, timestamp)"
        " VALUES (?,?,?,?)",
        (str(uuid.uuid4()), action_id, amount, _now().isoformat()),
    )


def test_unmatched_swift_action_raises_critical_alert(db):
    aid = str(uuid.uuid4())
    con = sqlite3.connect(db)
    _insert_action(con, aid, "swift_like", 14000)
    con.commit()
    con.close()
    alerts = reconcile.run(sla_seconds=0)
    alert = next((a for a in alerts if a.action_id == aid), None)
    assert alert is not None
    assert alert.severity == "critical"


def test_unmatched_cbs_action_raises_high_alert(db):
    aid = str(uuid.uuid4())
    con = sqlite3.connect(db)
    _insert_action(con, aid, "cbs", 50000)
    con.commit()
    con.close()
    alerts = reconcile.run(sla_seconds=0)
    alert = next((a for a in alerts if a.action_id == aid), None)
    assert alert is not None
    assert alert.severity == "high"


def test_matched_action_raises_no_alert(db):
    aid = str(uuid.uuid4())
    con = sqlite3.connect(db)
    _insert_action(con, aid, "swift_like", 14000)
    _insert_ledger(con, aid, 14000)
    con.commit()
    con.close()
    alerts = reconcile.run(sla_seconds=0)
    assert not any(a.action_id == aid for a in alerts)


def test_alert_not_duplicated_on_second_run(db):
    aid = str(uuid.uuid4())
    con = sqlite3.connect(db)
    _insert_action(con, aid, "swift_like", 14000)
    con.commit()
    con.close()
    reconcile.run(sla_seconds=0)
    second_run = reconcile.run(sla_seconds=0)
    assert not any(a.action_id == aid for a in second_run)


def test_action_within_sla_not_alerted(db):
    aid = str(uuid.uuid4())
    con = sqlite3.connect(db)
    _insert_action(con, aid, "swift_like", 14000, seconds_ago=0)
    con.commit()
    con.close()
    alerts = reconcile.run(sla_seconds=30)
    assert not any(a.action_id == aid for a in alerts)
