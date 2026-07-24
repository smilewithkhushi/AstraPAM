import sqlite3

from core import crypto


def test_empty_chain_is_valid(db):
    result = crypto.verify_chain()
    assert result["valid"] is True
    assert result["length"] == 0


def test_chain_valid_after_single_append(db):
    crypto.append_audit('{"event": "test"}')
    result = crypto.verify_chain()
    assert result["valid"] is True
    assert result["length"] == 1


def test_chain_valid_after_multiple_appends(db):
    for i in range(5):
        crypto.append_audit(f'{{"event": "seq_{i}"}}')
    result = crypto.verify_chain()
    assert result["valid"] is True
    assert result["length"] == 5


def test_tampered_payload_detected(db):
    crypto.append_audit('{"event": "grant_issued", "user_id": "user_001"}')
    con = sqlite3.connect(db)
    con.execute(
        "UPDATE audit_records SET payload = ? WHERE seq = 1",
        ('{"event": "grant_issued", "user_id": "attacker"}',),
    )
    con.commit()
    con.close()
    result = crypto.verify_chain()
    assert result["valid"] is False
    assert result["first_bad_seq"] == 1


def test_kem_credential_returns_correct_byte_counts(db):
    artifact = crypto.issue_credential("user_001", "grant-test-001")
    assert artifact.pubkey_bytes == 1184
    assert artifact.ciphertext_bytes == 1088
    assert artifact.shared_secret_bytes == 32
    assert "ML-KEM-768" in artifact.algorithm
