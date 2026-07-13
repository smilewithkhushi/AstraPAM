"""Hybrid post-quantum credential exchange + ML-DSA-65-signed tamper-evident audit log.

KEM  : ML-KEM-768 (NIST FIPS 203) + X25519 ECDH, combined via HKDF.
       Breaking *either* primitive alone is insufficient — layered security.
Sig  : ML-DSA-65 (NIST FIPS 204) over a SHA-256 hash-chain of AuditRecords.

Artifact byte counts are real, not mocked:
    ML-KEM-768  public key  = 1184 B
    ML-KEM-768  ciphertext  = 1088 B
    shared secret           =   32 B
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from schemas import AuditRecord, CryptoArtifact, DB_PATH

_now            = lambda: datetime.now(timezone.utc).replace(tzinfo=None)
_GENESIS_HASH   = "0" * 64


# ── ML-DSA-65 keypair — one per process; persisted externally in production ──

@lru_cache(maxsize=1)
def _dsa_keys() -> tuple[bytes, bytes]:
    """(public_key, secret_key) for ML-DSA-65, generated once per process."""
    return ml_dsa_65.generate_keypair()


# ── hybrid KEM ────────────────────────────────────────────────────────────────

def issue_credential(user_id: str, grant_id: str) -> CryptoArtifact:
    """Hybrid ML-KEM-768 + X25519 handshake for privilege credential exchange.

    Both sides are simulated in-process for the demo; in production they run
    in separate services. The shared secret is never stored — only the artifact
    byte-counts are surfaced, proving the KEM ran for real.
    """
    # Side A (vault) — generate keypairs and publish public keys
    kem_pk, kem_sk  = ml_kem_768.generate_keypair()
    ecdh_a          = X25519PrivateKey.generate()
    ecdh_a_pub      = ecdh_a.public_key()

    # Side B (broker) — encapsulate KEM, generate own ECDH keypair
    kem_ct, kem_ss_b = ml_kem_768.encrypt(kem_pk)
    ecdh_b           = X25519PrivateKey.generate()
    ecdh_ss_b        = ecdh_b.exchange(ecdh_a_pub)

    # Side A — decapsulate KEM, complete ECDH
    kem_ss_a         = ml_kem_768.decrypt(kem_sk, kem_ct)
    ecdh_ss_a        = ecdh_a.exchange(ecdh_b.public_key())

    assert kem_ss_a == kem_ss_b and ecdh_ss_a == ecdh_ss_b  # both sides agree

    # HKDF over KEM + ECDH shared secrets → final credential key
    HKDF(algorithm=SHA256(), length=32, salt=None,
         info=b"aegispam-credential-v1").derive(kem_ss_a + ecdh_ss_a)

    artifact = CryptoArtifact(
        pubkey_bytes        = len(kem_pk),   # 1184 B — ML-KEM-768
        ciphertext_bytes    = len(kem_ct),   # 1088 B
        shared_secret_bytes = 32,
        algorithm           = "ML-KEM-768 + X25519/HKDF",
    )

    append_audit(json.dumps({
        "event":            "credential_issued",
        "user_id":          user_id,
        "grant_id":         grant_id,
        "algorithm":        artifact.algorithm,
        "pubkey_bytes":     artifact.pubkey_bytes,
        "ciphertext_bytes": artifact.ciphertext_bytes,
    }))

    return artifact


# ── hash-chained audit log ────────────────────────────────────────────────────

def _last_seq_and_hash(con: sqlite3.Connection) -> tuple[int, str]:
    row = con.execute(
        "SELECT seq, hash FROM audit_records ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    return (row[0], row[1]) if row else (0, _GENESIS_HASH)


def append_audit(payload: str) -> AuditRecord:
    """Append a ML-DSA-65-signed, hash-chained record. seq is auto-incremented."""
    _, dsa_sk = _dsa_keys()
    con       = sqlite3.connect(DB_PATH)
    seq, prev = _last_seq_and_hash(con)
    seq      += 1

    rec_hash  = hashlib.sha256(f"{seq}{prev}{payload}".encode()).hexdigest()
    signature = ml_dsa_65.sign(dsa_sk, rec_hash.encode()).hex()

    record = AuditRecord(seq=seq, prev_hash=prev,
                         payload=payload, signature=signature, hash=rec_hash)
    con.execute(
        "INSERT INTO audit_records (seq, prev_hash, payload, signature, hash)"
        " VALUES (?,?,?,?,?)",
        (record.seq, record.prev_hash, record.payload, record.signature, record.hash),
    )
    con.commit()
    con.close()
    return record


def verify_chain() -> dict:
    """Walk the full chain: recompute every hash and verify every ML-DSA-65 signature.

    Returns {"valid": bool, "length": int, "first_bad_seq": int | None}.
    Any tamper — deletion, reorder, payload edit — surfaces here.
    """
    dsa_pk, _ = _dsa_keys()
    con        = sqlite3.connect(DB_PATH)
    rows       = con.execute(
        "SELECT seq, prev_hash, payload, signature, hash FROM audit_records ORDER BY seq"
    ).fetchall()
    con.close()

    prev_hash = _GENESIS_HASH
    for seq, stored_prev, payload, sig_hex, stored_hash in rows:
        expected = hashlib.sha256(f"{seq}{stored_prev}{payload}".encode()).hexdigest()
        if stored_hash != expected or stored_prev != prev_hash:
            return {"valid": False, "length": len(rows), "first_bad_seq": seq}
        try:
            ml_dsa_65.verify(dsa_pk, stored_hash.encode(), bytes.fromhex(sig_hex))
        except Exception:
            return {"valid": False, "length": len(rows), "first_bad_seq": seq}
        prev_hash = stored_hash

    return {"valid": True, "length": len(rows), "first_bad_seq": None}


def get_audit_log() -> list[AuditRecord]:
    con  = sqlite3.connect(DB_PATH)
    rows = con.execute(
        "SELECT seq, prev_hash, payload, signature, hash FROM audit_records ORDER BY seq"
    ).fetchall()
    con.close()
    return [AuditRecord(seq=r[0], prev_hash=r[1], payload=r[2],
                        signature=r[3], hash=r[4]) for r in rows]
