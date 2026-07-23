"""Cryptographic Bill of Materials (CBOM) scanner.

Walks all project .py files, identifies cryptographic algorithm usage, and
classifies each finding as quantum_safe / hybrid_pqc / quantum_vulnerable /
classical_symmetric. Mirrors the RBI Q-SAFE CBOM workstream.

Public API:
    scan(root: str | None = None) -> CBOMReport
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

# ── models ────────────────────────────────────────────────────────────────────

Category = Literal["quantum_safe", "hybrid_pqc", "quantum_vulnerable", "classical_symmetric"]


class CBOMEntry(BaseModel):
    file: str
    line: int
    algorithm: str
    category: Category
    reason: str


class CBOMReport(BaseModel):
    scanned_files: int
    total_findings: int
    quantum_safe_count: int
    quantum_vulnerable_count: int
    hybrid_pqc_count: int
    classical_count: int
    entries: list[CBOMEntry]
    verdict: str
    generated_at: str


# ── detection rules (specific → general; order determines priority) ───────────
# Each tuple: (compiled pattern, display name, category, reason)

_RULES: list[tuple[re.Pattern, str, Category, str]] = [
    # quantum-safe — NIST PQC standards
    (re.compile(r'ml_kem|ML.KEM|kyber', re.I),
     "ML-KEM-768 (Kyber)", "quantum_safe",
     "NIST FIPS 203 — lattice KEM, quantum-safe"),

    (re.compile(r'ml_dsa|ML.DSA|dilithium', re.I),
     "ML-DSA (Dilithium)", "quantum_safe",
     "NIST FIPS 204 — lattice signature, quantum-safe"),

    (re.compile(r'\bHKDF\b'),
     "HKDF", "quantum_safe",
     "Key derivation via SHA-2 — security follows hash security"),

    (re.compile(r'SHA.?256|SHA.?384|SHA.?512|sha256|sha384|sha512'),
     "SHA-2 (256/384/512)", "quantum_safe",
     "Grover halves preimage security: SHA-256 → 128-bit PQ margin — adequate"),

    (re.compile(r'AES.?256|aes_256', re.I),
     "AES-256", "quantum_safe",
     "Grover reduces to 128-bit effective security — adequate"),

    (re.compile(r'ChaCha20|chacha20', re.I),
     "ChaCha20", "quantum_safe",
     "256-bit symmetric stream cipher — Grover-resistant"),

    # hybrid PQC — classical EC used alongside a PQC primitive; safe in combination
    (re.compile(r'X25519|x25519'),
     "X25519 (ECDH, in hybrid)", "hybrid_pqc",
     "ECDH — quantum-vulnerable alone, but combined with ML-KEM-768 "
     "via HKDF → hybrid construction retains quantum safety"),

    # quantum-vulnerable
    (re.compile(r'\bRSA\b', re.I),
     "RSA", "quantum_vulnerable",
     "Shor's algorithm solves integer factoring in polynomial time on a CRQC"),

    (re.compile(r'\bECDSA\b', re.I),
     "ECDSA", "quantum_vulnerable",
     "Elliptic-curve discrete log — Shor-vulnerable"),

    (re.compile(r'\bDSA\b', re.I),
     "DSA", "quantum_vulnerable",
     "Discrete-log problem — Shor-vulnerable"),

    (re.compile(r'DiffieHellman|diffie.hellman|\bDHE\b|\bECDHE\b', re.I),
     "DH/ECDHE", "quantum_vulnerable",
     "Discrete-log — Shor-vulnerable"),

    (re.compile(r'\bRC4\b|arcfour', re.I),
     "RC4", "quantum_vulnerable",
     "Classically broken stream cipher"),

    (re.compile(r'\b3DES\b|TripleDES|triple.des', re.I),
     "3DES", "quantum_vulnerable",
     "56-bit effective key — Grover weakens further"),

    (re.compile(r'\bMD5\b'),
     "MD5", "quantum_vulnerable",
     "Cryptographically broken — collision attacks practical"),

    (re.compile(r'\bSHA-?1\b(?!\d)'),
     "SHA-1", "quantum_vulnerable",
     "Collision attacks demonstrated — deprecated for cryptographic use"),

    # classical symmetric — adequate today, monitor under quantum threat
    (re.compile(r'AES.?128|aes_128', re.I),
     "AES-128", "classical_symmetric",
     "Grover reduces effective security to 64-bit — upgrade to AES-256 recommended"),
]

_SKIP_DIRS = {'.venv', '__pycache__', '.git', 'data', 'database', 'node_modules', 'info'}


def _scan_file(path: Path, root: Path) -> list[CBOMEntry]:
    rel = str(path.relative_to(root))
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []

    entries: list[CBOMEntry] = []
    for lineno, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue  # skip comment-only lines to reduce doc noise

        line_hits: list[CBOMEntry] = []
        for pattern, algo, category, reason in _RULES:
            if pattern.search(line):
                line_hits.append(CBOMEntry(
                    file=rel, line=lineno,
                    algorithm=algo, category=category, reason=reason,
                ))

        # Subsumption: if a quantum_safe/hybrid algo name contains the name of a
        # flagged vulnerable algo on the same line, drop the vulnerable one.
        # Example: ML-DSA match prevents a spurious DSA match on the same line.
        safe_names = {m.algorithm for m in line_hits
                      if m.category in ("quantum_safe", "hybrid_pqc")}
        for hit in line_hits:
            if hit.category == "quantum_vulnerable":
                if any(hit.algorithm in s for s in safe_names):
                    continue
            entries.append(hit)

    return entries


def scan(root: str | None = None) -> CBOMReport:
    """Scan all project .py files for cryptographic algorithm usage."""
    base = Path(root) if root else Path(__file__).parent.parent
    all_entries: list[CBOMEntry] = []
    file_count = 0

    for py_file in sorted(base.rglob("*.py")):
        if any(skip in py_file.parts for skip in _SKIP_DIRS):
            continue
        if py_file.name == "cbom.py":
            continue  # skip self — rule strings would self-trigger
        file_count += 1
        all_entries.extend(_scan_file(py_file, base))

    # one entry per (file, algorithm) pair — keep first occurrence line
    seen: set[tuple[str, str]] = set()
    unique: list[CBOMEntry] = []
    for e in sorted(all_entries, key=lambda x: (x.file, x.algorithm, x.line)):
        key = (e.file, e.algorithm)
        if key not in seen:
            seen.add(key)
            unique.append(e)

    qs  = sum(1 for e in unique if e.category == "quantum_safe")
    qv  = sum(1 for e in unique if e.category == "quantum_vulnerable")
    hyb = sum(1 for e in unique if e.category == "hybrid_pqc")
    cls = sum(1 for e in unique if e.category == "classical_symmetric")

    if qv == 0:
        verdict = (
            f"QUANTUM-SAFE — {qs} quantum-safe primitive(s), {hyb} hybrid-PQC "
            "construction(s), 0 quantum-vulnerable algorithms detected. "
            "AstraPAM's cryptographic posture is NIST PQC-aligned."
        )
    else:
        verdict = (
            f"ACTION REQUIRED — {qv} quantum-vulnerable algorithm(s) detected. "
            "Migrate to NIST PQC standards (ML-KEM / ML-DSA) before CRQC threat materialises."
        )

    return CBOMReport(
        scanned_files=file_count,
        total_findings=len(unique),
        quantum_safe_count=qs,
        quantum_vulnerable_count=qv,
        hybrid_pqc_count=hyb,
        classical_count=cls,
        entries=unique,
        verdict=verdict,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
