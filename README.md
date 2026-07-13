# AegisPAM

Zero-Standing-Privilege PAM control plane for Indian banks — FinSpark'26 Problem Statement 1.

Detects the **absence** of a CBS ledger entry for privileged financial actions (the PNB LoU signal), not just anomalous-looking payments. Couples that with a real-time behavioral risk AI, JIT ephemeral grants, and post-quantum cryptography.

---

## Quick start

```bash
cp .env.example .env        # configure if needed (defaults work out of the box)
chmod +x script.sh
./script.sh
```

That's it. `script.sh` will:

1. Create a Python venv at `.venv/` if it doesn't exist
2. Install all dependencies from `requirements.txt`
3. Source `.env`
4. Start **Mock CBS** on `:8001`
5. Start **Control API** on `:8000`
6. Start **Streamlit Dashboard** on `:8501`

Once running:

| Service | URL |
|---|---|
| Dashboard | http://localhost:8501 |
| Control API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| Mock CBS | http://localhost:8001 |

Press **Ctrl+C** to stop all three services cleanly.

---

## Train the risk model (optional)

The dashboard works immediately with a synthetic model. For real AUC numbers, train on CMU CERT r4.2:

```bash
# quick demo — synthetic data, no download needed
python train.py --synth

# production — download CERT r4.2 first, place CSVs under data/cert_r4.2/
python train.py
```

Saved to `data/model/` (gitignored). Reports AUC and FPR@95%TPR.

---

## Demo script (judges walkthrough)

Follow these steps in the Dashboard sidebar:

1. **Score normal session** — risk score near 0, decision: ALLOW
2. **Score malicious session** — after-hours + 4 PCs + mass file export → risk near 1, DENY, SHAP chart explains why
3. **Issue SWIFT LoU (no ledger)** — simulates the PNB pattern: payment goes out-of-band, no CBS ledger entry
4. **Run reconciliation (SLA=0s)** — cross-channel diff fires a CRITICAL alert with remediation playbook
5. **Issue PQC credential** — real ML-KEM-768 + X25519/HKDF handshake; byte-counts prove it ran (1184B pubkey, 1088B ciphertext)
6. **Tamper audit record → Verify chain** — ML-DSA-65 signature check catches the tamper immediately

---

## Architecture

```
schemas.py      all Pydantic v2 contracts + SQLite init
main.py         FastAPI control plane (port 8000)
mock_cbs.py     fake Core Banking System (port 8001)
broker.py       JIT grant lifecycle — Zero Standing Privilege
risk.py         LSTM-AE behavioral risk AI + SHAP explainability
reconcile.py    cross-channel reconciliation engine
crypto.py       ML-KEM-768 + X25519 hybrid KEM, ML-DSA-65 audit log
dashboard.py    Streamlit unified view
train.py        one-off LSTM-AE training (CMU CERT r4.2 or --synth)
```

**Stack:** Python 3.12+, FastAPI, Streamlit, SQLite, PyTorch (CPU), SHAP, pqcrypto (NIST FIPS 203/204), Pydantic v2

**Decision thresholds:** allow < 0.40 ≤ throttle < 0.65 ≤ step_up < 0.80 ≤ deny

---

## What is real vs. simulated

| Component | Status | Notes |
|---|---|---|
| ML-KEM-768 key exchange | **Real** | `pqcrypto` — NIST FIPS 203 byte-counts (1184B pubkey, 1088B ciphertext) |
| ML-DSA-65 audit signatures | **Real** | Every audit record is signed; `verify_chain()` checks all sigs |
| LSTM-AE risk model | **Real** | PyTorch model trained on CMU CERT r4.2 (or `--synth` for demo); SHAP KernelExplainer attribution |
| Cross-channel reconciliation | **Real** | SQL diff of `privileged_actions` vs `ledger_entries`; absence-of-entry detection |
| JIT ephemeral grants + TTL | **Real** | SQLite-backed, auto-revoked, rate-cap enforced on CBS |
| Core Banking System (CBS) | **Simulated** | `mock_cbs.py` — in-memory FastAPI server on `:8001` |
| SWIFT network | **Simulated** | `/swift/action` endpoint on mock CBS; represents out-of-band channel |
| Real bank integration | **Out of scope** | No Finacle / FLEXCUBE / BaNCS connection |
| Multi-tenancy / Kubernetes | **Out of scope** | Single-node localhost demo only |
| PCI-DSS / RBI compliance mapping | **Out of scope** | Pitch slide only — not enforced as code |

---

## Run the smoke test

Verifies all phase acceptance criteria headlessly (no dashboard required):

```bash
python smoke.py
```

Starts its own isolated services on ports 8000/8001, asserts every outcome, cleans up. Exit 0 = all pass.
