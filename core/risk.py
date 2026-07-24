"""Behavioral risk engine — LSTM-AE inference, SHAP explainability, attack tags.

Public API:
    score(features: dict[str, float]) -> RiskResult
    decision_from_score(s: float) -> Decision
"""
from __future__ import annotations

import json
import os
import pickle
from functools import lru_cache
from pathlib import Path

import numpy as np
import shap
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

from .schemas import AttackTag, Decision, RiskFactor, RiskResult

MODEL_DIR = Path("data/model")
_FALLBACK_MODEL_DIR = Path("/tmp/astra_model")

# feature names must match what train.py produces
FEATURES: list[str] = [
    "logon_count", "after_hours", "unique_pcs",
    "device_events", "file_events", "http_events", "email_events",
]
SEQ_LEN = 5
HIDDEN = 32

_THRESH_THROTTLE = float(os.getenv("RISK_THRESHOLD_THROTTLE", "0.40"))
_THRESH_STEP_UP  = float(os.getenv("RISK_THRESHOLD_STEP_UP",  "0.65"))
_THRESH_DENY     = float(os.getenv("RISK_THRESHOLD_DENY",     "0.80"))

# rule-based tags on raw (unscaled) feature values — not ML outputs, framed honestly
_TAG_RULES: list[tuple[AttackTag, str, float]] = [
    ("OFF_HOURS_ACTIVITY",   "after_hours",   0.30),   # >30% logons outside 8am–6pm
    ("ANOMALOUS_LOCATION",   "unique_pcs",    2.0),    # accessing >2 distinct PCs
    ("MASS_DATA_EXPORT",     "file_events",   50.0),   # >50 file events in session
    ("PRIVILEGE_ESCALATION", "device_events", 2.0),    # >2 USB/device events
]


# ── model definition ──────────────────────────────────────────────────────────

class LSTMAe(nn.Module):
    def __init__(self, n_features: int = len(FEATURES), hidden: int = HIDDEN):
        super().__init__()
        self.enc = nn.LSTM(n_features, hidden, batch_first=True)
        self.dec = nn.LSTM(hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, n_features)

    def forward(self, x: torch.Tensor) -> torch.Tensor:  # (B, T, F) → (B, T, F)
        _, (h, c) = self.enc(x)
        dec_in = h.permute(1, 0, 2).expand(-1, x.size(1), -1).contiguous()
        decoded, _ = self.dec(dec_in, (h, c))
        return self.out(decoded)


# ── artifact loading ──────────────────────────────────────────────────────────

def _bootstrap_synthetic(target_dir: Path) -> None:
    """Train a small synthetic LSTM-AE and save artifacts to target_dir."""
    import torch.nn.functional as F

    rng = np.random.default_rng(42)
    rows = []
    for uid in range(300):
        is_mal = uid >= 260
        for _ in range(30):
            if is_mal:
                rows.append([rng.integers(1, 3), rng.uniform(0.6, 1.0), rng.integers(2, 5),
                              rng.integers(3, 12), rng.integers(80, 200), rng.integers(1, 5), rng.integers(0, 3)])
            else:
                rows.append([rng.integers(1, 8), rng.uniform(0.0, 0.15), rng.integers(1, 2),
                              rng.integers(0, 2), rng.integers(5, 30), rng.integers(20, 100), rng.integers(5, 25)])

    X_raw = np.array(rows, dtype=np.float32)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)
    X_norm = X_scaled[:260 * 30]

    seqs = np.stack([X_norm[i: i + SEQ_LEN] for i in range(len(X_norm) - SEQ_LEN + 1)]).astype(np.float32)

    torch.manual_seed(42)
    model = LSTMAe()
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    X_t = torch.tensor(seqs)
    model.train()
    for _ in range(20):
        idx = torch.randperm(len(X_t))
        for i in range(0, len(X_t), 64):
            b = X_t[idx[i: i + 64]]
            loss = F.mse_loss(model(b), b)
            opt.zero_grad(); loss.backward(); opt.step()
    model.eval()

    with torch.no_grad():
        errs = ((model(X_t) - X_t) ** 2).mean(dim=(1, 2)).numpy()
    mu, sigma = float(errs.mean()), float(errs.std())

    target_dir.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), target_dir / "lstm_ae.pt")
    with open(target_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    with open(target_dir / "meta.json", "w") as f:
        json.dump({"features": FEATURES, "hidden": HIDDEN, "seq_len": SEQ_LEN,
                   "error_mu": mu, "error_sigma": sigma}, f)


@lru_cache(maxsize=1)
def _load() -> tuple[LSTMAe, object, dict]:
    """Lazy-load weights, scaler, meta once. Auto-bootstraps synthetic model if missing."""
    # Prefer committed repo artifacts; fall back to a writable temp location.
    model_dir = MODEL_DIR if (MODEL_DIR / "lstm_ae.pt").exists() else _FALLBACK_MODEL_DIR

    if not (model_dir / "lstm_ae.pt").exists():
        _bootstrap_synthetic(model_dir)

    with open(model_dir / "meta.json") as f:
        meta = json.load(f)
    with open(model_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    model = LSTMAe(n_features=len(meta["features"]), hidden=meta["hidden"])
    model.load_state_dict(torch.load(model_dir / "lstm_ae.pt", map_location="cpu"))
    model.eval()
    return model, scaler, meta


# ── internals ─────────────────────────────────────────────────────────────────

def _to_seq(raw: dict[str, float], feat_names: list[str], scaler: object) -> np.ndarray:
    """Raw feature dict → scaled (1, SEQ_LEN, n_features) array."""
    vec = np.array([raw.get(f, 0.0) for f in feat_names], dtype=np.float32)
    scaled = scaler.transform(vec.reshape(1, -1))[0]  # type: ignore[attr-defined]
    return np.tile(scaled, (SEQ_LEN, 1))[np.newaxis].astype(np.float32)  # (1, T, F)


def _recon_error(model: LSTMAe, x: np.ndarray) -> float:
    t = torch.tensor(x)
    with torch.no_grad():
        return float(((model(t) - t) ** 2).mean().item())


def _calibrated_score(err: float, mu: float, sigma: float) -> float:
    """Map MSE to 0–1 via sigmoid centred on the normal distribution."""
    z = (err - mu) / max(sigma, 1e-6)
    return float(1.0 / (1.0 + np.exp(-3.0 * z)))


def _shap_factors(
    raw: dict[str, float],
    model: LSTMAe,
    scaler: object,
    meta: dict,
) -> list[RiskFactor]:
    feat_names: list[str] = meta["features"]
    seq_len = meta.get("seq_len", SEQ_LEN)

    def _scorer(X: np.ndarray) -> np.ndarray:
        X_seq = np.tile(X[:, np.newaxis, :], (1, seq_len, 1)).astype(np.float32)
        with torch.no_grad():
            t = torch.tensor(X_seq)
            return ((model(t) - t) ** 2).mean(dim=(1, 2)).numpy()

    x_scaled = scaler.transform(  # type: ignore[attr-defined]
        np.array([[raw.get(f, 0.0) for f in feat_names]])
    ).astype(np.float32)
    background = np.zeros((1, len(feat_names)), dtype=np.float32)

    explainer = shap.KernelExplainer(_scorer, background)
    sv = explainer.shap_values(x_scaled, nsamples=64, silent=True)
    sv = np.asarray(sv).flatten()

    top = np.argsort(np.abs(sv))[::-1][:3]
    return [RiskFactor(feature=feat_names[i], contribution=round(float(sv[i]), 4)) for i in top]


def _tags(raw: dict[str, float]) -> list[AttackTag]:
    return [tag for tag, feat, thresh in _TAG_RULES if raw.get(feat, 0.0) >= thresh]


def decision_from_score(s: float) -> Decision:
    if s >= _THRESH_DENY:
        return "deny"
    if s >= _THRESH_STEP_UP:
        return "step_up"
    if s >= _THRESH_THROTTLE:
        return "throttle"
    return "allow"


# ── public API ────────────────────────────────────────────────────────────────

def score(features: dict[str, float]) -> RiskResult:
    """Score a privileged session. Returns RiskResult with decision, SHAP factors, attack tags."""
    model, scaler, meta = _load()
    seq = _to_seq(features, meta["features"], scaler)
    err = _recon_error(model, seq)
    s = _calibrated_score(err, meta.get("error_mu", 0.1), meta.get("error_sigma", 0.05))
    factors = _shap_factors(features, model, scaler, meta)
    tags = _tags(features)
    return RiskResult(
        score=round(s, 4),
        decision=decision_from_score(s),
        top_factors=factors,
        attack_tags=tags,
    )
