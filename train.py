"""One-off LSTM-AE training on CMU CERT r4.2 insider-threat dataset.

Dataset: https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247
Place the extracted CSV files in  data/cert_r4.2/  then run:
    python train.py

For demo / CI without CERT data:
    python train.py --synth      (synthetic data, reports no CERT metrics)

Honesty gate: reports AUC and FPR@95%TPR — never raw accuracy on imbalanced data.
Saves artifacts to data/model/ (gitignored).
"""
from __future__ import annotations

import argparse
import json
import os
import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from risk import FEATURES, HIDDEN, LSTMAe, MODEL_DIR, SEQ_LEN

SEED = 42
EPOCHS = 30
BATCH = 64


# ── CERT feature engineering ──────────────────────────────────────────────────

def _parse_dt(s: str) -> pd.Timestamp:
    return pd.to_datetime(s, format="%m/%d/%Y %H:%M:%S", errors="coerce")


def _after_hours(dt: pd.Timestamp) -> float:
    return float(dt.hour < 8 or dt.hour >= 18)


def load_cert(data_dir: str) -> tuple[pd.DataFrame, set[str]]:
    """Aggregate CERT r4.2 CSVs → per-user per-day feature DataFrame."""
    d = Path(data_dir)

    logon = pd.read_csv(d / "logon.csv", usecols=["date", "user", "pc", "activity"])
    logon["dt"] = logon["date"].apply(_parse_dt)
    logon["day"] = logon["dt"].dt.date
    logon = logon[logon["activity"].str.lower() == "logon"]
    agg = logon.groupby(["user", "day"]).agg(
        logon_count=("pc", "count"),
        after_hours=("dt", lambda x: x.apply(_after_hours).mean()),
        unique_pcs=("pc", "nunique"),
    ).reset_index()

    for fname, col in [("device.csv", "device_events"), ("file.csv", "file_events"),
                       ("http.csv", "http_events"), ("email.csv", "email_events")]:
        tmp = pd.read_csv(d / fname, usecols=["date", "user"])
        tmp["day"] = tmp["date"].apply(_parse_dt).dt.date
        cnt = tmp.groupby(["user", "day"]).size().reset_index(name=col)
        agg = agg.merge(cnt, on=["user", "day"], how="left")

    agg = agg.fillna(0)

    malicious: set[str] = set()
    for candidate in [d / "answers" / "insiders.csv", d / "insiders.csv"]:
        if candidate.exists():
            ans = pd.read_csv(candidate)
            col = next((c for c in ans.columns if "user" in c.lower()), None)
            if col:
                malicious = set(ans[col].dropna().unique())
            break

    return agg, malicious


# ── synthetic data fallback ───────────────────────────────────────────────────

def generate_synth(n_normal: int = 800, n_mal: int = 50, days: int = 60) -> tuple[pd.DataFrame, set[str]]:
    """Synthetic CERT-like data. For demo only — do not report as CERT metrics."""
    rng = np.random.default_rng(SEED)
    rows, malicious = [], set()
    for uid in range(n_normal + n_mal):
        user = f"USR{uid:04d}"
        is_mal = uid >= n_normal
        if is_mal:
            malicious.add(user)
        for day in pd.date_range("2010-01-01", periods=days):
            if is_mal:
                rows.append({"user": user, "day": day.date(),
                              "logon_count": int(rng.integers(1, 3)),
                              "after_hours":  float(rng.uniform(0.6, 1.0)),
                              "unique_pcs":   int(rng.integers(2, 5)),
                              "device_events": int(rng.integers(3, 12)),
                              "file_events":  int(rng.integers(80, 200)),
                              "http_events":  int(rng.integers(1, 5)),
                              "email_events": int(rng.integers(0, 3))})
            else:
                rows.append({"user": user, "day": day.date(),
                              "logon_count": int(rng.integers(1, 8)),
                              "after_hours":  float(rng.uniform(0.0, 0.15)),
                              "unique_pcs":   int(rng.integers(1, 2)),
                              "device_events": int(rng.integers(0, 2)),
                              "file_events":  int(rng.integers(5, 30)),
                              "http_events":  int(rng.integers(20, 100)),
                              "email_events": int(rng.integers(5, 25))})
    return pd.DataFrame(rows), malicious


# ── sequences ─────────────────────────────────────────────────────────────────

def build_sequences(df: pd.DataFrame, malicious: set[str]) -> tuple[np.ndarray, np.ndarray]:
    """Sliding-window sequences of shape (n, SEQ_LEN, n_features)."""
    X_norm, X_mal = [], []
    for user, grp in df.sort_values(["user", "day"]).groupby("user"):
        vals = grp[FEATURES].values.astype(np.float32)
        for i in range(len(vals) - SEQ_LEN + 1):
            seq = vals[i: i + SEQ_LEN]
            (X_mal if user in malicious else X_norm).append(seq)
    return (np.array(X_norm),
            np.array(X_mal) if X_mal else np.empty((0, SEQ_LEN, len(FEATURES)), dtype=np.float32))


# ── training ──────────────────────────────────────────────────────────────────

def train(X_normal: np.ndarray, epochs: int) -> LSTMAe:
    torch.manual_seed(SEED)
    model = LSTMAe()
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    X = torch.tensor(X_normal)
    model.train()
    for ep in range(epochs):
        idx = torch.randperm(len(X))
        loss_sum = 0.0
        for i in range(0, len(X), BATCH):
            b = X[idx[i: i + BATCH]]
            loss = nn.functional.mse_loss(model(b), b)
            opt.zero_grad(); loss.backward(); opt.step()
            loss_sum += loss.item()
        if (ep + 1) % 10 == 0:
            print(f"  epoch {ep+1:3d}/{epochs}  loss={loss_sum / max(1, len(X)//BATCH):.5f}")
    model.eval()
    return model


def _errors(model: LSTMAe, X: np.ndarray) -> np.ndarray:
    with torch.no_grad():
        t = torch.tensor(X)
        return ((model(t) - t) ** 2).mean(dim=(1, 2)).numpy()


# ── evaluation ────────────────────────────────────────────────────────────────

def evaluate(model: LSTMAe, X_norm: np.ndarray, X_mal: np.ndarray) -> dict:
    en = _errors(model, X_norm[:3000])   # cap to avoid OOM
    em = _errors(model, X_mal)
    scores = np.concatenate([en, em])
    labels = np.concatenate([np.zeros(len(en)), np.ones(len(em))])
    auc = float(roc_auc_score(labels, scores))
    thresh = float(np.percentile(em, 5))         # threshold at 95th pct of mal errors
    fpr = float((en > thresh).mean())
    return {"auc": round(auc, 4), "fpr_at_95tpr": round(fpr, 4)}


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/cert_r4.2")
    ap.add_argument("--synth", action="store_true",
                    help="use synthetic data (demo only — no real CERT metrics)")
    ap.add_argument("--epochs", type=int, default=EPOCHS)
    args = ap.parse_args()

    print("AstraPAM — LSTM-AE training")

    if args.synth:
        print("  [demo mode] generating synthetic CERT-like data")
        df, malicious = generate_synth()
    else:
        if not Path(args.data_dir).exists():
            print(f"\n[error] CERT data not found at {args.data_dir}/")
            print("  Download: https://kilthub.cmu.edu/articles/dataset/12841247")
            print("  Demo:     python train.py --synth")
            sys.exit(1)
        print(f"  loading CERT r4.2 from {args.data_dir}/")
        df, malicious = load_cert(args.data_dir)

    print(f"  users={df['user'].nunique()}  malicious={len(malicious)}  rows={len(df)}")

    scaler = StandardScaler()
    df[FEATURES] = scaler.fit_transform(df[FEATURES].values)

    X_norm, X_mal = build_sequences(df, malicious)
    print(f"  sequences  normal={len(X_norm)}  malicious={len(X_mal)}")

    print(f"\n  training (seed={SEED}, epochs={args.epochs})")
    model = train(X_norm, args.epochs)

    # calibration constants saved to meta so risk.py can normalise scores
    errors_norm = _errors(model, X_norm)
    mu, sigma = float(errors_norm.mean()), float(errors_norm.std())

    metrics: dict = {}
    if len(X_mal) > 0:
        metrics = evaluate(model, X_norm, X_mal)
        print(f"\n  AUC        : {metrics['auc']}")
        print(f"  FPR@95%TPR : {metrics['fpr_at_95tpr']}")
        if metrics["auc"] < 0.70:
            print("  [WARNING] AUC < 0.70 — model may underperform; check class balance.")
    else:
        print("  [skip] no malicious sequences — skipping evaluation")

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), MODEL_DIR / "lstm_ae.pt")
    with open(MODEL_DIR / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    meta = {"features": FEATURES, "hidden": HIDDEN, "seq_len": SEQ_LEN,
            "error_mu": mu, "error_sigma": sigma, **metrics}
    with open(MODEL_DIR / "meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n  artifacts saved → {MODEL_DIR}/")
    print(f"  calibration  mu={mu:.5f}  sigma={sigma:.5f}")


if __name__ == "__main__":
    main()
