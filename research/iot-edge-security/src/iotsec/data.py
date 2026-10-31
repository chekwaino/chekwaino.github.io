"""Data loading, cleaning and splitting for the CIC IoT-DIAD 2024 flow dataset.

The AD_Flow-based-features CSVs use the CICFlowMeter schema (84 columns). Identifier
columns (Flow ID, IPs, ports, Timestamp) are dropped to prevent identifier-based leakage,
leaving 76 numeric flow features + `label`.

Labels may be granular (33 attacks, e.g. 'DDoS-UDP_Flood') or category-level (7 families).
`family_of()` normalizes any label to one of the 7 attack families (or 'Benign').
"""
from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

FAMILIES = ["DDoS", "DoS", "Recon", "Web-based", "Brute_Force", "Spoofing", "Mirai"]
BENIGN = "BenignTraffic"

IDENTIFIER_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Timestamp"]
LABEL_COL = "label"

_FAMILY_KEYWORDS = [
    ("ddos", "DDoS"),
    ("dos", "DoS"),          # checked after ddos
    ("recon", "Recon"),
    ("scan", "Recon"),
    ("web", "Web-based"),
    ("sql", "Web-based"),
    ("xss", "Web-based"),
    ("brute", "Brute_Force"),
    ("password", "Brute_Force"),
    ("spoof", "Spoofing"),
    ("arp", "Spoofing"),
    ("mirai", "Mirai"),
    ("botnet", "Mirai"),
]


def family_of(label: str) -> str:
    """Map a raw DIAD label (granular or category-level) to one of the 7 families / Benign."""
    if label is None:
        return "Unknown"
    s = str(label).strip().lower()
    if s in ("benign", "benigntraffic", "normal", "benign_traffic"):
        return BENIGN
    for kw, fam in _FAMILY_KEYWORDS:
        if kw in s:
            return fam
    return "Unknown"


def load_flows(data_dir: str | Path, sample_frac: float = 1.0, seed: int = 42) -> pd.DataFrame:
    """Load all CSVs in `data_dir` (or a single CSV file), clean, and add `family`."""
    data_dir = Path(data_dir)
    files = [data_dir] if data_dir.is_file() else sorted(data_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}. Download the CIC IoT-DIAD 2024 "
            "AD_Flow-based-features CSVs from https://www.unb.ca/cic/datasets/iot-diad-2024.html"
        )
    frames = []
    for f in files:
        df = pd.read_csv(f, low_memory=False)
        # strip whitespace in column names (CICFlowMeter files sometimes have trailing spaces)
        df.columns = [c.strip() for c in df.columns]
        if LABEL_COL not in df.columns:
            raise ValueError(f"{f}: missing '{LABEL_COL}' column")
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)

    # normalize label whitespace
    df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()
    df["family"] = df[LABEL_COL].map(family_of)
    unknown = (df["family"] == "Unknown").sum()
    if unknown:
        print(f"[data] warning: {unknown} rows with unmapped label -> kept as 'Unknown'")

    if sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=seed).reset_index(drop=True)
    return df


def feature_matrix(df: pd.DataFrame, drop_identifiers: list[str] | None = IDENTIFIER_COLS):
    """Return (X, y_family, y_raw, feature_names): numeric feature matrix + labels."""
    drop = [c for c in (drop_identifiers or []) if c in df.columns]
    feats = [c for c in df.columns if c not in drop + [LABEL_COL, "family"]]
    X = df[feats].copy()
    # numeric coercion; replace inf with NaN then impute with column median
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median(numeric_only=True)).fillna(0.0)
    return X, df["family"].values, df[LABEL_COL].values, feats


def stratified_split(df, test_size=0.20, val_size=0.10, seed=42):
    """Stratified train/val/test split on attack family."""
    train_df, test_df = train_test_split(
        df, test_size=test_size, random_state=seed, stratify=df["family"]
    )
    val_rel = val_size / (1 - test_size)
    train_df, val_df = train_test_split(
        train_df, test_size=val_rel, random_state=seed, stratify=train_df["family"]
    )
    return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)


def zero_day_split(df, holdout_families: list[str], seed=42):
    """Zero-day protocol: train on all families EXCEPT `holdout_families` (attacks);
    the held-out attack families appear only in the test set as unseen (zero-day) traffic.
    Benign traffic is always in train and test."""
    holdout = set(holdout_families)
    unknown_holdout = holdout - set(FAMILIES)
    if unknown_holdout:
        raise ValueError(f"Unknown families: {unknown_holdout}. Choose from {FAMILIES}")
    train_df = df[~((df["family"].isin(holdout)) & (df["family"] != BENIGN))].copy()
    test_df = df[(df["family"].isin(holdout)) | (df["family"] == BENIGN)].copy()
    # also keep a stratified benign-only + seen-attack test for reference
    train_df = train_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    test_df = test_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return train_df, test_df
