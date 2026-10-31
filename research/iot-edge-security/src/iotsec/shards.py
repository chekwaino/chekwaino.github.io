"""Loader for NPZ shard runs produced by the Colab v97 preprocessing pipeline
(objective_i_hybrid_security_feature_preprocessing_v97.py).

Shard layout (per run dir):
  SHARDS/supervised/{train,val,test}/*.npz
  SHARDS/zeroday/*.npz
  SHARDS/device_disjoint_protocol/{known_train,known_val,known_test,unseen_test}/*.npz
Each NPZ contains: X_security, X_security_hybrid, X_security_compact,
X_security_rich, X_device, X_device_behavior_only, X_recon_input, X_recon_target,
row_hash, y_threat, y_threat_known, y_family, y_policy, y_binary, y_device*, masks...
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

import numpy as np

SPLIT_DIRS = {
    "train": ("SHARDS/supervised/train",),
    "val": ("SHARDS/supervised/val",),
    "test": ("SHARDS/supervised/test",),
    "zeroday": ("SHARDS/zeroday",),
    "dd_known_train": ("SHARDS/device_disjoint_protocol/known_train",),
    "dd_known_val": ("SHARDS/device_disjoint_protocol/known_val",),
    "dd_known_test": ("SHARDS/device_disjoint_protocol/known_test",),
    "dd_unseen_test": ("SHARDS/device_disjoint_protocol/unseen_test",),
}


def shard_files(run_dir: str | Path, split: str) -> list[Path]:
    run_dir = Path(run_dir)
    out: list[Path] = []
    for rel in SPLIT_DIRS[split]:
        out.extend(sorted((run_dir / rel).glob("*.npz")))
    return out


def iter_shard(run_dir: str | Path, split: str, keys: list[str] | None = None) -> Iterator[dict[str, np.ndarray]]:
    """Stream one NPZ shard at a time (memory-safe for 35M-row runs)."""
    for p in shard_files(run_dir, split):
        with np.load(p, allow_pickle=False) as z:
            keys = keys or z.files
            yield {k: z[k] for k in keys if k in z.files}


def load_split(run_dir: str | Path, split: str, keys: list[str],
               max_rows: Optional[int] = None) -> dict[str, np.ndarray]:
    """Load a full split into memory (cap with max_rows for sandbox runs)."""
    parts: dict[str, list[np.ndarray]] = {k: [] for k in keys}
    n = 0
    for shard in iter_shard(run_dir, split, keys):
        for k in keys:
            if k in shard:
                parts[k].append(shard[k])
        n += len(next(iter(shard.values())))
        if max_rows and n >= max_rows:
            break
    out = {}
    for k, v in parts.items():
        if not v:
            continue
        arr = np.concatenate(v, axis=0)
        out[k] = arr[:max_rows] if max_rows else arr
    return out


def load_xy(run_dir: str | Path, split: str, view: str = "X_security",
            target: str = "y_family", max_rows: Optional[int] = None):
    d = load_split(run_dir, split, [view, target], max_rows=max_rows)
    return d[view], d[target]
