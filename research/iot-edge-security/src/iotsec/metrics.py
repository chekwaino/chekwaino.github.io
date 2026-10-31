"""Evaluation metrics required by the research objectives.

Classification: Macro-F1, balanced accuracy, MCC, FPR (macro + per-class), ROC-AUC (OvR macro),
accuracy, full classification report.
Edge: per-flow inference latency (mean/p50/p95/p99), throughput (flows/s), memory (peak RSS delta).
"""
from __future__ import annotations

import time
import tracemalloc
from dataclasses import dataclass, field

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    roc_auc_score,
)


def classification_metrics(y_true, y_pred, y_proba=None, labels=None) -> dict:
    """All classification metrics for objective 2. y_proba: (n, k) class probabilities."""
    labels = list(labels) if labels is not None else sorted(set(y_true) | set(y_pred))
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    per_class_fpr = {}
    for i, lab in enumerate(labels):
        fp = cm[:, i].sum() - cm[i, i]
        tn = cm.sum() - cm[i, :].sum() - cm[:, i].sum() + cm[i, i]
        per_class_fpr[lab] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    out = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "fpr_macro": float(np.mean(list(per_class_fpr.values()))),
        "fpr_per_class": per_class_fpr,
        "n_samples": int(len(y_true)),
        "labels": labels,
        "report": classification_report(y_true, y_pred, labels=labels, zero_division=0),
    }
    if y_proba is not None and len(labels) > 2:
        y_true_bin = np.array([[1 if t == l else 0 for l in labels] for t in y_true])
        try:
            out["roc_auc_ovr_macro"] = float(
                roc_auc_score(y_true_bin, y_proba, multi_class="ovr", average="macro")
            )
        except ValueError:
            out["roc_auc_ovr_macro"] = None
    elif y_proba is not None and len(labels) == 2:
        out["roc_auc"] = float(roc_auc_score(y_true, y_proba[:, 1]))
    return out


@dataclass
class EdgeMetrics:
    """Latency / memory / throughput of a fitted predictor on flow batches."""
    model_name: str
    batch_size: int
    latency_ms_mean: float
    latency_ms_p50: float
    latency_ms_p95: float
    latency_ms_p99: float
    throughput_fps: float
    peak_mem_mb: float
    n_flows: int
    repeat: int = 1

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def benchmark_predictor(predict_fn, X, batch_sizes=(1, 16, 64, 256), repeat=5,
                        model_name="model") -> list[EdgeMetrics]:
    """Measure per-flow latency, throughput and peak memory for `predict_fn(X_batch)`.

    `predict_fn` must accept a (n, d) numpy array and return predictions for all rows.
    Latency is measured per flow (total batch time / batch size) and in wall-clock batches.
    """
    X = np.asarray(X)
    results: list[EdgeMetrics] = []
    for bs in batch_sizes:
        bs = min(bs, len(X))
        batches = [X[i:i + bs] for i in range(0, len(X), bs)]
        # warmup
        predict_fn(batches[0])
        tracemalloc.start()
        latencies = []
        t0 = time.perf_counter()
        for _ in range(repeat):
            for b in batches:
                tb = time.perf_counter()
                predict_fn(b)
                latencies.append((time.perf_counter() - tb) / len(b) * 1000.0)  # ms per flow
        wall = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        total_flows = len(batches) * bs * repeat
        results.append(EdgeMetrics(
            model_name=model_name,
            batch_size=bs,
            latency_ms_mean=float(np.mean(latencies)),
            latency_ms_p50=float(np.percentile(latencies, 50)),
            latency_ms_p95=float(np.percentile(latencies, 95)),
            latency_ms_p99=float(np.percentile(latencies, 99)),
            throughput_fps=float(total_flows / wall),
            peak_mem_mb=float(peak / 1e6),
            n_flows=int(total_flows),
            repeat=repeat,
        ))
    return results
