"""Experiment runner: eda | compare | zero-day | benchmark.

Examples:
  python scripts/run_experiment.py eda --data-dir /path/to/csvs --out results/eda
  python scripts/run_experiment.py compare --data-dir /path/to/csvs --out results/compare
  python scripts/run_experiment.py zero-day --data-dir /path/to/csvs --holdout Mirai Spoofing
  python scripts/run_experiment.py benchmark --data-dir /path/to/csvs --out results/benchmark
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iotsec.data import (BENIGN, feature_matrix, load_flows, stratified_split,
                        zero_day_split)
from iotsec.metrics import benchmark_predictor, classification_metrics
from iotsec.models import (AutoencoderAnomalyDetector, BaselineClassifier,
                          EdgeSecurityFramework)

ROOT = Path(__file__).resolve().parent.parent


def load_cfg(path: str | None):
    cfg_path = Path(path) if path else ROOT / "configs/default.yaml"
    return yaml.safe_load(cfg_path.read_text())


def save_json(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str))


def prepare(cfg, args):
    df = load_flows(args.data_dir or cfg["data"]["dir"],
                    sample_frac=args.sample_frac or cfg["data"]["sample_frac"],
                    seed=cfg["data"]["seed"])
    print(f"[data] loaded {len(df)} flows, labels: {df['family'].value_counts().to_dict()}")
    return df


# ----------------------------------------------------------------------------- eda
def cmd_eda(cfg, args):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns

    df = prepare(cfg, args)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    X, y_fam, y_raw, feats = feature_matrix(df, cfg["features"]["drop_identifiers"])
    print(f"[eda] feature matrix: {X.shape}, {len(feats)} features")

    # class distribution
    vc = df["family"].value_counts()
    vc.to_csv(out / "class_distribution.csv")
    fig, ax = plt.subplots(figsize=(9, 5))
    sns.barplot(x=vc.index, y=vc.values, ax=ax)
    ax.set_title("CIC IoT-DIAD 2024 — attack-family distribution")
    ax.set_ylabel("flows"); ax.tick_params(axis="x", rotation=30)
    fig.tight_layout(); fig.savefig(out / "class_distribution.png", dpi=150); plt.close(fig)

    # raw (granular) label distribution if present
    vc_raw = df["label"].value_counts()
    vc_raw.to_csv(out / "raw_label_distribution.csv")

    # numeric summary + missingness
    desc = X.describe().T
    desc["missing"] = df[feats].isna().sum().values
    desc.to_csv(out / "feature_summary.csv")

    # correlation heatmap of top-variance features
    variances = X.var().sort_values(ascending=False)
    top = variances.head(30).index
    corr = X[top].corr()
    fig, ax = plt.subplots(figsize=(12, 10))
    sns.heatmap(corr, cmap="vlag", center=0, ax=ax)
    ax.set_title("Correlation of top-30 highest-variance flow features")
    fig.tight_layout(); fig.savefig(out / "correlation_heatmap.png", dpi=150); plt.close(fig)

    # per-family means of a few key features
    key_feats = [c for c in ["Flow Duration", "Flow Packets/s", "Flow Bytes/s",
                             "Packet Length Mean", "SYN Flag Count"] if c in feats]
    if key_feats:
        melted = df.assign(**{c: X[c] for c in key_feats}).melt(
            id_vars="family", value_vars=key_feats, var_name="feature", value_name="value")
        g = sns.catplot(data=melted, x="family", y="value", col="feature",
                        kind="box", col_wrap=2, sharey=False, height=3, aspect=1.4)
        g.set_xticklabels(rotation=30)
        g.savefig(out / "family_feature_boxplots.png", dpi=150); plt.close("all")

    summary = {"n_flows": int(len(df)), "n_features": len(feats),
               "families": vc.to_dict(), "raw_labels": int(vc_raw.shape[0])}
    save_json(summary, out / "eda_summary.json")
    print(f"[eda] artifacts written to {out}")


# ----------------------------------------------------------------------------- compare
def _train_and_eval_framework(cfg, Xtr, ytr, Xte, yte, labels):
    fw = EdgeSecurityFramework(
        ae_hidden=tuple(cfg["framework"]["ae_hidden"]),
        ae_max_iter=cfg["framework"]["ae_max_iter"],
        ae_threshold_quantile=cfg["framework"]["ae_threshold_quantile"],
        conf_threshold=cfg["framework"]["conf_threshold"],
        classifier_kind=cfg["framework"]["classifier"],
        classifier_params=cfg["framework"]["classifier_params"],
        seed=cfg["data"]["seed"],
    ).fit(Xtr, ytr)
    v = fw.predict(Xte)
    m = classification_metrics(yte, v["family"], v["proba"], labels=labels)
    m["zero_day_flagged"] = int(v["zero_day"].sum())
    return fw, v, m


def _train_and_eval_baseline(name, cfg, Xtr, ytr, Xte, yte, labels):
    if name == "ae":
        det = AutoencoderAnomalyDetector(
            hidden=tuple(cfg["baselines"]["ae_only"]["hidden"]),
            max_iter=cfg["framework"]["ae_max_iter"],
            threshold_quantile=cfg["baselines"]["ae_only"]["threshold_quantile"],
            seed=cfg["data"]["seed"],
        ).fit(Xtr, ytr)
        ypred = det.predict(Xte)
        ybin_true = np.where(np.asarray(yte) == BENIGN, BENIGN, "Attack")
        ybin_pred = ypred
        proba = det.predict_proba(Xte)
        m = classification_metrics(ybin_true, ybin_pred, proba,
                                   labels=[BENIGN, "Attack"])
        return det, ypred, m
    clf = BaselineClassifier(name, cfg["baselines"].get(name, {}), seed=cfg["data"]["seed"]).fit(Xtr, ytr)
    ypred = clf.predict(Xte)
    proba = clf.predict_proba(Xte)
    m = classification_metrics(yte, ypred, proba, labels=labels)
    return clf, ypred, m


def cmd_compare(cfg, args):
    df = prepare(cfg, args)
    tr, va, te = stratified_split(df, cfg["split"]["test_size"], cfg["split"]["val_size"],
                                 cfg["split"]["seed"])
    Xtr, ytr, _, feats = feature_matrix(tr, cfg["features"]["drop_identifiers"])
    Xte, yte, _, _ = feature_matrix(te, cfg["features"]["drop_identifiers"])
    Xtr, Xte = Xtr[feats].values, Xte[feats].values
    labels = sorted(set(ytr) | set(yte))
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    results = {}
    fw, v, m = _train_and_eval_framework(cfg, Xtr, ytr, Xte, yte, labels)
    results["framework"] = m
    for name in ["xgboost", "extratrees", "lightgbm", "catboost", "ae"]:
        print(f"[compare] training baseline: {name}")
        _, _, mb = _train_and_eval_baseline(name, cfg, Xtr, ytr, Xte, yte, labels)
        results[name] = mb

    rows = []
    for name, m in results.items():
        rows.append({"model": name, "macro_f1": m["macro_f1"],
                     "balanced_accuracy": m["balanced_accuracy"], "mcc": m["mcc"],
                     "fpr_macro": m["fpr_macro"],
                     "roc_auc": m.get("roc_auc_ovr_macro", m.get("roc_auc")),
                     "accuracy": m["accuracy"]})
    pd.DataFrame(rows).to_csv(out / "comparison.csv", index=False)
    save_json(results, out / "comparison_full.json")
    print(pd.DataFrame(rows).to_string(index=False))
    print(f"[compare] artifacts written to {out}")


# ----------------------------------------------------------------------------- zero-day
def cmd_zero_day(cfg, args):
    df = prepare(cfg, args)
    holdout = args.holdout or cfg["zero_day"]["holdout_families"]
    tr, te = zero_day_split(df, holdout, cfg["zero_day"]["seed"])
    print(f"[zero-day] held-out families: {holdout} | train={len(tr)} test={len(te)}")
    print(f"[zero-day] train families: {sorted(tr['family'].unique())}")
    print(f"[zero-day] test families:  {sorted(te['family'].unique())}")
    Xtr, ytr, _, feats = feature_matrix(tr, cfg["features"]["drop_identifiers"])
    Xte, yte, _, _ = feature_matrix(te, cfg["features"]["drop_identifiers"])
    Xtr, Xte = Xtr[feats].values, Xte[feats].values
    labels = sorted(set(ytr) | set(yte))
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    fw, v, m = _train_and_eval_framework(cfg, Xtr, ytr, Xte, yte, labels)
    # zero-day metrics: held-out attack flows should be flagged zero-day or detected as attack
    holdout_mask = np.isin(yte, holdout)
    zd = v["zero_day"][holdout_mask]
    det = v["is_attack"][holdout_mask]
    zd_summary = {
        "holdout_families": holdout,
        "n_holdout_flows": int(holdout_mask.sum()),
        "zero_day_flag_rate": float(zd.mean()),
        "attack_detected_rate": float(det.mean()),
        "classification": m,
    }
    save_json(zd_summary, out / "zero_day_summary.json")
    pd.DataFrame({"family": yte[holdout_mask],
                  "zero_day": zd, "is_attack": det,
                  "anomaly_score": v["anomaly_score"][holdout_mask],
                  "confidence": v["confidence"][holdout_mask]}
                  ).to_csv(out / "zero_day_predictions.csv", index=False)
    print(json.dumps({k: zd_summary[k] for k in
                      ["holdout_families", "n_holdout_flows", "zero_day_flag_rate",
                       "attack_detected_rate"]}, indent=2))
    print(f"[zero-day] artifacts written to {out}")


# ----------------------------------------------------------------------------- benchmark
def cmd_benchmark(cfg, args):
    df = prepare(cfg, args)
    tr, va, te = stratified_split(df, cfg["split"]["test_size"], cfg["split"]["val_size"],
                                 cfg["split"]["seed"])
    Xtr, ytr, _, feats = feature_matrix(tr, cfg["features"]["drop_identifiers"])
    Xte, _, _, _ = feature_matrix(te, cfg["features"]["drop_identifiers"])
    Xtr, Xte = Xtr[feats].values, Xte[feats].values
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    fw, _, _ = _train_and_eval_framework(cfg, Xtr, ytr, Xte, np.asarray([BENIGN] * len(Xte)),
                                         sorted(set(ytr)))
    models = {"framework": fw.predict_scores}
    for name in ["xgboost", "extratrees", "lightgbm", "catboost"]:
        clf, _, _ = _train_and_eval_baseline(name, cfg, Xtr, ytr, Xte,
                                             np.asarray([BENIGN] * len(Xte)),
                                             sorted(set(ytr)))
        models[name] = clf.predict

    rows = []
    for name, fn in models.items():
        for em in benchmark_predictor(fn, Xte, batch_sizes=tuple(cfg["benchmark"]["batch_sizes"]),
                                      repeat=cfg["benchmark"]["repeat"], model_name=name):
            print(f"[bench] {em.model_name:<10} bs={em.batch_size:<4} "
                  f"lat_mean={em.latency_ms_mean:.4f}ms p99={em.latency_ms_p99:.4f}ms "
                  f"throughput={em.throughput_fps:.0f} flows/s peak_mem={em.peak_mem_mb:.1f}MB")
            rows.append(em.as_dict())
    pd.DataFrame(rows).to_csv(out / "benchmark.csv", index=False)
    save_json(rows, out / "benchmark.json")
    print(f"[benchmark] artifacts written to {out}")


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=None)
    common.add_argument("--data-dir", default=None, help="dir with DIAD flow CSVs (or single CSV)")
    common.add_argument("--sample-frac", type=float, default=None)
    common.add_argument("--out", default="results/run")
    ap = argparse.ArgumentParser(description="IoT edge security framework experiments")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("eda", parents=[common])
    sub.add_parser("compare", parents=[common])
    zd = sub.add_parser("zero-day", parents=[common])
    zd.add_argument("--holdout", nargs="+", default=None)
    sub.add_parser("benchmark", parents=[common])
    args = ap.parse_args()
    cfg = load_cfg(args.config)
    {"eda": cmd_eda, "compare": cmd_compare, "zero-day": cmd_zero_day,
     "benchmark": cmd_benchmark}[args.cmd](cfg, args)


if __name__ == "__main__":
    main()
