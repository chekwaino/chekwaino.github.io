# Intelligent Edge Security Framework for IoT Networks

**Research aim:** *To develop and validate an intelligent edge security framework for real-time
threat detection, attack classification, zero-day identification, and mitigation support in
Internet of Things networks* — benchmarked on the **CIC IoT-DIAD 2024** dataset.

## Objectives → implementation map

| # | Research objective | Where in this repo |
|---|---|---|
| 1 | Intelligent edge framework: real-time detection, attack-family ID, policy decisions, zero-day detection | `src/iotsec/models.py` (`EdgeSecurityFramework`), `src/iotsec/policy.py` |
| 2 | Evaluate on benchmark IoT data with Macro-F1, balanced accuracy, MCC, FPR, ROC-AUC, latency, memory, throughput | `src/iotsec/metrics.py`, `scripts/run_experiment.py evaluate/benchmark` |
| 3 | Compare against XGBoost, Extra Trees, LightGBM, CatBoost + compact autoencoder anomaly detection | `src/iotsec/models.py` (baselines), `scripts/run_experiment.py compare` |
| 4 | Deploy on edge→server (Raspberry Pi gateway, API, DB logging, dashboard, policy reporting) | `edge/` (to be built) |

## Dataset: CIC IoT-DIAD 2024

- Source: Canadian Institute for Cybersecurity (UNB), <https://www.unb.ca/cic/datasets/iot-diad-2024.html>
- 105 IoT devices, **33 attacks in 7 families**: DDoS, DoS, Recon, Web-based, Brute Force, Spoofing, Mirai (+ Benign).
- Flow-based features (`AD_Flow-based-features`, CICFlowMeter schema, 84 columns incl. `label`)
  are used for anomaly detection / attack classification.
- Full corpus ≈ 35.6M flows across 180 CSV files (~tens of GB). **In this sandbox** (limited
  disk/RAM, no access to unb.ca) we use a GitHub-mirrored sample of the flow CSV
  (`IoTDIAD.csv`, 33,618 flows, category-level labels). To use the full dataset, download the
  `AD_Flow-based-features` CSVs from UNB and drop them into `data/raw/` — the loader picks up
  every `*.csv` in that directory.

> Citation: please cite the CIC IoT-DIAD 2024 dataset paper as required by UNB/CIC when
> redistributing or publishing results.

## Framework design (objective 1)

Two-stage edge pipeline, all scikit-learn/numpy based so it runs on a Raspberry Pi gateway:

1. **Compact autoencoder** (`MLPRegressor` bottleneck 76→32→8→32→76, trained on benign flows
   only) → reconstruction error = **anomaly score** (unsupervised, catches novel attacks).
2. **Attack-family classifier** (gradient boosting, e.g. HistGradientBoosting/XGBoost) trained on
   labeled families → **attack-family classification** with class probabilities.
3. **Zero-day rule**: `anomaly_score > τ_anom` **and** `max family probability < τ_conf`
   ⇒ flagged as *unknown/zero-day* (novel attack family not seen in training).
4. **Policy engine** (`policy.py`): maps (family, anomaly score, confidence) → mitigation
   action: `ALLOW`, `ALERT`, `RATE_LIMIT`, `BLOCK`, `QUARANTINE_DEVICE`, with a human-readable
   report entry for the dashboard.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src

# 1. EDA on the available data
python scripts/run_experiment.py eda --data-dir /path/to/csvs --out results/eda

# 2. Standard evaluation (stratified split) of framework + all baselines
python scripts/run_experiment.py compare --data-dir /path/to/csvs --out results/compare

# 3. Zero-day evaluation (hold out entire attack families, e.g. Mirai+Spoofing)
python scripts/run_experiment.py zero-day --data-dir /path/to/csvs \
    --holdout Mirai Spoofing --out results/zero_day

# 4. Edge metrics: latency, memory, throughput
python scripts/run_experiment.py benchmark --data-dir /path/to/csvs --out results/benchmark
```

All heavy artifacts (`data/`, `models/`, `results/`, venvs) are git-ignored; only code,
configs and documentation are tracked.

## Repo layout

```
research/iot-edge-security/
├── configs/default.yaml        # experiment configuration
├── scripts/run_experiment.py   # eda | compare | zero-day | benchmark
├── src/iotsec/
│   ├── data.py                 # loading, cleaning, label→family map, splits (incl. zero-day)
│   ├── metrics.py              # Macro-F1, balanced acc, MCC, FPR, ROC-AUC, latency/mem/throughput
│   ├── models.py               # EdgeSecurityFramework + XGB/ET/LGBM/CatBoost/AE baselines
│   └── policy.py               # policy-based mitigation engine
├── edge/                       # Raspberry Pi gateway API + DB logging + dashboard (obj. 4)
├── notebooks/                  # exploratory notebooks
└── results/                    # git-ignored outputs
```

## Metrics (objective 2)

Reported per experiment: **Macro-F1**, **balanced accuracy**, **Matthews correlation
coefficient (MCC)**, **false positive rate** (macro over classes, FPR = FP/(FP+TN) per class),
**ROC-AUC (OvR, macro)**, plus edge metrics: **per-flow inference latency** (mean/p50/p99),
**memory** (peak RSS delta via `tracemalloc`/`resource`), and **throughput** (flows/s).
