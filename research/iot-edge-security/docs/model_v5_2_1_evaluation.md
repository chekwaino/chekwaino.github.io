# Thorough evaluation: `UHM-IoTSec V5.2.1` model/training script (Colab, single-file with embedded helpers)

Evaluated: the visible ~2,600 lines of the pasted script (training, proxy protocols, V4/V5
novelty scoring, integrity/freezing, CLI dispatch). The three embedded helper modules
(`uhm_complete_reporting`, `uhm_evidence_reporting`, `uhm_model_freeze_pipeline`) are
zlib+base85-compressed, SHA-256-pinned blobs — extractable with `--extract-helpers` —
so their internals (reporting, golden-reference generation, certification, signing) are
**not auditable from the paste alone**; see recommendations.

## What it does

- **Frozen supervised subsystem**: copies byte-identical XGBoost Threat/Family/Policy heads +
  ExtraTrees secondary from the accepted run (`run_20260914_104855`), guarded by a SHA-256
  manifest check (`verify_sha256_manifest`) with an explicit trust-boundary note.
- **Novelty / zero-day branch (the new work)**: Attention beta-VAE on the 125-D recon view
  (encoder = LayerNorm→Linear→GELU→2×ResidualMLP; heads = μ/logvar, cosine classifier,
  attention gate), trained with MSE recon + β·KL (β warm-up) + CE + supervised contrastive
  + batch-center + class-center-margin (+ optional denoising noise), in 4 predeclared variants.
- **Open-set scoring**: per-class multi-prototypes (MiniBatchKMeans) + train-only kNN
  reference bank; class-conditioned ECDF tail transforms of distance / uncertainty /
  recon-NLL / KL / kNN distance; novelty score = predeclared weighted fusion; decision =
  strict `score > class-conditioned finite-sample order-statistic threshold` at a nominal
  known-FPR (default 1%), with tie-safe semantics (verified in self-tests).
- **Nested proxy protocol (V4/V5)**: 5 folds over the 21 known attack classes (benign always
  known); outer folds' classes excluded from *all* inner training/validation; per-fold
  fold-local robust scalers fit on kept classes only; disjoint monitor / ECDF-reference /
  threshold-calibration / evaluation pools (three-way 30/35/35, four-way 20/20/20/40);
  fixed proxy-unknown prevalence (0.20); eligibility gates (FPR ceiling 3%, worst-fold
  recall ≥ 0.10); candidate locked on inner folds by AUPRC before outer evaluation;
  outer folds evaluate the locked candidate only (plus descriptive all-method comparison in V5).
- **Integrity machinery**: exact per-row sample identity (shard id, source row, V97 row
  hash), train/val source-row disjointness assertions, per-fold checkpoints, SHA256SUMS
  manifest, scientific freeze certificate, TorchScript export + eager-vs-export numerical
  parity certification, known-only golden reference audit, optional Ed25519-signed
  deployment bundle, report-only recovery that never re-selects.
- **Self-tests**: `self_test_upgrade`, `v4_self_test`, `v5_synthetic_test` verify partition
  disjointness, ECDF semantics, tie-aware thresholds, VAE shapes, TorchScript parity — all
  runnable without data.

## Strengths (thesis-relevant)

1. **Claim discipline is exemplary.** Every output states "development-only",
   `independent_unknown_test_status="NOT PERFORMED"`, and the six designated zero-day
   classes are *never read* by this runner. This directly protects the thesis from the
   classic "proxy zero-day ≠ true zero-day" critique.
2. **Leakage controls are real, not cosmetic**: fold-local scalers, outer-class exclusion,
   disjoint calibration pools, strict tie-aware finite-sample thresholds (self-tested:
   all-tied scores → 0 flags; 100 distinct scores at FPR 1% → exactly 1 flag), source-row
   disjointness assertions.
3. **Reproducibility**: seeded everywhere, deterministic order statistics (no random
   tie-breaking), exact sample identity persisted per split, per-fold checkpoints, sealed
   manifests, freeze certificates.
4. **Honest deployment posture**: TorchScript export must pass numerical parity before
   "deployment-ready"; host-vs-Pi scope labelled; console v2.4 incompatibility explicitly
   flagged instead of silently aliasing the new detector to the legacy compact-AE contract.
5. **V5 rank study** is prospective: 16 predeclared scoring profiles, locked candidate,
   paired bootstrap deltas vs prototype-only/global-kNN, and a recovery path that audits
   completeness (per-fold paired-tuple audit) and marks PARTIAL instead of imputing.

## Bugs found (fix before next run)

1. **`--verify-embedded` crashes**: the `__main__` dispatch calls `_uhm_verify_embedded()`,
   which is never defined (only `_uhm_get_helper_source`/`_uhm_install_helpers` exist).
   → NameError. Replace with a loop over `_UHM_EMBEDDED_MODULES` calling
   `_uhm_get_helper_source` (as `--extract-helpers` does).
2. **Runtime monkey-patching of embedded helpers is fragile**: `v4_patch_run_helpers()`
   string-replaces markers inside the decompressed helper source and `exec`s it, and
   rewrites `write_json` payloads by *filename*. Any whitespace/format change in the
   embedded source → hard failure mid-run (safe-fail, but still). Better: implement kNN
   support natively in the helper source of truth; keep runtime patching as a tested
   compatibility shim only.
3. **Global mutable state for the kNN bank**: `_V4_ACTIVE_BANK`, `_V4_ACTIVE_K`,
   `_V4_FINAL_BANK_LABELS` — `final_save_refs` depends on call order via
   `_V4_FINAL_BANK_LABELS[0]`. Works single-threaded, but replace with explicit
   arguments/a small dataclass.
4. **Split classification by path substring**: `load_supervised_paths` matches
   `"/train/" in path` OR manifest text; a run directory containing `test`/`metadata`/
   `zero` substrings can misclassify or be excluded (fallback glob saves it, but
   silently). Classify primarily from the manifest's `split` column; use path only as a
   last resort.
5. **`standalone_preflight` hardcodes the frozen-run path** instead of using
   `FROZEN_SUPERVISED_RUN` / `--frozen-supervised-run`. Minor.
6. Dead code: `audit_pool_ix=dev_ix[:0]` immediately reassigned; the entire
   "historical execution routine" (designated zero-day loading, `collect_zero_with_labels`)
   is present but unreachable — intentional per the claim boundary, but keep it that way
   and route the *confirmatory* evaluation through a separate, explicitly-labelled entrypoint.

## Methodological risks / gaps vs. the stated research objectives

1. **The thesis-critical number is still unmeasured by design**: the six designated
   unknown classes (Backdoor_Malware, CommandInjection, SqlInjection, Uploading_Attack,
   XSS, Recon-PingSweep) are held out of this runner. Plan a separate confirmatory
   evaluation (frozen artifacts only, no re-selection) — the script already has the
   loader (`collect_zero_with_labels`) and claim-boundary language for it.
2. **Proxy folds are class-disjoint, not device-disjoint**: rows from the same device
   appear across folds; the script acknowledges this ("row-disjoint within this run does
   not establish device-disjoint"). The v97 `device_disjoint_protocol/unseen_test` shards
   are the right vehicle for an unseen-*device* claim — add that evaluation.
3. **Objective-2 metric list**: `metric_block` has accuracy, macro/weighted/micro-F1,
   balanced accuracy, MCC, macro PR-AUC — but **no multiclass ROC-AUC (OvR)** and no
   explicit multiclass FPR (per-class FPR exists only in the audit CSV). Add
   `roc_auc_score(..., multi_class='ovr')` and macro FPR to `metric_block` so the
   supervised heads report exactly the metrics in objective 2.
4. **Objective-3 baselines incomplete here**: this script uses XGBoost (+ExtraTrees
   secondary) and a beta-VAE novelty branch; **LightGBM, CatBoost, and a standalone
   compact-AE anomaly detector are not in this runner**. For a fair objective-3 comparison
   they must be trained on the *same* V97 shards/splits with the same metrics — the repo
   scaffold (`research/iot-edge-security`) already implements XGB/ET/LGBM/CatBoost/compact-AE
   on DIAD flow data via `scripts/run_experiment.py compare`.
5. **Latency/throughput are host-only** (`scope: model_ready_host_not_raspberry_pi`).
   Objective 4 needs real Pi 5 measurements (the signed bundle exists, but physical
   enforcement is unmeasured). The repo's `benchmark` subcommand + a Pi-side harness cover this.
6. **β-VAE is heavily classifier-driven** (β=0.005 with warm-up; recon weight in score
   profiles ≤0.25): the "VAE evidence" components are minor by design — fine, but the
   thesis should present this as a *metric-learning encoder with VAE regularization*, not
   as a pure generative model, unless a recon-heavier variant is also compared.
7. **Memory**: per-shard full-array materialization (`np.asarray(z[...])`) is fine at
   100k rows/shard, but `collect_balanced_with_identity` with `need_security=True` on val
   holds ~200k×353 float32 (~280 MB) plus XR — fine on Colab; note for local runs.
8. **Embedded helpers unaudited**: certification/signing/reporting logic lives in the
   compressed blobs. Extract with `--extract-helpers` and review once; the SHA-256 pins
   integrity of the payload, not its correctness.

## Recommendations (priority order)

1. Fix the 5 bugs above (esp. `--verify-embedded` and de-fragilizing the helper patch);
   re-run `--self-test`, `--v4-self-test`, `--v5-self-test`.
2. Extract and review the 3 embedded helpers; move kNN support into the helper source.
3. Add multiclass ROC-AUC (OvR) + macro FPR to `metric_block` (objective 2 completeness).
4. Run the **confirmatory designated-zero-day evaluation** with the frozen artifacts
   (no re-selection), reporting AUROC/AUPRC/recall/FPR per unknown class + confusion
   against known classes, plus the device-disjoint (`unseen_test`) protocol.
5. Run the objective-3 baseline suite (XGB/ET/LGBM/CatBoost/compact-AE) on the identical
   V97 shards and splits, same metric block, so the comparison is apples-to-apples.
6. Objective 4: deploy the TorchScript novelty model + frozen XGB heads on the
   Raspberry Pi gateway (FastAPI + SQLite + dashboard), measure real latency/throughput/
   memory and policy-enforcement outcomes.
