# Review: `objective_i_hybrid_security_feature_preprocessing_v97.py` (Colab, packet-based DIAD 2024)

Scope: 180 raw parquet files, 35,672,407 rows, 136-column packet schema (device_mac,
src/dst MAC/IP, stream, http_*, tls_*, handshake, etc.), official IEEE OUI parquet.
Outputs NPZ shards + metadata + reports + dashboard + 50 figures per run.

## What the script does well

1. **Streaming two-pass design** — Pass 1 scans in 250k-row parquet batches to fit
   *train-only* scalers/category maps/OUI maps; Pass 2 transforms + writes shards.
   Never loads 35.6M rows into RAM. Good.
2. **Drive-robust IO** — retry/backoff + local `/content` cache copy with size
   verification before `pq.ParquetFile` / `read_parquet`. Correct mitigation for
   Colab Drive `ConnectionAbortedError`.
3. **Leakage-safe feature contract** — raw identifiers (MAC/IP/stream), medium-risk
   identity fields (http_host, http_uri, tls_server, user_agent) and identity-derived
   aggregates (`src_ip_*`, `stream_*`, `most_freq_spot`) are excluded from scientific
   X views; identifier metadata is stored separately with SHA-256 hashed keys. This
   matches the leakage-control practice reported in the literature for this dataset.
4. **Strict taxonomy governance** — canonical label alias map; unknown labels /
   unmapped family / unmapped policy are *hard failures*, not silent buckets.
   28-class → 8-family → 5-policy (Allow/Alert/Throttle/Block/Quarantine) lock, with a
   written policy-derivation contract (label-rule-derived, not SOC-annotated). Good for
   thesis defensibility.
5. **Split integrity** — feature-only row hashes (label/targets/identifiers excluded)
   drive a deterministic 70/15/15 split, so exact duplicates cannot cross splits.
6. **Zero-day protocol** — `ZERO_DAY_HOLDOUT_LABELS` (Backdoor_Malware,
   CommandInjection, SqlInjection, Uploading_Attack, XSS, Recon-PingSweep) are routed
   to separate `SHARDS/zeroday` NPZs; `y_threat_known` gives the closed-set training
   target while `y_threat` stays the full reference. Plus a device-disjoint protocol
   (known_* / unseen_test) for unseen-device claims. This cleanly separates
   label-level zero-day from device-level generalization — exactly the distinction a
   thesis needs.
7. **Multi-view, multi-target shards** — X_security_compact / _rich / hybrid,
   X_device (+behavior-only ablation), X_recon_input/target for the edge AE, and
   targets y_threat, y_threat_known, y_family, y_policy, y_binary, y_device_full/grouped
   + strict/reportable/rare masks + effective-number sample weights. Directly consumable
   by the framework code in this repo via `src/iotsec/shards.py`.
8. **Diagnostic harness gates ACCEPTED** — artifact inventory, shard array contract,
   split drift, scoped hash isolation, zero-day isolation, device-disjoint isolation,
   policy contract, leakage governance (DH-A…DH-H). Strong.

## Bugs found (fix before the next full run)

1. **SQL syntax error** in `builtin_postrun_diagnostics` (full-inventory path):
   `UPDATE row_hash_inventory SET count= WHERE h=?` — missing value (`SET count=?`).
   Only fires when `ENABLE_FULL_ROW_HASH_INVENTORY_DIAGNOSTIC=True`, but it will
   crash a full-diagnostic run.
2. **Duplicate function definition**: `_generate_bar_from_counter` is defined twice
   (second silently overrides the first with `horizontal=True`). Harmless today,
   confusing later — delete one.
3. **Per-row Python loop in `write_pass2`**: `should_keep_by_caps` is called per row
   (~35M calls across the run). With all caps `None` it still increments counters in a
   Python loop — slow. Short-circuit when all caps are `None`, or vectorize.
4. **Dashboard refresh cost**: `update_dashboard` re-renders the entire HTML (with an
   escaped `srcdoc` iframe) every 10 files. On 180 files with a giant template this is
   fine, but during Pass 2 shard writes the template is ~30KB+ each time — consider
   throttling to every N seconds, not N files.
5. **Metric naming risk**: dashboard tiles labelled FDSS/DFDI/FLS/ASCS/AIS are actually
   proxies (JS divergence of label distributions; constant 0 for leakage). In a
   thesis these names will be read as specific published metrics — either rename to
   what they compute (e.g. "label-distribution JS drift") or define them explicitly.
6. **Policy severity inconsistency**: `Mirai-greip_flood → Quarantine` while all other
   DDoS/DoS → Block and Backdoor_Malware → Block. If Quarantine is meant as the most
   severe action, Mirai should arguably be Block too; document the rationale either way.
7. **Hardcoded Drive paths** (`RAW_DIR`, `OUI_PATH`, `OUT_ROOT`, cache dir) — wrap in
   `os.environ.get(..., default)` so the same script runs locally / on the Pi / CI.
8. Minor: duplicated `# VALIDATION` section header; `_sample_npz` falls back to
   `Path("").glob` for unknown splits (reads CWD) — guard it.

## Integration with this repo (research/iot-edge-security)

| v97 pipeline output | consumed by |
|---|---|
| `SHARDS/supervised/{train,val,test}/*.npz` (X_security, y_family, y_threat_known, y_policy, sample_w_*) | `src/iotsec/shards.py` → `scripts/run_experiment.py` (compare/benchmark) |
| `SHARDS/zeroday/*.npz` (y_zero_day_holdout=1) | zero-day/OOD evaluation (objective 1) — AE reconstruction + low-confidence rule |
| `SHARDS/device_disjoint_protocol/unseen_test` | unseen-device robustness protocol |
| `X_recon_input/target` + compact view | compact autoencoder for Raspberry Pi edge (objective 4) |
| `policy_derivation_contract.csv`, `POLICY_MAPPING` | `src/iotsec/policy.py` (extend its 5 actions to the same Allow/Alert/Throttle/Block/Quarantine vocabulary) |
| flow-based CSV sample (this sandbox) | quick local smoke tests of the same framework |

Taxonomy note: the UNB page describes 7 attack categories + Benign; the script's
8 "families" are those 7 attacks with Benign split out (Benign, Web-Based, Brute-Force,
DDoS Attacks, Spoofing, DoS Attacks, Mirai/Malware, Reconnaissance) — consistent.
The flow-CSV mirror used in this sandbox has category-level labels
(BenignTraffic, DDoS, DoS, Mirai, Recon, Spoofing, Web-based, Brute_Force), which map
onto the same families via `iotsec.data.family_of`.

## Suggested next steps (pick one)

1. Fix the bugs above in v97 and re-run on Colab (full 35.6M rows).
2. Build `scripts/train_on_shards.py` here that trains the EdgeSecurityFramework +
   XGB/ET/LGBM/CatBoost baselines directly on the v97 NPZ shards (objectives 2–3 at
   full scale), reusing `iotsec.metrics` (Macro-F1, balanced acc, MCC, FPR, ROC-AUC,
   latency/memory/throughput).
3. Zero-day evaluation on `SHARDS/zeroday` (AE AUROC/AUPRC + zero-day flag rate).
4. Edge deployment (objective 4): FastAPI gateway on Raspberry Pi + SQLite logging +
   dashboard, scoring with the compact AE + family head exported from the shard-trained model.
