# V5.2.1 → V5.2.2 changelog (produced by `tools/make_v5_2_2.py`)

Apply with:

```bash
cd research/iot-edge-security
python tools/make_v5_2_2.py colab/UHM_V5_2_1_RECOVERY_FIXED.py     # -> colab/UHM_V5_2_2_RECOVERY_FIXED.py
!python /content/UHM_V5_2_2_RECOVERY_FIXED.py --verify-embedded   # in Colab
!python /content/UHM_V5_2_2_RECOVERY_FIXED.py --self-test         # in Colab, before any run
```

| # | Fix | Detail |
|---|-----|--------|
| F1 | Dead `--verify-embedded` branch removed | The bottom `__main__` chain called undefined `_uhm_verify_embedded()`; it was unreachable because `_uhm_early_action()` handles the flag first, but it is now deleted to avoid confusion. `--verify-embedded` behaviour unchanged (verifies via `_uhm_get_helper_source`). |
| F2 | kNN support baked into embedded `uhm_model_freeze_pipeline` | The patcher decompresses the SHA-256-pinned blob, applies the three marker edits (add `'MODELS/knn_reference_bank.npz'` to the artifact manifest list; extend `allowed={...}` with `'knn_tail'`; extend `dep={...}` with `'knn_tail':'knn_distance'`), recompiles, re-compresses, and writes the **new SHA-256** into `_UHM_EMBEDDED_MODULES`. `v4_patch_run_helpers()` no longer string-patches + `exec`s helper source at runtime; it only verifies the markers are present and fails loudly otherwise. |
| F3 | Global bank state removed | `_V4_ACTIVE_BANK`, `_V4_ACTIVE_K`, `_V4_FINAL_BANK_LABELS` → one dict `_V4_BANK = {'bank', 'k', 'labels'}`; the two `global` statements removed. Removes call-order coupling between `final_prototypes` and `final_save_refs`. |
| F4 | Manifest-first split classification | `load_supervised_paths` now matches the manifest's `split`/`protocol`/… column by **token**, and only falls back to path/name matching; shard filenames must start with `train_`/`val_`/`test_` (not bare `train`) for the fallback. Prevents silent misclassification when the run directory path contains substrings like `test`/`metadata`. |
| F5 | Preflight honours the constant | `standalone_preflight` uses `FROZEN_SUPERVISED_RUN` instead of a duplicated hardcoded Drive path. |
| F6 | Version bump | `5.2.1` → `5.2.2` in docstring, `SCRIPT_VERSION`, `EXPERIMENT_TAG`, `V5_TAG`. |

Safety properties of the patcher: stdlib-only; every textual replacement asserts its
expected occurrence count outside the embedded-blob segment and aborts without writing on
mismatch; the original blob hash is verified before editing and the new hash after;
output is `compile()`-checked and then validated by running `--verify-embedded` in a
subprocess (that code path exits before the numpy/torch imports).

Not changed (deliberately): all training/scoring/protocol logic, seeds, thresholds, and
claim-boundary language are byte-identical, so V5.2.2 results remain comparable to V5.2.1.
