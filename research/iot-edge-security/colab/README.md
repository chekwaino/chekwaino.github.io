# Colab scripts

Drop your Colab `.py` research scripts here (download from Colab via
`Files → /content/<name>.py → Download`, or copy from Drive) so they are versioned
in this repo and can be patched/audited locally.

Current pipeline lineage:

1. `objective_i_hybrid_security_feature_preprocessing_v97.py` — preprocessing (see
   `docs/preprocessing_v97_review.md`). *Add the original here, then run:*

   ```bash
   cd research/iot-edge-security
   python tools/make_v97_patch.py colab/objective_i_hybrid_security_feature_preprocessing_v97.py --dry-run
   python tools/make_v97_patch.py colab/objective_i_hybrid_security_feature_preprocessing_v97.py
   # -> writes colab/objective_i_..._v97_PATCHED.py with the 8 reviewed fixes
   #    (--align-mirai-to-block optional; see docs/v97_patch_changes.md)
   ```
2. `UHM_V5_2_1_RECOVERY_FIXED.py` — model training / zero-day development runner
   (see `docs/model_v5_2_1_evaluation.md`). *Add the original here, then run:*

   ```bash
   cd research/iot-edge-security
   python tools/make_v5_2_2.py colab/UHM_V5_2_1_RECOVERY_FIXED.py
   # -> writes colab/UHM_V5_2_2_RECOVERY_FIXED.py, verifies embedded hashes via --verify-embedded
   ```

   Then in Colab: `!python /content/UHM_V5_2_2_RECOVERY_FIXED.py --self-test` before any run.

Patched versions produced by `tools/make_v5_2_2.py` / `tools/make_v97_patch.py` live
alongside the originals; see `docs/v5_2_2_changes.md` and `docs/v97_patch_changes.md`
for the changelogs.
