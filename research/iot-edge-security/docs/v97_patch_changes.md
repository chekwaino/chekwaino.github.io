# v97 preprocessing — patch changelog (produced by `tools/make_v97_patch.py`)

Apply with (after dropping the original into `colab/`):

```bash
cd research/iot-edge-security
python tools/make_v97_patch.py colab/objective_i_hybrid_security_feature_preprocessing_v97.py --dry-run   # report only
python tools/make_v97_patch.py colab/objective_i_hybrid_security_feature_preprocessing_v97.py
# -> colab/objective_i_hybrid_security_feature_preprocessing_v97_PATCHED.py
```

| # | Fix | What the patcher does | Behaviour change |
|---|-----|------------------------|------------------|
| V1 | SQL syntax error | `SET count= WHERE h=?` → `SET count=? WHERE h=?` (whitespace-tolerant fallback) | Full-diagnostic run no longer crashes |
| V2 | Duplicate `_generate_bar_from_counter` | Deletes the **second** definition (the `horizontal=True` override); asserts exactly 2 defs exist and that the 2nd mentions `horizontal` | None (the surviving def is the one already in effect) |
| V3 | Per-row cap loop (~35M calls) | Renames the original to `_should_keep_by_caps_orig` and installs a `should_keep_by_caps(*args, **kwargs)` wrapper that returns `True` immediately when every cap is `None` (scalar `None`, dict of `None`s, or container of `None`s) | When all caps are `None` the per-row counter increments are skipped — set `V97_KEEP_CAP_COUNTERS=1` to restore them |
| V4 | Dashboard re-render every 10 files | Renames original to `_update_dashboard_impl`; new `update_dashboard(...)` renders at most once per `V97_DASH_MIN_INTERVAL_S` seconds (default 30), unless `force=True` | Fewer full-template renders during Pass 2; final render should pass `force=True` if the call site supports it |
| V5 | Proxy-metric tile names | Qualifies bare HTML tile text only: `>FDSS<` → `>FDSS* JS label-drift proxy<` etc. (FDSS/DFDI/FLS/ASCS as JS label-drift proxies, AIS as leakage check where 0 = no leakage). Never touches quoted tokens (dict keys / f-strings) | Display labels only; legend: `*` = in-script proxy, not a published metric |
| V6 | Mirai → Quarantine vs other DDoS → Block | Default: inserts an inline comment documenting the rationale (Mirai is self-propagating worm traffic → device-level Quarantine). With `--align-mirai-to-block`: rewrites `'Mirai-greip_flood': 'Quarantine'` → `'Block'` | Default: none. Flag: **changes labels** — only use before re-running preprocessing, never on shards already consumed by the frozen run |
| V7 | Hardcoded Drive paths | Wraps every `NAME = Path(<literal containing 'drive'>)` in `Path(os.environ.get("V97_NAME", <original>))` — covers RAW_DIR, OUI_PATH, OUT_ROOT, cache dir, etc. Adds `import os` if missing | None by default; override per run with env vars, e.g. `V97_RAW_DIR=/data/diad/raw` |
| V8 | Minor guards | Removes the duplicate `# VALIDATION` header (asserts exactly 2); replaces the `Path("")` CWD fallback in `_sample_npz` with `_v97_refuse_cwd_glob()` which raises loudly | Unknown split in `_sample_npz` now errors instead of silently globbing the CWD |

Safety properties: stdlib-only; every fix asserts its expected occurrence count and
**aborts without writing anything** on mismatch; `--dry-run` prints the per-fix report
without writing; the patched file is `compile()`-checked before being written. Tested
end-to-end on a synthetic replica of the script (all 8 fixes applied, re-run on the
patched file fails safe, `--align-mirai-to-block` and `--dry-run` verified).

If a marker doesn't match your real file (whitespace/format drift from what was
reviewed), the patcher names the failing fix — paste the error and the marker gets
adjusted; nothing is ever half-applied.

## Audit revision (v2 of the patcher)

An external audit tested the first version of this patcher against the real
`Dataset Preprocessing.txt` and found five defects, all fixed in `make_v97_patch.py`
v2 (functionally re-tested on a fixture reproducing the real structures):

| Audit finding | v2 fix |
|---|---|
| V2 deleted the *effective* (last, `horizontal=True`) bar function, changing chart orientation | V2 now deletes the **shadowed first** definition and keeps the last (effective) one |
| V3 wrapper inspected `args[-1]` (the counters dict), not the caps — no real optimisation | V3 short-circuits on **cap-like CONFIG keys** (names containing CAP/MAX/LIMIT with `None`/int values), memoised once; a positional int arg is treated as a directly-passed cap and disables the short-circuit; fails safe (no optimisation) when no cap-like keys are found |
| V4 throttle could suppress the final render; `force` only checked as kwarg | V4 wrapper treats `force=True`/`final=True` kwargs **or** a first positional `True` as always-render; `V97_DASH_ALWAYS=1` disables throttling entirely; changelog tells the caller to pass `force=True` on the terminal call |
| V5 only matched standalone HTML text; real labels live in Python data structures | V5 now also matches quoted string **values** (`'FDSS'` not followed by `:` — dict keys are never rewritten) plus `>FDSS<` HTML text and bare tokens on HTML lines |
| V7 only matched `NAME = Path(...)`; real paths are CONFIG string values | V7 wraps both `'KEY': '<...drive...>'` CONFIG entries (→ `os.environ.get('V97_KEY', ...)`) and `NAME = Path(<drive literal>)` assignments; derived paths like `Path(CONFIG[...])` are untouched |
| V8 inserted a raising call as `dict.get(...)` default → raised even for valid splits | V8 replaces the empty `Path("")` with a **lazy** `_V97UnknownSplitDir()` object: instantiation is side-effect free; only an actual `.glob()` on an unknown split raises |
| V6 comment asserted a rationale | V6 comment is neutral: mapping kept **unchanged pending a documented policy decision** |

Accepted as-is: V1 (SQL). Scientific concern (FDSS/DFDI/FLS/ASCS/AIS are proxies, not
published metrics and not independent evidence) is documented with exact definitions
and thesis-safe wording in `docs/v97_metric_definitions.md`.

Remaining verification gap: the real `Dataset Preprocessing.txt` is not in this repo.
Drop it into `colab/` and run the patcher here so every marker is checked against the
actual source before any full run.
