#!/usr/bin/env python3
"""make_v5_2_2.py — apply the five V5.2.1 -> V5.2.2 fixes to UHM-IoTSec V5.2.1 recovery script.

Usage:
    python tools/make_v5_2_2.py path/to/UHM_V5_2_1_RECOVERY_FIXED.py [--out OUTPUT.py]

Produces a patched copy (default: same directory, name with V5_2_1 -> V5_2_2).
Stdlib only. The embedded helper blobs are decompressed, patched, re-compressed and
re-hashed in place (the outer code is untouched by blob edits). After patching, the
output file is syntax-checked (compile) and verified by running `--verify-embedded`
in a subprocess (that path exits before the heavy numpy/torch imports).

Fixes (see docs/model_v5_2_1_evaluation.md and docs/v5_2_2_changes.md):
  F1  remove dead `--verify-embedded` dispatch branch (calls undefined _uhm_verify_embedded)
  F2  bake kNN support into the embedded uhm_model_freeze_pipeline source (manifest entry,
      allowed score keys, dependency map) and stop runtime source-patching/exec in
      v4_patch_run_helpers(); it now only verifies the markers are present.
  F3  replace global bank state (_V4_ACTIVE_BANK/_V4_ACTIVE_K/_V4_FINAL_BANK_LABELS)
      with a single dict _V4_BANK
  F4  load_supervised_paths: classify from the manifest split column (token match) first;
      path/name matching only as fallback
  F5  standalone_preflight: use FROZEN_SUPERVISED_RUN instead of a hardcoded path
  F6  version bump 5.2.1 -> 5.2.2 (SCRIPT_VERSION, EXPERIMENT_TAG, V5_TAG, docstring)

Every replacement asserts its expected occurrence count; on mismatch the patcher aborts
without writing output (safe-fail).
"""
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import re
import subprocess
import sys
import zlib
from pathlib import Path

HELPER = "uhm_model_freeze_pipeline"

# (old, new) applied outside the embedded-blob segment; each must occur exactly `count` times.
PLAIN_FIXES = [
    # F1: dead dispatch branch calling undefined _uhm_verify_embedded
    (
        "    elif '--verify-embedded' in sys.argv[1:]:print('Embedded helper verification:',_uhm_verify_embedded())",
        "    elif '--verify-embedded' in sys.argv[1:]:pass  # V5.2.2: verified by _uhm_early_action(); dead branch removed",
        1,
    ),
    # F3: remove `global` statements (dict mutation needs no global), then swap identifiers
    # (regex: match the whole line at any indent, so nested-def indentation cannot be mangled)
    ("REGEX:^[ \\t]*global _V4_ACTIVE_BANK,_V4_ACTIVE_K[ \\t]*\\r?\\n", "", 2),
    ("_V4_ACTIVE_BANK = None\n", "", 1),
    (
        "_V4_ACTIVE_K = 5\n",
        "_V4_BANK = {'bank': None, 'k': 5, 'labels': np.empty(0, dtype=np.int32)}  # V5.2.2: single state holder (replaces the old separate globals)\n",
        1,
    ),
    ("_V4_FINAL_BANK_LABELS=[np.empty(0,dtype=np.int32)]", "", 1),
    ("_V4_FINAL_BANK_LABELS[0]", "_V4_BANK['labels']", None),  # count checked after removal
    ("_V4_ACTIVE_BANK", "_V4_BANK['bank']", None),
    ("_V4_ACTIVE_K", "_V4_BANK['k']", None),
    # F5: preflight uses the module constant, not a hardcoded path
    (
        "        'Frozen supervised redevelopment': _UHMPath('/content/drive/MyDrive/CIC_IoT_IDAD/Objective_i/Raspberry_Development/UHM_IoTSec_REDEVELOPMENT/run_20260914_104855'),",
        "        'Frozen supervised redevelopment': FROZEN_SUPERVISED_RUN,  # V5.2.2: honour --frozen-supervised-run",
        1,
    ),
]

# F2 outer: replace the runtime source-patch/exec block inside v4_patch_run_helpers
F2_OLD = """    from types import ModuleType
    source=_uhm_get_helper_source('uhm_model_freeze_pipeline')
    old="'MODELS/prototype_bank.npz',"
    if old not in source or "allowed={'distance_tail','uncertainty_tail'" not in source:
        raise RuntimeError('Unrecognised freeze helper; refuse unsafe patch')
    source=source.replace(old,old+"\\n    'MODELS/knn_reference_bank.npz',",1)
    source=source.replace("allowed={'distance_tail','uncertainty_tail'","allowed={'distance_tail','knn_tail','uncertainty_tail'",1)
    if "dep={'distance_tail':'distance'," not in source:
        raise RuntimeError('Unrecognised certification dependency mapping')
    source=source.replace("dep={'distance_tail':'distance',","dep={'knn_tail':'knn_distance','distance_tail':'distance',",1)
    namespace=sys.modules['uhm_model_freeze_pipeline'].__dict__
    exec(compile(source,'<embedded uhm_model_freeze_pipeline V4>','exec'),namespace)
    frozen=sys.modules['uhm_model_freeze_pipeline']"""

F2_NEW = """    frozen=sys.modules['uhm_model_freeze_pipeline']
    # V5.2.2: kNN support is baked into the embedded helper source by tools/make_v5_2_2.py;
    # verify the markers instead of re-exec'ing a patched copy at runtime.
    _helper_src=_uhm_get_helper_source('uhm_model_freeze_pipeline')
    for _marker in ("'MODELS/knn_reference_bank.npz',",
                    "allowed={'distance_tail','knn_tail','uncertainty_tail'",
                    "dep={'knn_tail':'knn_distance','distance_tail':'distance',"):
        if _marker not in _helper_src:
            raise RuntimeError('Embedded freeze helper lacks native V5.2.2 kNN support; refuse unsafe patch')"""

# F2 blob: replacements applied to the decompressed helper source (must occur exactly once)
HELPER_FIXES = [
    (
        "'MODELS/prototype_bank.npz',",
        "'MODELS/prototype_bank.npz',\n    'MODELS/knn_reference_bank.npz',",
    ),
    (
        "allowed={'distance_tail','uncertainty_tail'",
        "allowed={'distance_tail','knn_tail','uncertainty_tail'",
    ),
    (
        "dep={'distance_tail':'distance',",
        "dep={'knn_tail':'knn_distance','distance_tail':'distance',",
    ),
]

# F4: whole-function replacement via regex (anchored between top-level defs)
F4_NEW_FUNC = '''def load_supervised_paths(run_dir: Path) -> List[Path]:
    """V5.2.2: classify shards from the manifest split column first (token match);
    path/name matching is only a fallback, so run directories whose path contains
    'test'/'metadata'/etc. cannot silently misclassify shards."""
    _split_by_path = globals().get("SHARD_SPLIT_BY_PATH")  # only if the host script defines one
    if _split_by_path is not None:
        _split_by_path.clear()
    manifest = shard_manifest_path(run_dir)
    paths: List[Path] = []
    with manifest.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            raw = str(row.get("path") or row.get("shard_path") or row.get("file") or "")
            low = raw.replace("\\\\", "/").lower()
            split_text = " ".join(str(row.get(k, "")) for k in ("split", "protocol", "subset", "stage", "kind")).lower()
            if any(t in low or t in split_text for t in ("zero", "zeroday", "device_disjoint", "metadata")):
                continue
            p = Path(raw)
            if not p.exists() and "/SHARDS/" in raw.replace("\\\\", "/"):
                p = run_dir / "SHARDS" / raw.replace("\\\\", "/").split("/SHARDS/", 1)[1]
            if not p.exists():
                continue
            code = None
            for name, c in SPLIT_CODE.items():
                if name in split_text.split():
                    code = c
                    break
            if code is None:
                for name, c in SPLIT_CODE.items():
                    if f"/{name}/" in low or p.name.lower().startswith(name + "_"):
                        code = c
                        break
            if code is not None and _split_by_path is not None:
                _split_by_path[str(p)] = code
            paths.append(p)
    if not paths:
        paths = [
            p for p in (run_dir / "SHARDS").glob("**/*.npz")
            if not any(t in str(p).lower() for t in ("zero", "zeroday", "device_disjoint", "metadata"))
        ]
    if not paths:
        raise RuntimeError("No supervised shard paths found")
    return sorted(set(paths))


'''


def find_blob_segment(src: str):
    """Locate the _UHM_EMBEDDED_MODULES assignment via AST; return (start, end, node)."""
    tree = ast.parse(src)
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "_UHM_EMBEDDED_MODULES"
        ):
            seg = ast.get_source_segment(src, node)
            start = src.index("_UHM_EMBEDDED_MODULES")
            return start, start + len(seg), node
    raise RuntimeError("_UHM_EMBEDDED_MODULES assignment not found")


def patch_blob(src: str) -> str:
    start, end, node = find_blob_segment(src)
    modules = ast.literal_eval(node.value)
    if HELPER not in modules:
        raise RuntimeError(f"embedded helper {HELPER!r} not found")
    expected_hash, chunks = modules[HELPER]
    code = zlib.decompress(base64.b85decode("".join(chunks))).decode("utf-8")
    actual = hashlib.sha256(code.encode("utf-8")).hexdigest()
    if actual != expected_hash:
        raise RuntimeError("original embedded helper hash mismatch — wrong input file?")
    for old, new in HELPER_FIXES:
        n = code.count(old)
        if n != 1:
            raise RuntimeError(f"helper marker {old!r} found {n} times (expected 1); aborting")
        code = code.replace(old, new)
    compile(code, f"<embedded {HELPER} v5.2.2>", "exec")
    blob = base64.b85encode(zlib.compress(code.encode("utf-8"), 9)).decode("ascii")
    new_chunks = [blob[i : i + 110] for i in range(0, len(blob), 110)]
    modules[HELPER] = (hashlib.sha256(code.encode("utf-8")).hexdigest(), tuple(new_chunks))
    lines = ["_UHM_EMBEDDED_MODULES = {"]
    for name, (h, ch) in modules.items():
        lines.append(f"{name!r}: (")
        lines.append(f"{h!r},")
        lines.append("(")
        lines.extend(repr(c) for c in ch)
        lines.append(")),")
    lines.append("}")
    new_seg = "\n".join(lines) + "\n"
    print(f"[blob] {HELPER}: {len(code.splitlines())} lines patched, sha256 {expected_hash[:12]}… -> {modules[HELPER][0][:12]}…")
    return src[:start] + new_seg + src[end:]


def apply_outside_blobs(src: str, old: str, new: str, count) -> str:
    """Apply a replacement anywhere EXCEPT inside the embedded-blob segment.

    `count` is the expected TOTAL occurrences across both non-blob regions
    (a marker may live entirely in the head or entirely in the tail).
    """
    start, end, _ = find_blob_segment(src)
    head, blob, tail = src[:start], src[start:end], src[end:]

    def do(part: str) -> tuple[str, int]:
        if old.startswith("REGEX:"):
            pat = re.compile(old[6:], re.M)
            n = len(pat.findall(part))
            return (pat.sub(new, part) if n else part), n
        n = part.count(old)
        return (part.replace(old, new) if n else part), n

    new_head, nh = do(head)
    new_tail, nt = do(tail)
    total = nh + nt
    if count is not None and total != count:
        raise RuntimeError(f"marker {old[:60]!r}…: found {total}, expected {count}; aborting")
    if count is None and total == 0:
        raise RuntimeError(f"marker {old[:60]!r}… not found outside blobs; aborting")
    return new_head + blob + new_tail


def patch_f4(src: str) -> str:
    start, end, _ = find_blob_segment(src)
    head, tail = src[:start], src[end:]
    pat = re.compile(
        r"^def load_supervised_paths\(.*?(?=^def load_zero_paths)",
        re.S | re.M,
    )
    # NB: replacement goes through a lambda because re.sub would otherwise eat
    # backslash escapes inside F4_NEW_FUNC (it contains "\\" literals).
    n_total = pat.subn(lambda m: F4_NEW_FUNC, head)[1] + pat.subn(lambda m: F4_NEW_FUNC, tail)[1]
    if n_total != 1:
        raise RuntimeError(f"F4: load_supervised_paths found {n_total} times (expected 1); aborting")
    head = pat.sub(lambda m: F4_NEW_FUNC, head)
    tail = pat.sub(lambda m: F4_NEW_FUNC, tail)
    return head + src[start:end] + tail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    inp = Path(args.input)
    src = inp.read_text(encoding="utf-8")

    out = Path(args.out) if args.out else inp.with_name(
        inp.name.replace("V5_2_1", "V5_2_2").replace("v5_2_1", "v5_2_2")
    )
    if out.name == inp.name:
        out = inp.with_name(inp.stem + "_v5_2_2.py")

    # F2 blob patch first (changes the blob segment boundaries)
    src = patch_blob(src)
    # F2 outer block
    src = apply_outside_blobs(src, F2_OLD, F2_NEW, 1)
    # F1/F3/F5 plain fixes
    for old, new, count in PLAIN_FIXES:
        src = apply_outside_blobs(src, old, new, count)
    # F4 function replacement
    src = patch_f4(src)
    # F6 version bump (base85 alphabet contains no '.', so blobs are unaffected)
    n_ver = src.count("5.2.1")
    if n_ver < 3:
        raise RuntimeError(f"version bump: expected >=3 occurrences of '5.2.1', found {n_ver}")
    src = src.replace("5.2.1", "5.2.2")

    compile(src, str(out), "exec")
    out.write_text(src, encoding="utf-8")
    print(f"[ok] wrote {out} ({len(src.splitlines())} lines); version markers bumped: {n_ver}")

    # verify embedded hashes of the patched file (stdlib-only path, exits before heavy imports)
    r = subprocess.run(
        [sys.executable, str(out), "--verify-embedded"],
        capture_output=True, text=True, timeout=120,
    )
    print(r.stdout.strip() or r.stderr.strip())
    if r.returncode != 0:
        print("[warn] --verify-embedded subprocess failed; inspect output above", file=sys.stderr)
        return 1
    print("[ok] embedded helper hashes verified in patched file")
    print("next: in Colab run  !python %s --self-test  before training" % out.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
