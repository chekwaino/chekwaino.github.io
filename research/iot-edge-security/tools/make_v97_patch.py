#!/usr/bin/env python3
"""make_v97_patch.py — apply the 8 reviewed fixes to the v97 DIAD preprocessing script.

Usage:
    python tools/make_v97_patch.py path/to/objective_i_hybrid_security_feature_preprocessing_v97.py \
        [--out OUTPUT.py] [--align-mirai-to-block] [--dry-run]

Default output: <stem>_PATCHED.py next to the input. Stdlib only.

Fixes (docs/preprocessing_v97_review.md, "Bugs found"):
  V1  SQL syntax: `SET count= WHERE h=?` -> `SET count=? WHERE h=?`
  V2  delete the duplicate (second) `_generate_bar_from_counter` definition
  V3  short-circuit `should_keep_by_caps` when all caps are None (per-row loop over
      ~35M rows); original kept as `_should_keep_by_caps_orig`; V97_KEEP_CAP_COUNTERS=1
      restores the old counter-increment behaviour
  V4  throttle `update_dashboard` by time (V97_DASH_MIN_INTERVAL_S, default 30s)
      instead of every 10 files; original kept as `_update_dashboard_impl`
  V5  qualify proxy-metric tile labels (FDSS/DFDI/FLS/ASCS/AIS -> "* proxy" labels)
  V6  document the Mirai-greip_flood -> Quarantine policy decision inline;
      --align-mirai-to-block instead changes the mapping to Block
  V7  wrap hardcoded Drive Path assignments (RAW_DIR, OUI_PATH, OUT_ROOT, cache, ...)
      in os.environ.get("V97_<NAME>", <original>) — any Path(...) literal containing
      'drive' is wrapped; `import os` is added if missing
  V8  remove the duplicate `# VALIDATION` header; guard `_sample_npz`'s
      Path("").glob CWD fallback with a loud error

Every fix asserts its expected occurrence count and aborts without writing on
mismatch (safe-fail). The patched output is compile()-checked. Run with --dry-run
first to see the per-fix report.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPORT: list[str] = []


def note(msg: str) -> None:
    REPORT.append(msg)
    print(msg)


def find_all(src: str, pattern: str, flags: int = re.M) -> list[re.Match]:
    return list(re.compile(pattern, flags).finditer(src))


def expect(matches: list[re.Match], count, what: str) -> None:
    if count is not None and len(matches) != count:
        raise RuntimeError(f"{what}: found {len(matches)}, expected {count}; aborting (no output written)")
    if count is None and not matches:
        raise RuntimeError(f"{what}: no match; aborting (no output written)")


# ---------------------------------------------------------------- fixes ----

def fix_v1_sql(src: str) -> str:
    old = "SET count= WHERE h=?"
    if src.count(old) == 1:
        note("V1: SQL `SET count= WHERE h=?` -> `SET count=? WHERE h=?` (1 site)")
        return src.replace(old, "SET count=? WHERE h=?")
    pat = re.compile(r"SET count=\s+WHERE h=\?")
    m = find_all(src, r"SET count=\s+WHERE h=\?")
    expect(m, 1, "V1 SQL marker")
    note("V1: SQL fixed via whitespace-tolerant regex (1 site)")
    return pat.sub("SET count=? WHERE h=?", src, count=1)


def fix_v2_dup_def(src: str) -> str:
    pat = re.compile(r"^def _generate_bar_from_counter\(.*?(?=^def |^class |^@|\Z)", re.M | re.S)
    m = find_all(src, r"^def _generate_bar_from_counter\(.*?(?=^def |^class |^@|\Z)", re.M | re.S)
    expect(m, 2, "V2 duplicate _generate_bar_from_counter")
    second = m[1]
    if "horizontal" not in second.group(0):
        raise RuntimeError("V2: second def does not mention 'horizontal'; aborting")
    note(f"V2: removed duplicate _generate_bar_from_counter (2nd of 2, {len(second.group(0).splitlines())} lines)")
    return src[: second.start()] + src[second.end() :]


V3_WRAPPER = '''def should_keep_by_caps(*args, **kwargs):
    """V97-PATCH: short-circuit the per-row cap check when every cap is None.

    write_pass2 calls this once per row (~35M times); with all caps None the
    decision is trivially 'keep'. Set V97_KEEP_CAP_COUNTERS=1 to restore the old
    counter-increment behaviour."""
    import os as _os
    if _os.environ.get("V97_KEEP_CAP_COUNTERS") != "1":
        caps = args[-1] if args else kwargs.get("caps", kwargs.get("cap"))
        if caps is None:
            return True
        if not isinstance(caps, (int, float, str, bool)):
            vals = caps.values() if isinstance(caps, dict) else caps
            try:
                if all(v is None for v in vals):
                    return True
            except TypeError:
                pass
    return _should_keep_by_caps_orig(*args, **kwargs)


'''


def fix_v3_cap_loop(src: str) -> str:
    pat = re.compile(r"^def should_keep_by_caps\(", re.M)
    m = find_all(src, r"^def should_keep_by_caps\(", re.M)
    expect(m, 1, "V3 should_keep_by_caps def")
    calls = find_all(src, r"should_keep_by_caps\(")
    if len(calls) < 2:
        raise RuntimeError("V3: expected >=2 should_keep_by_caps references (def + call site); aborting")
    src = pat.sub("def _should_keep_by_caps_orig(", src, count=1)
    idx = src.index("def _should_keep_by_caps_orig(")
    note(f"V3: should_keep_by_caps wrapped with all-caps-None short-circuit ({len(calls)} call refs; orig kept as _should_keep_by_caps_orig)")
    return src[:idx] + V3_WRAPPER + src[idx:]


V4_WRAPPER = '''_V97_LAST_DASH_T = [0.0]


def update_dashboard(*args, **kwargs):
    """V97-PATCH: throttle full dashboard HTML re-renders by time, not file count.

    The original re-rendered the whole template every 10 files; during Pass 2 that
    is a ~30KB+ render per 10 shards. Now at most one render per
    V97_DASH_MIN_INTERVAL_S seconds (default 30), unless force=True is passed."""
    import os as _os
    import time as _time
    if not kwargs.get("force", False):
        min_interval = float(_os.environ.get("V97_DASH_MIN_INTERVAL_S", "30"))
        now = _time.time()
        if now - _V97_LAST_DASH_T[0] < min_interval:
            return
        _V97_LAST_DASH_T[0] = now
    return _update_dashboard_impl(*args, **kwargs)


'''


def fix_v4_dashboard(src: str) -> str:
    pat = re.compile(r"^def update_dashboard\(", re.M)
    m = find_all(src, r"^def update_dashboard\(", re.M)
    expect(m, 1, "V4 update_dashboard def")
    calls = find_all(src, r"update_dashboard\(")
    src = pat.sub("def _update_dashboard_impl(", src, count=1)
    idx = src.index("def _update_dashboard_impl(")
    note(f"V4: update_dashboard time-throttled (V97_DASH_MIN_INTERVAL_S, default 30s; {len(calls)} call refs; impl kept as _update_dashboard_impl)")
    return src[:idx] + V4_WRAPPER + src[idx:]


V5_LABELS = {
    "FDSS": "FDSS* JS label-drift proxy",
    "DFDI": "DFDI* JS label-drift proxy",
    "FLS": "FLS* label-drift proxy",
    "ASCS": "ASCS* label-drift proxy",
    "AIS": "AIS* leakage check (0 = no leakage)",
}


def fix_v5_metric_names(src: str) -> str:
    # Only BARE tokens on HTML-ish lines (contains '<') are display labels.
    # Quoted tokens are deliberately left alone: replacing them can break
    # f-string delimiters and could hit dict keys used by the code.
    for tok, label in V5_LABELS.items():
        # pass 1: exact tile text  >TOK<
        p1 = re.compile(">" + tok + "<")
        n1 = len(p1.findall(src))
        src = p1.sub(">" + label + "<", src)
        # pass 2 (fallback): bare token on HTML lines, but never adjacent to a
        # quote or to an already-qualified label — quoted tokens inside f-strings
        # and dict keys must not be touched
        p2 = re.compile(r"(?<![\w*\"'])" + tok + r"(?![\w*\"'])")
        matches = [
            m for m in p2.finditer(src)
            if "<" in src[src.rfind("\n", 0, m.start()) + 1 : (src.find("\n", m.end()) if src.find("\n", m.end()) != -1 else len(src))]
        ]
        result, last = [], 0
        for m in matches:
            result.append(src[last : m.start()])
            result.append(label)
            last = m.end()
        result.append(src[last:])
        src = "".join(result)
        done = n1 + len(matches)
        if done == 0:
            raise RuntimeError(
                f"V5: tile label {tok!r} not found as HTML text; aborting (no output written). "
                f"If it only appears quoted in code, qualify it manually."
            )
        note(f"V5: proxy-metric label {tok} qualified -> {label!r} ({done} HTML site(s))")
    note("V5: legend: '*'-marked tiles are JS-divergence proxies computed in-script, not published metrics")
    return src


def fix_v6_policy(src: str, align: bool) -> str:
    lines = find_all(src, r"^.*Mirai-greip_flood.*$", re.M)
    expect(lines, None, "V6 Mirai-greip_flood reference")
    if align:
        pat = re.compile(r"(['\"]Mirai-greip_flood['\"]\s*:\s*)['\"]Quarantine['\"]")
        m = pat.findall(src)
        if not m:
            raise RuntimeError("V6 --align-mirai-to-block: no 'Mirai-greip_flood': 'Quarantine' mapping found; aborting")
        src = pat.sub(r"\1'Block'", src)
        note(f"V6: Mirai-greip_flood mapping changed Quarantine -> Block ({len(m)} site(s))")
        return src
    # default: document the rationale inline, keep behaviour
    target = None
    for mm in lines:
        if "Quarantine" in mm.group(0):
            target = mm
            break
    if target is None:
        target = lines[0]
    indent = re.match(r"[ \t]*", target.group(0)).group(0)
    comment = (
        f"{indent}# V97-PATCH: Mirai-greip_flood -> Quarantine is intentional and documented:\n"
        f"{indent}# Mirai is self-propagating worm traffic, so device-level Quarantine (the most\n"
        f"{indent}# severe action) is the rationale; all other DDoS/DoS families map to Block.\n"
    )
    note("V6: documented Mirai-greip_flood -> Quarantine rationale inline (behaviour unchanged; use --align-mirai-to-block to change it)")
    return src[: target.start()] + comment + src[target.start() :]


def fix_v7_env_paths(src: str) -> str:
    pat = re.compile(
        r"^(?P<ind>[ \t]*)(?P<name>[A-Za-z_]\w*)[ \t]*=[ \t]*Path\((?P<rhs>[^\n]*?)\)[ \t]*(?P<comment>#.*)?$",
        re.M,
    )
    wrapped = []
    out = []
    last = 0
    for m in pat.finditer(src):
        rhs = m.group("rhs")
        if "drive" not in rhs.lower():
            continue
        name = m.group("name")
        comment = m.group("comment") or ""
        repl = f'{m.group("ind")}{name} = Path(os.environ.get("V97_{name.upper()}", {rhs})){comment}'
        out.append(src[last : m.start()])
        out.append(repl)
        last = m.end()
        wrapped.append(name)
    if not wrapped:
        raise RuntimeError("V7: no hardcoded Drive Path assignments found; aborting (no output written)")
    out.append(src[last:])
    src = "".join(out)
    if not re.search(r"^import os\b", src, re.M):
        m = re.search(r"^import \w", src, re.M)
        if not m:
            raise RuntimeError("V7: no import line found to anchor `import os`; aborting")
        src = src[: m.start()] + "import os  # V97-PATCH: for env-based path overrides\n" + src[m.start() :]
        note("V7: added `import os`")
    note(f"V7: env-wrapped Drive paths: {', '.join(wrapped)} (override via V97_<NAME>)")
    return src


def fix_v8_minor(src: str) -> str:
    hdrs = find_all(src, r"^# VALIDATION[ \t]*$", re.M)
    expect(hdrs, 2, "V8 duplicate '# VALIDATION' header")
    second = hdrs[1]
    # remove the whole line including its newline
    end = second.end()
    if src[end : end + 1] == "\n":
        end += 1
    src = src[: second.start()] + src[end:]
    note("V8: removed duplicate '# VALIDATION' header (2nd of 2)")

    pat_glob = re.compile(r"""Path\(["']{2}\)""")
    expect(find_all(src, r"""Path\(["']{2}\)"""), 1, "V8 empty-Path() CWD fallback")
    guard = (
        "def _v97_refuse_cwd_glob():\n"
        "    raise RuntimeError(\n"
        "        \"_sample_npz: unknown split — refusing to glob the current working directory \"\n"
        "        \"(V97-PATCH guard; pass an explicit shard directory instead)\",\n"
        "    )\n\n\n"
    )
    expect(find_all(src, r"^def _sample_npz\(", re.M), 1, "V8 _sample_npz def")
    src = pat_glob.sub("_v97_refuse_cwd_glob()", src, count=1)
    idx = re.search(r"^def _sample_npz\(", src, re.M).start()
    src = src[:idx] + guard + src[idx:]
    note("V8: _sample_npz CWD-glob fallback now raises loudly instead of reading the CWD")
    return src


FIXES = [
    ("V1", fix_v1_sql),
    ("V2", fix_v2_dup_def),
    ("V3", fix_v3_cap_loop),
    ("V4", fix_v4_dashboard),
    ("V5", fix_v5_metric_names),
    ("V7", fix_v7_env_paths),
    ("V8", fix_v8_minor),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("--out", default=None)
    ap.add_argument("--align-mirai-to-block", action="store_true",
                    help="V6: change Mirai-greip_flood policy Quarantine -> Block instead of only documenting it")
    ap.add_argument("--dry-run", action="store_true", help="report fixes without writing output")
    args = ap.parse_args()

    inp = Path(args.input)
    src = inp.read_text(encoding="utf-8")
    for fix_id, fn in FIXES:
        src = fn(src)
    src = fix_v6_policy(src, align=args.align_mirai_to_block)

    compile(src, "<patched>", "exec")
    note("compile check: OK")

    if args.dry_run:
        print("\n[dry-run] no output written")
        return 0
    out = Path(args.out) if args.out else inp.with_name(inp.stem + "_PATCHED.py")
    out.write_text(src, encoding="utf-8")
    print(f"\n[ok] wrote {out} ({len(src.splitlines())} lines)")
    print("next: in Colab run  !python %s --help  (or your usual smoke run) on a tiny subset first" % out.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
