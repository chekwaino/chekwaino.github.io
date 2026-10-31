#!/usr/bin/env python3
"""make_v97_patch.py — apply the 8 reviewed fixes to the v97 DIAD preprocessing script.

Revised after an external audit (see docs/v97_patch_changes.md "audit revision").
Key changes vs v1 of this patcher:
  V2 keeps the LAST (effective) _generate_bar_from_counter definition, deletes the first
  V3 short-circuits on the *CAP* settings in CONFIG (memoised), not on function args;
     if any positional int arg is present (a cap passed directly) it never short-circuits
  V4 force/final rendering handled as kwarg OR first positional; V97_DASH_ALWAYS=1 kill-switch
  V5 matches labels in HTML text (>TOK<), as quoted string *values* ('TOK' not followed
     by ':' — so dict keys are never touched), and as bare text on HTML lines
  V6 comment is neutral (mapping kept pending a documented policy decision)
  V7 wraps both `NAME = Path(<literal with 'drive'>)` AND `'KEY': '<...drive...>'`
     string values inside CONFIG, via os.environ.get("V97_<KEY>", ...)
  V8 replaces the empty-Path CWD fallback with a LAZY guard object whose .glob() raises
     only when actually used with an unknown split (no eager raise inside dict.get)

Usage:
    python tools/make_v97_patch.py path/to/script.py [--out OUTPUT.py]
        [--align-mirai-to-block] [--dry-run]

Stdlib only. Every fix asserts its expected occurrence count and aborts without
writing on mismatch (safe-fail). Patched output is compile()-checked.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def note(msg: str) -> None:
    print(msg)


def find_all(src: str, pattern: str, flags: int = re.M):
    return list(re.compile(pattern, flags).finditer(src))


def expect(matches, count, what: str) -> None:
    if count is not None and len(matches) != count:
        raise RuntimeError(f"{what}: found {len(matches)}, expected {count}; aborting (no output written)")
    if count is None and not matches:
        raise RuntimeError(f"{what}: no match; aborting (no output written)")


# ---------------------------------------------------------------- V1 SQL ---

def fix_v1_sql(src: str) -> str:
    old = "SET count= WHERE h=?"
    if src.count(old) == 1:
        note("V1: SQL `SET count= WHERE h=?` -> `SET count=? WHERE h=?` (1 site)")
        return src.replace(old, "SET count=? WHERE h=?")
    pat = re.compile(r"SET count=\s+WHERE h=\?")
    expect(find_all(src, r"SET count=\s+WHERE h=\?"), 1, "V1 SQL marker")
    note("V1: SQL fixed via whitespace-tolerant regex (1 site)")
    return pat.sub("SET count=? WHERE h=?", src, count=1)


# ------------------------------------------------- V2 duplicate bar func ---

def fix_v2_dup_def(src: str) -> str:
    """Python semantics: the LAST def wins, so the effective implementation is the
    second one (horizontal=True). Delete the FIRST (shadowed) definition and keep
    the effective one — deleting the second would change chart orientation."""
    pat = re.compile(r"^def _generate_bar_from_counter\(.*?(?=^def |^class |^@|\Z)", re.M | re.S)
    m = list(pat.finditer(src))
    expect(m, 2, "V2 duplicate _generate_bar_from_counter")
    first = m[0]
    note(f"V2: removed the SHADOWED first _generate_bar_from_counter ({len(first.group(0).splitlines())} lines); "
         f"kept the effective later def (horizontal={ 'horizontal' in m[1].group(0) })")
    return src[: first.start()] + src[first.end() :]


# ------------------------------------------------------- V3 cap short-circuit

V3_WRAPPER = '''_V97_CAPS_DISABLED = None


def _v97_all_caps_none():
    """True when every cap-like setting in CONFIG is None (memoised once per process).

    The caps live in CONFIG (not in the per-row call arguments — the last argument
    of the original should_keep_by_caps is the counters dict), so the short-circuit
    must read CONFIG, not args. A key counts as cap-like if its name suggests a cap
    (CAP/MAX/LIMIT) and its value is None or an int; if none is found we return
    False (fail-safe: no optimisation rather than a wrong one)."""
    global _V97_CAPS_DISABLED
    if _V97_CAPS_DISABLED is None:
        try:
            keys = [
                k for k, v in CONFIG.items()
                if ("CAP" in str(k).upper() or "MAX" in str(k).upper() or "LIMIT" in str(k).upper())
                and (v is None or isinstance(v, int))
            ]
            _V97_CAPS_DISABLED = bool(keys) and all(CONFIG[k] is None for k in keys)
        except NameError:
            _V97_CAPS_DISABLED = False
    return _V97_CAPS_DISABLED


def should_keep_by_caps(*args, **kwargs):
    """V97-PATCH: short-circuit when all caps in CONFIG are disabled.

    write_pass2 calls this once per row (~35.6M times). When every *CAP* setting in
    CONFIG is None the decision is trivially 'keep'. A positional int argument is
    treated as a directly-passed cap and disables the short-circuit. Set
    V97_KEEP_CAP_COUNTERS=1 to restore the old counter-increment behaviour."""
    import os as _os
    has_direct_cap = any(isinstance(a, int) and not isinstance(a, bool) for a in args)
    if _os.environ.get("V97_KEEP_CAP_COUNTERS") != "1" and not has_direct_cap and _v97_all_caps_none():
        return True
    return _should_keep_by_caps_orig(*args, **kwargs)


'''


def fix_v3_cap_loop(src: str) -> str:
    pat = re.compile(r"^def should_keep_by_caps\(", re.M)
    expect(find_all(src, r"^def should_keep_by_caps\(", re.M), 1, "V3 should_keep_by_caps def")
    calls = find_all(src, r"should_keep_by_caps\(")
    if len(calls) < 2:
        raise RuntimeError("V3: expected >=2 should_keep_by_caps references (def + call site); aborting")
    src = pat.sub("def _should_keep_by_caps_orig(", src, count=1)
    idx = src.index("def _should_keep_by_caps_orig(")
    note(f"V3: should_keep_by_caps short-circuits on CONFIG *CAP* settings (memoised; {len(calls)} call refs; orig kept as _should_keep_by_caps_orig)")
    return src[:idx] + V3_WRAPPER + src[idx:]


# ------------------------------------------------------ V4 dashboard throttle

V4_WRAPPER = '''_V97_LAST_DASH_T = [0.0]


def update_dashboard(*args, **kwargs):
    """V97-PATCH: throttle full dashboard HTML re-renders by time, not file count.

    Renders at most once per V97_DASH_MIN_INTERVAL_S seconds (default 30). Terminal /
    forced updates are always rendered: pass force=True (kwarg or first positional
    arg) or final=True for the last call after a loop, or set V97_DASH_ALWAYS=1 to
    disable throttling entirely."""
    import os as _os
    import time as _time
    force = (
        kwargs.get("force", False)
        or kwargs.get("final", False)
        or (bool(args) and args[0] is True)
        or _os.environ.get("V97_DASH_ALWAYS") == "1"
    )
    now = _time.time()
    if not force:
        min_interval = float(_os.environ.get("V97_DASH_MIN_INTERVAL_S", "30"))
        if now - _V97_LAST_DASH_T[0] < min_interval:
            return
    _V97_LAST_DASH_T[0] = now
    return _update_dashboard_impl(*args, **kwargs)


'''


def fix_v4_dashboard(src: str) -> str:
    pat = re.compile(r"^def update_dashboard\(", re.M)
    expect(find_all(src, r"^def update_dashboard\(", re.M), 1, "V4 update_dashboard def")
    calls = find_all(src, r"update_dashboard\(")
    src = pat.sub("def _update_dashboard_impl(", src, count=1)
    idx = src.index("def _update_dashboard_impl(")
    note(f"V4: update_dashboard time-throttled (default 30s; force/final always render; {len(calls)} call refs; impl kept as _update_dashboard_impl)")
    return src[:idx] + V4_WRAPPER + src[idx:]


# -------------------------------------------------------- V5 metric labels ---

V5_LABELS = {
    "FDSS": "FDSS* JS label-drift proxy",
    "DFDI": "DFDI* JS label-drift proxy",
    "FLS": "FLS* label-drift proxy",
    "ASCS": "ASCS* label-drift proxy",
    "AIS": "AIS* leakage check (0 = no leakage)",
}


def fix_v5_metric_names(src: str) -> str:
    for tok, label in V5_LABELS.items():
        done = 0
        # pass 1: exact HTML tile text  >TOK<
        p1 = re.compile(">" + tok + "<")
        done += len(p1.findall(src))
        src = p1.sub(lambda m: ">" + label + "<", src)
        # pass 2: quoted string VALUES ('TOK' / "TOK" not followed by ':' so dict
        # keys are never rewritten) — covers labels built inside Python structures
        p2 = re.compile(r"(['\"])" + tok + r"\1(?!\s*:)")
        done += len(p2.findall(src))
        src = p2.sub(lambda m: m.group(1) + label + m.group(1), src)
        # pass 3: bare token on HTML-ish lines, never adjacent to a quote or an
        # already-qualified label
        p3 = re.compile(r"(?<![\w*\"'])" + tok + r"(?![\w*\"'])")
        matches = []
        for m in p3.finditer(src):
            ls = src.rfind("\n", 0, m.start()) + 1
            le = src.find("\n", m.end())
            le = len(src) if le == -1 else le
            if "<" in src[ls:le]:
                matches.append(m)
        result, last = [], 0
        for m in matches:
            result.append(src[last : m.start()])
            result.append(label)
            last = m.end()
        result.append(src[last:])
        src = "".join(result)
        done += len(matches)
        if done == 0:
            raise RuntimeError(
                f"V5: label {tok!r} not found (HTML text, quoted value, or bare HTML line); "
                f"aborting (no output written). Qualify it manually."
            )
        note(f"V5: proxy-metric label {tok} -> {label!r} ({done} site(s))")
    note("V5: legend: '*'-marked tiles are JS-divergence proxies computed in-script, not published metrics")
    return src


# ------------------------------------------------------------- V6 policy -----

def fix_v6_policy(src: str, align: bool) -> str:
    lines = find_all(src, r"^.*Mirai-greip_flood.*$", re.M)
    expect(lines, None, "V6 Mirai-greip_flood reference")
    if align:
        pat = re.compile(r"(['\"]Mirai-greip_flood['\"]\s*:\s*)['\"]Quarantine['\"]")
        if not pat.search(src):
            raise RuntimeError("V6 --align-mirai-to-block: no 'Mirai-greip_flood': 'Quarantine' mapping found; aborting")
        src = pat.sub(lambda m: m.group(1) + "'Block'", src)
        note("V6: Mirai-greip_flood mapping changed Quarantine -> Block (label-changing; fresh preprocessing run only)")
        return src
    target = next((mm for mm in lines if "Quarantine" in mm.group(0)), lines[0])
    indent = re.match(r"[ \t]*", target.group(0)).group(0)
    comment = (
        f"{indent}# V97-PATCH: 'Mirai-greip_flood' -> 'Quarantine' kept UNCHANGED pending a documented\n"
        f"{indent}# policy decision (other DDoS/DoS families map to 'Block'). This comment is not a\n"
        f"{indent}# validated rationale; record the decision in the policy-derivation contract.\n"
    )
    note("V6: mapping unchanged; neutral pending-decision comment inserted (use --align-mirai-to-block to change it)")
    return src[: target.start()] + comment + src[target.start() :]


# ---------------------------------------------------------- V7 env paths -----

def _env_name(key_literal: str) -> str:
    key = key_literal.strip("'\"")
    return "V97_" + re.sub(r"[^A-Za-z0-9]+", "_", key).upper().strip("_")


def fix_v7_env_paths(src: str) -> str:
    wrapped = []
    # pass A: string values containing 'drive' inside dict-style lines (CONFIG entries)
    pat_cfg = re.compile(
        r"^(?P<ind>[ \t]*)(?P<key>['\"][^'\"]+['\"])[ \t]*:[ \t]*(?P<val>['\"][^'\"]*drive[^'\"]*['\"])[ \t]*,?[ \t]*$",
        re.M | re.I,
    )

    def repl_cfg(m):
        wrapped.append(f"{m.group('key')}(cfg)")
        return f"{m.group('ind')}{m.group('key')}: os.environ.get({_env_name(m.group('key'))!r}, {m.group('val')}),"

    src = pat_cfg.sub(repl_cfg, src)
    # pass B: NAME = Path(<literal containing 'drive'>)
    pat_path = re.compile(
        r"^(?P<ind>[ \t]*)(?P<name>[A-Za-z_]\w*)[ \t]*=[ \t]*Path\((?P<rhs>[^\n]*?)\)[ \t]*(?P<comment>#.*)?$",
        re.M,
    )

    def repl_path(m):
        if "drive" not in m.group("rhs").lower():
            return m.group(0)
        wrapped.append(m.group("name"))
        comment = m.group("comment") or ""
        return f"{m.group('ind')}{m.group('name')} = Path(os.environ.get('V97_{m.group('name').upper()}', {m.group('rhs')})){comment}"

    src = pat_path.sub(repl_path, src)
    if not wrapped:
        raise RuntimeError("V7: no hardcoded Drive paths found (neither CONFIG string values nor Path literals); aborting")
    if not re.search(r"^import os\b", src, re.M):
        m = re.search(r"^import \w", src, re.M)
        if not m:
            raise RuntimeError("V7: no import line found to anchor `import os`; aborting")
        src = src[: m.start()] + "import os  # V97-PATCH: for env-based path overrides\n" + src[m.start() :]
        note("V7: added `import os`")
    note(f"V7: env-wrapped Drive paths ({len(wrapped)}): {', '.join(wrapped)} — override via V97_<NAME>")
    return src


# ------------------------------------------------------------- V8 guards -----

V8_GUARD = '''class _V97UnknownSplitDir:
    """V97-PATCH: lazy stand-in for the old Path('') CWD fallback.

    Instantiating is side-effect free (safe as a dict.get default); any actual use
    raises, so an unknown split can never silently glob the current working
    directory."""

    def glob(self, *args, **kwargs):
        raise RuntimeError(
            "_sample_npz: unknown split — refusing to glob the current working "
            "directory (V97-PATCH guard; pass an explicit shard directory instead)"
        )

    def __getattr__(self, name):
        raise RuntimeError("_sample_npz: unknown split — refusing CWD access (V97-PATCH guard)")


'''


def fix_v8_minor(src: str) -> str:
    hdrs = find_all(src, r"^# VALIDATION[ \t]*$", re.M)
    expect(hdrs, 2, "V8 duplicate '# VALIDATION' header")
    second = hdrs[1]
    end = second.end()
    if src[end : end + 1] == "\n":
        end += 1
    src = src[: second.start()] + src[end:]
    note("V8: removed duplicate '# VALIDATION' header (2nd of 2)")

    pat_empty = re.compile(r"""Path\(["']{2}\)""")
    expect(find_all(src, r"""Path\(["']{2}\)"""), 1, "V8 empty-Path() CWD fallback")
    expect(find_all(src, r"^def _sample_npz\(", re.M), 1, "V8 _sample_npz def")
    src = pat_empty.sub("_V97UnknownSplitDir()", src, count=1)
    idx = re.search(r"^def _sample_npz\(", src, re.M).start()
    src = src[:idx] + V8_GUARD + src[idx:]
    note("V8: empty-Path CWD fallback replaced by a lazy guard — raises only when an unknown split is actually globbed")
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
                    help="V6: change Mirai-greip_flood policy Quarantine -> Block (label-changing; fresh run only)")
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
    print("next: smoke-test on a tiny subset before the full 35.6M-row run; "
          "terminal dashboard call should pass force=True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
