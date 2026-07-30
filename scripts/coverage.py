#!/usr/bin/env python3
"""Classify scan output and report candidates per cell.

Reads runs/ and answers two things: how many candidate examples exist for
each language and vulnerability type, and which findings could not be
classified.

Classification uses CWE from each tool's own metadata, not rule names,
because rule naming differs between tools and changes between versions.

    CodeQL   rule tags, "external/cwe/cwe-089"
    Bearer   cwe_ids, ["89"]
    Semgrep  rule metadata cwe, ["CWE-89: ..."]

A few Semgrep rules carry wrong CWE tags. Those are corrected in
RULE_OVERRIDES so every correction stays visible.

    python3 scripts/coverage.py                # matrix
    python3 scripts/coverage.py --candidates   # files per cell
    python3 scripts/coverage.py --unclassified # findings with no mapping
"""  

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
SOURCES_CSV = ROOT / "sources.csv"

# Variants are grouped: the CWE-79 family counts as XSS, relative and
# absolute path traversal count as one.
CWE_MAP = {
    "89": "sqli",
    "79": "xss", "80": "xss", "81": "xss", "83": "xss", "116": "xss",
    "22": "path-traversal", "23": "path-traversal", "35": "path-traversal",
    "36": "path-traversal", "73": "path-traversal",
    "78": "cmd-injection", "77": "cmd-injection", "88": "cmd-injection",
}

# Matched against rule id. Each entry needs a reason.
RULE_OVERRIDES = {
    "tainted-sql-string": ("sqli", "Semgrep tags CWE-915/704, rule detects SQL injection"),
    "subprocess-injection": ("cmd-injection", "shell command built from user input"),
    "subprocess-shell-true": ("cmd-injection", "shell=True with dynamic argument"),
}

VULN_TYPES = ["sqli", "xss", "path-traversal", "cmd-injection"]
LANGS = ["java", "python", "javascript"]

# Not candidate examples even when flagged: third-party libraries, build
# tooling, CI config. A warning about code the developers did not write
# says nothing about whether they could act on it.
EXCLUDE_PATH_PARTS = {"vendor", "node_modules", "assets", ".github", "dist", "build"}
EXCLUDE_NAMES = {"Gruntfile.js", "gulpfile.js", "webpack.config.js"}
EXCLUDE_SUFFIXES = {".yml", ".yaml", ".json", ".lock", ".md"}


def cwe_from_codeql(rule):
    out = []
    for t in rule.get("properties", {}).get("tags", []):
        m = re.search(r"cwe[-/](\d+)", t, re.I)
        if m:
            out.append(str(int(m.group(1))))
    return out


def cwe_from_semgrep(result):
    out = []
    for c in result.get("extra", {}).get("metadata", {}).get("cwe", []) or []:
        m = re.search(r"CWE-(\d+)", c)
        if m:
            out.append(str(int(m.group(1))))
    return out


def classify(rule_id, cwes):
    """Works out which vulnerability type a finding belongs to, and whether
    that came from the CWE tag or from an override."""
    for frag, (vt, _reason) in RULE_OVERRIDES.items():
        if frag in (rule_id or ""):
            return vt, "override"
    for c in cwes:
        if c in CWE_MAP:
            return CWE_MAP[c], "cwe"
    return None, None


def excluded(path):
    p = Path(path)
    if set(p.parts) & EXCLUDE_PATH_PARTS:
        return True
    if p.name in EXCLUDE_NAMES:
        return True
    return p.suffix in EXCLUDE_SUFFIXES


def load_all():
    """Reads every scan file and returns one row per finding."""
    langs = {}
    with open(SOURCES_CSV) as f:
        for r in csv.DictReader(f):
            langs[r["source_id"]] = r["language"]

    for p in sorted((RUNS / "semgrep").glob("*.json")):
        proj = p.stem
        if proj not in langs:
            continue
        for r in json.load(open(p)).get("results", []):
            vt, basis = classify(r["check_id"], cwe_from_semgrep(r))
            yield (proj, langs[proj], "semgrep", r["check_id"], vt, basis,
                   r["path"], r.get("start", {}).get("line"))

    for p in sorted((RUNS / "codeql").glob("*.sarif")):
        proj = p.stem
        if proj not in langs:
            continue
        run = json.load(open(p))["runs"][0]
        rules = {x["id"]: x for x in run["tool"]["driver"].get("rules", [])}
        for r in run.get("results", []):
            rid = r.get("ruleId")
            vt, basis = classify(rid, cwe_from_codeql(rules.get(rid, {})))
            L = r["locations"][0]["physicalLocation"]
            yield (proj, langs[proj], "codeql", rid, vt, basis,
                   L["artifactLocation"]["uri"], L["region"].get("startLine"))

    for p in sorted((RUNS / "bearer").glob("*.json")):
        proj = p.stem
        if proj not in langs:
            continue
        d = json.load(open(p))
        for sev in ("critical", "high", "medium", "low", "warning"):
            for x in d.get(sev) or []:
                cwes = [str(int(c)) for c in (x.get("cwe_ids") or []) if str(c).isdigit()]
                vt, basis = classify(x.get("id"), cwes)
                yield (proj, langs[proj], "bearer", x.get("id"), vt, basis,
                       x.get("filename") or "", x.get("line_number"))


def main():
    """Prints the coverage matrix, or the candidate list if asked for it."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", action="store_true",
                    help="list candidate files per cell")
    ap.add_argument("--unclassified", action="store_true",
                    help="list findings with no CWE mapping")
    ap.add_argument("--min", type=int, default=5,
                    help="target examples per cell")
    args = ap.parse_args()

    rows = list(load_all())
    if not rows:
        raise SystemExit("no scan output in runs/ - run run_scans.py first")

    if args.unclassified:
        unmapped = defaultdict(int)
        for (_p, _l, tool, rid, vt, _b, _f, _n) in rows:
            if vt is None:
                unmapped[(tool, rid)] += 1
        print(f"{len(unmapped)} distinct unclassified rules "
              f"({sum(unmapped.values())} findings)\n")
        for (tool, rid), n in sorted(unmapped.items(), key=lambda kv: -kv[1])[:40]:
            print(f"  {n:5d}  [{tool:8s}] {rid}")
        return

    cells = defaultdict(lambda: defaultdict(set))
    for (proj, lang, tool, rid, vt, basis, path, line) in rows:
        if vt is None or not path or excluded(path):
            continue
        cells[(lang, vt)][f"{proj}:{path}"].add(tool)

    if args.candidates:
        for lang in LANGS:
            for vt in VULN_TYPES:
                files = cells[(lang, vt)]
                print(f"\n--- {lang} / {vt}: {len(files)} candidate files ---")
                ranked = sorted(files.items(), key=lambda kv: (-len(kv[1]), kv[0]))
                for f, tools in ranked[:12]:
                    print(f"    {f[:76]:76s} {sorted(tools)}")
        return

    print(f"{'':12s} " + "".join(f"{v:>16s}" for v in VULN_TYPES))
    print("-" * 76)
    short = 0
    for lang in LANGS:
        line = f"{lang:12s} "
        for vt in VULN_TYPES:
            n = len(cells[(lang, vt)])
            flag = " " if n >= args.min else "*"
            if n < args.min:
                short += 1
            line += f"{str(n) + flag:>16s}"
        print(line)
    print("-" * 76)
    print(f"(files per cell; * = fewer than {args.min})")
    if short:
        print(f"\n{short} cell(s) below target")


if __name__ == "__main__":
    main()
