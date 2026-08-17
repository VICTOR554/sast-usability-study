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
import gzip
import json
import re
from collections import defaultdict
from pathlib import Path


def load_json(path: Path):
    """Scan files over 1 MB are gzipped, so both forms have to be readable."""
    if str(path).endswith(".gz"):
        with gzip.open(path, "rt") as f:
            return json.load(f)
    with open(path) as f:
        return json.load(f)


def scan_files(tool: str, ext: str):
    """Every scan result for a tool, compressed or not."""
    d = RUNS / tool
    return sorted(list(d.glob(f"*{ext}")) + list(d.glob(f"*{ext}.gz")))

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
SOURCES_CSV = ROOT / "sources.csv"

# Variants are grouped together. The CWE-79 family counts as XSS, and
# relative and absolute path traversal count as one type.
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
    "shell-command-constructed-from-input":
        ("cmd-injection", "tagged for path traversal as well, but the rule is "
                          "about building a shell command from user input"),
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
    that came from the CWE tag or from an override.

    A rule pointing at more than one of the four types is left unclassified.
    CodeQL tags js/prototype-polluting-assignment with CWE-78, 79, 94, 400,
    471 and 915, being everything prototype pollution could lead to. Taking
    the first match filed it as command injection, and it reached the survey
    before anyone read the warning."""
    for frag, (vt, _reason) in RULE_OVERRIDES.items():
        if frag in (rule_id or ""):
            return vt, "override"
    hits = {CWE_MAP[c] for c in cwes if c in CWE_MAP}
    if len(hits) == 1:
        return hits.pop(), "cwe"
    return None, None


def norm_path(path: str) -> str:
    """Same file, same string, whichever tool reported it.

    Semgrep prints the full path of the copy it scanned, while CodeQL and
    Bearer print it relative to the source. Left alone, one file counts two
    or three times and no file ever looks like all three tools found it."""
    p = str(path).replace("\\", "/")
    m = re.search(r"/scan(?:ql)?-[^/]+/(.*)$", p)
    if m:
        return m.group(1)
    return p.lstrip("./")


def excluded(path):
    p = Path(path)
    if set(p.parts) & EXCLUDE_PATH_PARTS:
        return True
    if p.name in EXCLUDE_NAMES:
        return True
    return p.suffix in EXCLUDE_SUFFIXES


def codeql_scanned(project):
    """Files CodeQL indexed for this source. Juliet is scoped for CodeQL but
    scanned in full by the other two, so a file only Semgrep saw would look
    like CodeQL missed it. Candidates are limited to what all three read.

    Missing output stops the run rather than returning nothing. Skipping the
    check silently gave a wrong matrix that looked right once already."""
    for p in (RUNS / "codeql" / f"{project}.sarif",
              RUNS / "codeql" / f"{project}.sarif.gz"):
        if p.exists():
            break
    else:
        raise SystemExit(f"no CodeQL output for {project} - "
                         f"cannot check which files it read")
    run = load_json(p)["runs"][0]
    return {Path(a.get("location", {}).get("uri", "")).name
            for a in run.get("artifacts", [])}


def load_all():
    """Reads every scan file and returns one row per finding."""
    langs = {}
    with open(SOURCES_CSV) as f:
        for r in csv.DictReader(f):
            langs[r["source_id"]] = r["language"]

    for p in scan_files("semgrep", ".json"):
        proj = p.name.split(".")[0]
        if proj not in langs:
            continue
        for r in load_json(p).get("results", []):
            vt, basis = classify(r["check_id"], cwe_from_semgrep(r))
            yield (proj, langs[proj], "semgrep", r["check_id"], vt, basis,
                   norm_path(r["path"]), r.get("start", {}).get("line"))

    for p in scan_files("codeql", ".sarif"):
        proj = p.name.split(".")[0]
        if proj not in langs:
            continue
        run = load_json(p)["runs"][0]
        rules = {x["id"]: x for x in run["tool"]["driver"].get("rules", [])}
        for r in run.get("results", []):
            rid = r.get("ruleId")
            vt, basis = classify(rid, cwe_from_codeql(rules.get(rid, {})))
            L = r["locations"][0]["physicalLocation"]
            yield (proj, langs[proj], "codeql", rid, vt, basis,
                   norm_path(L["artifactLocation"]["uri"]), L["region"].get("startLine"))

    for p in scan_files("bearer", ".json"):
        proj = p.name.split(".")[0]
        if proj not in langs:
            continue
        d = load_json(p)
        for sev in ("critical", "high", "medium", "low", "warning"):
            for x in d.get(sev) or []:
                cwes = [str(int(c)) for c in (x.get("cwe_ids") or []) if str(c).isdigit()]
                vt, basis = classify(x.get("id"), cwes)
                yield (proj, langs[proj], "bearer", x.get("id"), vt, basis,
                       norm_path(x.get("filename") or ""), x.get("line_number"))


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

    ql_seen = {}
    cells = defaultdict(lambda: defaultdict(set))
    dropped = 0
    for (proj, lang, tool, rid, vt, basis, path, line) in rows:
        if vt is None or not path or excluded(path):
            continue
        if proj not in ql_seen:
            ql_seen[proj] = codeql_scanned(proj)
        seen = ql_seen[proj]
        if seen is not None and Path(path).name not in seen:
            dropped += 1
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
    if dropped:
        print(f"{dropped} findings excluded: file not scanned by CodeQL")
    if short:
        print(f"\n{short} cell(s) below target")


if __name__ == "__main__":
    main()
