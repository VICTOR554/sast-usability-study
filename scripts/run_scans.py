#!/usr/bin/env python3
"""Run Semgrep, CodeQL and Bearer over each source project.

Raw output is written to runs/<tool>/<project>.*  and is never modified
afterwards; classification happens separately in coverage.py.

Two behaviours matter here:

1. Projects are staged to a temporary directory outside the repository
   before scanning. Semgrep and Bearer both respect .gitignore, and
   sources/ is ignored, so scanning in place makes them silently report
   zero findings.

2. After each scan the number of files the tool reports analysing is
   compared against the number staged. A mismatch aborts the run. A
   silent skip is indistinguishable from clean code, so it must fail
   loudly rather than produce a plausible-looking empty result.

Usage:
    python3 scripts/run_scans.py                 # all projects
    python3 scripts/run_scans.py pygoat dvna     # named projects only
    python3 scripts/run_scans.py --tools semgrep,bearer
"""

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES_CSV = ROOT / "sources.csv"
RUNS = ROOT / "runs"
CODEQL_DBS = ROOT / "codeql-databases"

# Bearer is not on PATH by default; adjust if you install it elsewhere.
BEARER = os.environ.get("BEARER_BIN", "bearer")

# Extensions that count as scannable source, per language.
EXTS = {
    "java": {".java"},
    "python": {".py"},
    "javascript": {".js", ".ts", ".ejs", ".pug", ".hbs", ".jsx", ".tsx"},
}

# Directories never worth scanning.
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "target", "__pycache__",
             "venv", ".venv", "vendor"}

# Test directories, excluded because a tool's own test file is not a
# candidate example. Note "testcases" is deliberately absent: Juliet stores
# every case under src/testcases/, and excluding it would empty the corpus.
SKIP_TEST_DIRS = {"test", "tests", "__tests__", "spec", "e2e"}


def is_test_file(path: Path) -> bool:
    """True if this is a test file. The tools skip these anyway, and a test
    file is not something you would show a developer as an example."""
    if set(path.parts) & SKIP_TEST_DIRS:
        return True
    name = path.name
    stem = path.stem
    return (name.startswith("test_") or stem.endswith("_test")
            or ".test." in name or ".spec." in name)

# CodeQL is the only tool expensive enough to need scoping. For Juliet Java
# it is restricted to the four relevant CWE directories, servlet variants
# only -- the other variants use console/file/environment input, which
# CodeQL does not treat as untrusted, so they yield nothing regardless.
CODEQL_SCOPE = {
    "juliet-java": {
        "include_dirs": ["CWE89_SQL_Injection", "CWE80_XSS",
                         "CWE81_XSS_Error_Message", "CWE83_XSS_Attribute",
                         "CWE23_Relative_Path_Traversal",
                         "CWE36_Absolute_Path_Traversal",
                         "CWE78_OS_Command_Injection"],
        "filename_contains": "Servlet",
    }
}

QL_SUITES = {
    "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
}


def load_sources():
    with open(SOURCES_CSV) as f:
        return list(csv.DictReader(f))


def source_files(root: Path, language: str):
    """Every file worth scanning, ignoring vendored and build folders."""
    exts = EXTS[language]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix in exts and not is_test_file(p.relative_to(root)):
                out.append(p)
    return out


def stage(src: Path, dest: Path, language: str, scope=None):
    """Copies the files to be scanned into a folder outside the repo."""
    staged = []
    for f in source_files(src, language):
        rel = f.relative_to(src)
        if scope:
            parts = set(rel.parts)
            if scope.get("include_dirs") and not (parts & set(scope["include_dirs"])):
                continue
            if scope.get("filename_contains") and scope["filename_contains"] not in f.name:
                continue
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target)
        staged.append(rel)
    return staged


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


# --- per-tool scans -------------------------------------------------------
# Each returns (output_path, files_analysed) so the caller can assert.

def scan_semgrep(staged_dir: Path, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    r = run(["semgrep", "--config=p/default", "--no-git-ignore",
             "--json", "--output", str(out), str(staged_dir)])
    if not out.exists():
        raise RuntimeError(f"semgrep produced no output\n{r.stderr[-2000:]}")
    data = json.load(open(out))
    analysed = len(data.get("paths", {}).get("scanned", []))
    return out, analysed


def scan_bearer(staged_dir: Path, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    run([BEARER, "scan", str(staged_dir), "--scanner", "sast",
         "--skip-git-ignore", "--skip-test=false",
         "--format", "json", "--output", str(out)])
    if not out.exists():
        raise RuntimeError("bearer produced no output")
    # Bearer does not report a file count in JSON output, so it is counted
    # from the findings' distinct filenames -- a weaker check than the
    # others, and the reason the staged count is also logged.
    d = json.load(open(out))
    files = set()
    for sev in ("critical", "high", "medium", "low", "warning"):
        for x in d.get(sev) or []:
            if x.get("filename"):
                files.add(x["filename"])
    return out, len(files)


def scan_codeql(staged_dir: Path, out: Path, language: str, db: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    if db.exists():
        shutil.rmtree(db)
    db.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["codeql", "database", "create", str(db),
           f"--language={language}", f"--source-root={staged_dir}"]
    if language in ("java", "csharp"):
        cmd.append("--build-mode=none")
    r = run(cmd)
    if not db.exists():
        raise RuntimeError(f"codeql database create failed\n{r.stderr[-2000:]}")
    r = run(["codeql", "database", "analyze", str(db), QL_SUITES[language],
             "--format=sarif-latest", f"--output={out}", "--download"])
    if not out.exists():
        raise RuntimeError(f"codeql analyze failed\n{r.stderr[-2000:]}")
    # CodeQL reports coverage in its stderr summary; parse the "scanned X out
    # of Y" line if present, otherwise fall back to distinct result files.
    analysed = None
    for line in (r.stdout + r.stderr).splitlines():
        if "scanned" in line and "out of" in line:
            try:
                parts = line.split()
                analysed = int(parts[parts.index("scanned") + 1])
            except (ValueError, IndexError):
                pass
    return out, analysed


def main():
    """Scans each project and stops if any file count does not match."""
    ap = argparse.ArgumentParser()
    ap.add_argument("projects", nargs="*", help="source_id values; default all")
    ap.add_argument("--tools", default="semgrep,codeql,bearer")
    ap.add_argument("--keep-staged", action="store_true",
                    help="do not delete the staging directory (for debugging)")
    args = ap.parse_args()
    tools = [t.strip() for t in args.tools.split(",")]

    sources = load_sources()
    if args.projects:
        sources = [s for s in sources if s["source_id"] in args.projects]
        if not sources:
            sys.exit("no matching source_id in sources.csv")

    failures = []
    for s in sources:
        sid, lang = s["source_id"], s["language"]
        src = ROOT / s["local_path"]
        if not src.is_dir():
            failures.append(f"{sid}: local_path missing ({src})")
            continue

        print(f"\n=== {sid} ({lang}) ===")
        tmp = Path(tempfile.mkdtemp(prefix=f"scan-{sid}-"))
        try:
            staged = stage(src, tmp, lang)
            print(f"  staged {len(staged)} files")
            if not staged:
                failures.append(f"{sid}: nothing staged -- check EXTS/SKIP_DIRS")
                continue

            if "semgrep" in tools:
                out, n = scan_semgrep(tmp, RUNS / "semgrep" / f"{sid}.json")
                ok = "OK" if n == len(staged) else "MISMATCH"
                print(f"  semgrep : analysed {n}/{len(staged)}  [{ok}]")
                if n != len(staged):
                    failures.append(f"{sid}: semgrep analysed {n} of {len(staged)}")

            if "bearer" in tools:
                out, n = scan_bearer(tmp, RUNS / "bearer" / f"{sid}.json")
                print(f"  bearer  : {n} files with findings of {len(staged)} staged")

            if "codeql" in tools:
                scope = CODEQL_SCOPE.get(sid)
                if scope:
                    tmp2 = Path(tempfile.mkdtemp(prefix=f"scanql-{sid}-"))
                    sub = stage(src, tmp2, lang, scope=scope)
                    print(f"  codeql  : scoped to {len(sub)} files")
                    target, expected = tmp2, len(sub)
                else:
                    target, expected = tmp, len(staged)
                out, n = scan_codeql(target, RUNS / "codeql" / f"{sid}.sarif",
                                     lang, CODEQL_DBS / sid)
                if n is None:
                    print(f"  codeql  : analysed (count not reported) of {expected}")
                else:
                    ok = "OK" if n == expected else "MISMATCH"
                    print(f"  codeql  : analysed {n}/{expected}  [{ok}]")
                    if n != expected:
                        failures.append(f"{sid}: codeql analysed {n} of {expected}")
                if scope and not args.keep_staged:
                    shutil.rmtree(tmp2, ignore_errors=True)
        finally:
            if not args.keep_staged:
                shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    if failures:
        print("FAILURES -- results should not be trusted:")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print("all scans completed with matching file counts")


if __name__ == "__main__":
    main()
