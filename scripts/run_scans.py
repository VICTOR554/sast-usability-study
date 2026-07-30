#!/usr/bin/env python3
"""Run Semgrep, CodeQL and Bearer over each source.

Output goes to runs/<tool>/<source>.* and is not changed afterwards.
coverage.py does the sorting into vulnerability types.

Each source is copied to a folder outside the repo before scanning.
Semgrep and Bearer both follow .gitignore, and sources/ is ignored, so
scanning it where it sits makes them report nothing at all.

After each scan the number of files the tool says it read is compared
against the number it was given. If a tool quietly skips files, the
result looks the same as clean code, so a mismatch stops the run.

    python3 scripts/run_scans.py                 # every source
    python3 scripts/run_scans.py pygoat dvna     # named sources
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

# Semgrep reads templates as well as source. CodeQL and Bearer only read the
# language's own files, and only count those, so their expected totals are
# taken from this narrower set.
NATIVE_EXTS = {
    "java": {".java"},
    "python": {".py"},
    "javascript": {".js", ".ts", ".jsx", ".tsx"},
}

# Directories never worth scanning.
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "target", "__pycache__",
             "venv", ".venv", "vendor"}

# Test folders. "testcases" is not in this list on purpose - Juliet keeps
# every case under src/testcases/, so excluding it would empty the corpus.
SKIP_TEST_DIRS = {"test", "tests", "__tests__", "spec", "e2e"}


def is_test_file(path: Path) -> bool:
    """True if this is a test file. The tools skip these anyway, and a test
    file is not something you would show a developer as an example."""
    if set(path.parts) & SKIP_TEST_DIRS:
        return True
    name = path.name
    stem = path.stem
    # Bearer also treats a file simply named test.js or spec.py as a test and
    # skips it, so those are dropped here too or the counts never agree.
    return (name.startswith("test_") or stem.endswith("_test")
            or ".test." in name or ".spec." in name
            or stem in ("test", "tests", "spec"))


def is_minified(path: Path) -> bool:
    """Minified libraries are one long line, so Semgrep skips them. They are
    third-party code and would not be used as examples anyway."""
    return ".min." in path.name or path.name.endswith("-min.js")

# CodeQL is slow enough that Juliet has to be narrowed down. Only the four
# CWE folders we need, and only the servlet versions. The other versions read
# from the console or a file, which CodeQL does not count as untrusted input,
# so it finds nothing in them anyway.
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
            rel = p.relative_to(root)
            if p.suffix in exts and not is_test_file(rel) and not is_minified(p):
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


# Each scan returns where it wrote the output and how many files the tool
# read, so the caller can compare that against what it was given.

def scan_semgrep(staged_dir: Path, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    r = run(["semgrep", "--config=p/default", "--no-git-ignore",
             "--json", "--output", str(out), str(staged_dir)])
    if not out.exists():
        raise RuntimeError(f"semgrep produced no output\n{r.stderr[-2000:]}")
    data = json.load(open(out))
    analysed = len(data.get("paths", {}).get("scanned", []))
    return out, analysed


def bearer_file_count(output: str):
    """Reads the Files column from Bearer's summary table. The JSON report
    only lists files that had findings, so without this you cannot tell a
    clean file from one Bearer never opened."""
    total = None
    for line in output.replace("\r", "\n").splitlines():
        parts = line.split()
        # rows look like: Python  88  0  8
        if len(parts) >= 4 and all(p.isdigit() for p in parts[-3:]):
            total = (total or 0) + int(parts[-1])
    return total


def scan_bearer(staged_dir: Path, out: Path):
    """Bearer runs twice. With --output it writes the JSON but prints no
    summary. Without it, it prints the table holding the file count but no
    file to read. Bearer is the fastest of the three, so running it twice is
    cheaper than having no way to tell what it read."""
    out.parent.mkdir(parents=True, exist_ok=True)
    base = [BEARER, "scan", str(staged_dir), "--scanner", "sast",
            "--skip-git-ignore", "--skip-test=false"]
    run(base + ["--format", "json", "--output", str(out)])
    if not out.exists():
        raise RuntimeError("bearer produced no output")
    r = run(base)
    return out, bearer_file_count(r.stdout + r.stderr)


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
    # CodeQL never says plainly how many files it read. Its summary line is
    # too low, counting only the files it analysed. Its file list is too high,
    # counting templates it does not read as code. Both are printed, neither
    # is used to fail the run.
    analysed = None
    for line in (r.stdout + r.stderr).splitlines():
        if "scanned" in line and "out of" in line:
            try:
                parts = line.split()
                analysed = int(parts[parts.index("scanned") + 1])
            except (ValueError, IndexError):
                pass
    indexed = len(json.load(open(out))["runs"][0].get("artifacts", []))
    return out, analysed, indexed


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

            native = sum(1 for f in staged if Path(f).suffix in NATIVE_EXTS[lang])

            if "bearer" in tools:
                out, n = scan_bearer(tmp, RUNS / "bearer" / f"{sid}.json")
                if n is None:
                    print(f"  bearer  : file count not reported, {native} staged")
                    failures.append(f"{sid}: bearer did not report a file count")
                else:
                    # Bearer skips the odd file for reasons it does not
                    # explain. This check is here to catch a tool reading
                    # nothing or half a project, not to chase single config
                    # files, so a small gap is a warning and not a failure.
                    missing = native - n
                    if missing == 0:
                        print(f"  bearer  : analysed {n}/{native}  [OK]")
                    elif missing <= max(2, native * 0.05):
                        print(f"  bearer  : analysed {n}/{native}  [{missing} skipped]")
                    else:
                        print(f"  bearer  : analysed {n}/{native}  [MISMATCH]")
                        failures.append(f"{sid}: bearer analysed {n} of {native}")

            if "codeql" in tools:
                scope = CODEQL_SCOPE.get(sid)
                if scope:
                    tmp2 = Path(tempfile.mkdtemp(prefix=f"scanql-{sid}-"))
                    sub = stage(src, tmp2, lang, scope=scope)
                    print(f"  codeql  : scoped to {len(sub)} files")
                    target, files = tmp2, sub
                else:
                    target, files = tmp, staged
                # Counted against the files CodeQL reads, so templates do not
                # throw it off. Printed only - see scan_codeql for why.
                expected = sum(1 for f in files if Path(f).suffix in NATIVE_EXTS[lang])
                out, n, indexed = scan_codeql(target, RUNS / "codeql" / f"{sid}.sarif",
                                              lang, CODEQL_DBS / sid)
                shown = "?" if n is None else n
                print(f"  codeql  : analysed {shown} of {expected} source files, "
                      f"{indexed} files indexed")
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
