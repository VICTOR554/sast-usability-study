#!/usr/bin/env python3
"""Pick the dataset examples and write dataset_index.csv.

Five examples for each language and vulnerability type, sixty in all. An
example is one vulnerable code location, not a whole file, so a file with
three findings can supply more than one.

Picking is random from the files that pass the rules below, using a fixed
seed so the same set comes back every time. Choosing by hand would raise
the question of whether the clearest examples were kept and the awkward
ones dropped.

Rules:
  - at least two per cell must be flagged by the tool survey_grid.csv
    assigns to it, since those two become the survey outputs
  - one per cell should be flagged by all three tools, so the cell can show
    the same code described three different ways. Some cells have none:
    for Python path traversal and JavaScript XSS there is no line in any
    source that all three tools flag, so those cells go without.
  - no more than two examples from the same file across the whole dataset
  - files over the line limit are skipped, as the survey shows the code
  - sources are spread out where a cell has enough files to allow it

    python3 scripts/select_examples.py            # write the selection
    python3 scripts/select_examples.py --dry-run  # show it without writing
"""

import argparse
import csv
import random
import shutil
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from coverage import load_all, excluded, codeql_scanned

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
SEED = 20260731
PER_CELL = 5
MAX_PER_FILE = 2
# The survey shows a window around the flagged line, not the whole file, so
# this is a loose guard against files too large to make sense of rather than
# a display limit. At 250 the JavaScript command injection cell could not be
# filled, and the limit was excluding the only file there that all three
# tools flagged.
MAX_LINES = 550

LANGS = ["java", "python", "javascript"]
VULNS = ["sqli", "xss", "path-traversal", "cmd-injection"]


def load_grid():
    """Which tool the survey shows for each vulnerability and language."""
    grid = {}
    with open(ROOT / "survey_grid.csv") as f:
        for r in csv.DictReader(f):
            grid[(r["language"], r["vuln_type"])] = r["tool"]
    return grid


def build_pool():
    """Every candidate finding, grouped by cell and file."""
    ql = {}
    pool = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    for (proj, lang, tool, rid, vt, basis, path, line) in load_all():
        if vt is None or not path or excluded(path) or not line:
            continue
        if proj not in ql:
            ql[proj] = codeql_scanned(proj)
        if ql[proj] is not None and Path(path).name not in ql[proj]:
            continue
        pool[(lang, vt)][f"{proj}|{path}"][line].add(tool)
    return pool


def resolve(key, paths):
    """Where the file actually sits under sources/."""
    proj, rel = key.split("|", 1)
    p = ROOT / paths[proj] / rel
    if p.exists():
        return p
    for c in (ROOT / paths[proj]).rglob(Path(rel).name):
        return c
    return None


def line_count(p):
    return sum(1 for _ in open(p, errors="ignore"))


def pick_cell(cell_files, grid_tool, rng, paths, per_file, per_source):
    """Five locations for one cell. Two must be flagged by the survey tool and
    one by all three, so the cell can show the same code described three ways.

    per_file and per_source carry across cells, so a file cannot supply more
    than MAX_PER_FILE examples anywhere in the dataset."""
    usable = []
    for key, lines in cell_files.items():
        p = resolve(key, paths)
        if not p or line_count(p) > MAX_LINES:
            continue
        for line, tools in lines.items():
            usable.append({"key": key, "path": p, "line": line,
                           "tools": sorted(tools), "source": key.split("|")[0]})
    if not usable:
        return []

    rng.shuffle(usable)
    chosen = []

    def free(u):
        return per_file[u["key"]] < MAX_PER_FILE and u not in chosen

    def take(u):
        chosen.append(u)
        per_file[u["key"]] += 1
        per_source[u["source"]] += 1

    # one flagged by all three tools
    three = [u for u in usable if len(u["tools"]) == 3 and free(u)]
    three.sort(key=lambda u: per_source[u["source"]])
    if three:
        take(three[0])

    # then up to two flagged by the tool this cell is assigned in the grid
    have = sum(1 for u in chosen if grid_tool in u["tools"])
    survey = [u for u in usable if grid_tool in u["tools"] and free(u)]
    survey.sort(key=lambda u: per_source[u["source"]])
    for u in survey:
        if have >= 2:
            break
        take(u)
        have += 1

    # fill the rest, spreading across sources
    while len(chosen) < PER_CELL:
        rest = [u for u in usable if free(u)]
        if not rest:
            break
        rest.sort(key=lambda u: per_source[u["source"]])
        take(rest[0])
    return chosen


def main():
    """Picks the examples, copies them into dataset/ and writes the index."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="print the selection without writing anything")
    args = ap.parse_args()

    paths = {r["source_id"]: r["local_path"]
             for r in csv.DictReader(open(ROOT / "sources.csv"))}
    grid = load_grid()
    pool = build_pool()
    rng = random.Random(SEED)

    rows, n, short, no_three = [], 0, [], []
    per_file, per_source = defaultdict(int), defaultdict(int)

    # Tightest cells first. A file can only supply MAX_PER_FILE examples in
    # total, so a cell filled early can use up a file a later cell needed.
    # JavaScript command injection has five files and came out with three,
    # because two had already been spent on other JavaScript cells.
    cells = sorted(((lang, vt) for lang in LANGS for vt in VULNS),
                   key=lambda c: len(pool[c]))
    picks = {}
    for cell in cells:
        picks[cell] = pick_cell(pool[cell], grid[cell], rng, paths,
                                per_file, per_source)

    for lang in LANGS:
        for vt in VULNS:
            tool = grid[(lang, vt)]
            picked = picks[(lang, vt)]
            with_tool = sum(1 for p in picked if tool in p["tools"])
            all_three = sum(1 for p in picked if len(p["tools"]) == 3)
            if len(picked) < PER_CELL or with_tool < 2:
                short.append(f"{lang}/{vt}: {len(picked)} picked, "
                             f"{with_tool} flagged by {tool}")
            if all_three == 0:
                no_three.append(f"{lang}/{vt}")
            for p in picked:
                n += 1
                proj, rel = p["key"].split("|", 1)
                rows.append({
                    "example_id": f"EX{n:03d}",
                    "language": lang,
                    "vuln_type": vt,
                    "source_id": proj,
                    "source_path": f"{proj}/{rel}",
                    "dataset_path": f"dataset/{lang}/{vt}/EX{n:03d}/{Path(rel).name}",
                    "line": p["line"],
                    "tools": "|".join(p["tools"]),
                    "survey_tool": tool if tool in p["tools"] else "",
                    "survey_role": "",
                    "_src": str(p["path"]),
                })

    print(f"{'cell':28s} {'picked':>7s} {'survey-eligible':>16s} {'all three':>11s}")
    print("-" * 68)
    for lang in LANGS:
        for vt in VULNS:
            sel = [r for r in rows if r["language"] == lang and r["vuln_type"] == vt]
            elig = sum(1 for r in sel if r["survey_tool"])
            three = sum(1 for r in sel if len(r["tools"].split("|")) == 3)
            print(f"{lang + '/' + vt:28s} {len(sel):7d} {elig:16d} {three:11d}")
    print(f"\ntotal: {len(rows)}  (seed {SEED})")
    if no_three:
        print("\nno example flagged by all three tools (none exists in these "
              "cells, worth reporting as a finding):")
        for c in no_three:
            print("  -", c)
    if short:
        print("\nCELLS BELOW TARGET:")
        for s in short:
            print("  -", s)

    if args.dry_run:
        return
    if short:
        raise SystemExit("\nnot writing: fix the cells above first")

    for d in DATASET.iterdir():
        if d.is_dir():
            for sub in d.iterdir():
                if sub.is_dir():
                    for ex in sub.iterdir():
                        if ex.is_dir():
                            shutil.rmtree(ex)
    for r in rows:
        dest = ROOT / r["dataset_path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(r["_src"], dest)
        del r["_src"]

    with open(ROOT / "dataset_index.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote dataset_index.csv and copied {len(rows)} files")


if __name__ == "__main__":
    main()
