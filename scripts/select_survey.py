#!/usr/bin/env python3
"""Choose the 24 survey outputs and mark them in dataset_index.csv.

Two examples from each of the twelve grid cells, one going to the
calibration version and one to the validation version. Both must have been
flagged by the tool that cell is assigned in survey_grid.csv, since that is
the warning participants will see.

Which of the pair goes to which version is decided at random with a fixed
seed. Choosing by hand would raise the question of whether the clearer
examples were steered into validation, where the agents are judged.

The calibration twelve are used to tune the agent prompts and are then
scored again as part of the results, so their agreement with participants
will look better than it should. Marking them here is what makes it
possible to check that later, by comparing agreement on the calibration
outputs against the validation ones.

    python3 scripts/select_survey.py
    python3 scripts/select_survey.py --dry-run
"""

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "dataset_index.csv"
SEED = 20260731


def main():
    """Marks two examples per cell as calibration and validation."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    grid = {(r["language"], r["vuln_type"]): r["tool"]
            for r in csv.DictReader(open(ROOT / "survey_grid.csv"))}
    rows = list(csv.DictReader(open(INDEX)))

    warnings = defaultdict(list)
    for w in csv.DictReader(open(ROOT / "normalised" / "outputs.csv")):
        warnings[(w["example_id"], w["tool"])].append(w)

    rng = random.Random(SEED)
    by_cell = defaultdict(list)
    for r in rows:
        by_cell[(r["language"], r["vuln_type"])].append(r)

    chosen, short = [], []
    for cell, sel in by_cell.items():
        tool = grid[cell]
        # only examples the cell's tool actually flagged can carry its warning
        eligible = [r for r in sel if r["survey_tool"] == tool]
        if len(eligible) < 2:
            short.append(f"{cell[0]}/{cell[1]}: only {len(eligible)} eligible")
            continue
        pair = rng.sample(eligible, 2)
        rng.shuffle(pair)
        pair[0]["survey_role"] = "calibration"
        pair[1]["survey_role"] = "validation"
        chosen += pair

    for r in rows:
        if not r["survey_role"]:
            r["survey_role"] = "dataset_only"

    print(f"{'cell':28s} {'calibration':>26s} {'validation':>12s}")
    print("-" * 70)
    for cell in sorted(by_cell):
        pair = [r for r in by_cell[cell] if r["survey_role"] != "dataset_only"]
        cal = next((r["example_id"] for r in pair
                    if r["survey_role"] == "calibration"), "-")
        val = next((r["example_id"] for r in pair
                    if r["survey_role"] == "validation"), "-")
        print(f"{cell[0] + '/' + cell[1]:28s} {cal:>26s} {val:>12s}")

    counts = defaultdict(int)
    for r in rows:
        counts[r["survey_role"]] += 1
    print(f"\n{dict(counts)}  (seed {SEED})")

    # each survey example must have a warning from its cell's tool to show
    missing = []
    for r in chosen:
        tool = grid[(r["language"], r["vuln_type"])]
        if not warnings.get((r["example_id"], tool)):
            missing.append(f"{r['example_id']} has no {tool} warning")
    if missing:
        print("\nNO WARNING TO SHOW:")
        for m in missing:
            print("  -", m)

    extra = [(r["example_id"], grid[(r["language"], r["vuln_type"])],
              len(warnings[(r["example_id"],
                            grid[(r["language"], r["vuln_type"])])]))
             for r in chosen
             if len(warnings.get((r["example_id"],
                                  grid[(r["language"], r["vuln_type"])]), [])) > 1]
    if extra:
        print("\nmore than one warning from the cell's tool, so one has to be "
              "chosen for display:")
        for ex, tool, n in extra:
            print(f"  {ex} / {tool}: {n} warnings")

    if short:
        print("\nCELLS SHORT OF TWO ELIGIBLE EXAMPLES:")
        for s in short:
            print("  -", s)

    if args.dry_run:
        return
    if short or missing:
        raise SystemExit("\nnot writing: fix the problems above first")

    with open(INDEX, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\nwrote survey_role for {len(rows)} examples")


if __name__ == "__main__":
    main()
