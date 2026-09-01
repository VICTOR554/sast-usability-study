#!/usr/bin/env python3
"""Compare the three SAST tools across the five usability dimensions.

This is the quantitative side of the study. compare_scores.py asks whether the
agents agree with people. This asks what the agents found once they had scored
everything, which is a question about the tools rather than about the agents.

Each warning gets one score per dimension, the median of the three models on
the primary run. Those medians are then grouped by tool, by vulnerability type
and by language.

The tools do not report the same code. Semgrep flags things CodeQL does not
and the other way round, so comparing their overall averages partly compares
what each tool chose to report rather than how well it reported it. The
comparison is therefore made at three levels.

All warnings gives the overall picture and carries that confound. Examples two
tools both flagged hold the code constant for a pair of tools. Examples all
three flagged hold it constant across the whole set. The last is the cleanest
comparison and the smallest.

    python3 scripts/compare_tools.py                  # scores_2.csv by default
    python3 scripts/compare_tools.py --matched
    python3 scripts/compare_tools.py --frequencies
    python3 scripts/compare_tools.py --skip-output OUT063

The same under the frozen prompt, which is how the two runs are compared:

    python3 scripts/compare_tools.py runs/agents/scores_1.csv
    python3 scripts/compare_tools.py runs/agents/scores_1.csv --matched
"""

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCORES = ROOT / "runs" / "agents" / "scores_2.csv"
INDEX = ROOT / "dataset_index.csv"

DIMENSIONS = ["clarity", "severity_justification", "specificity",
              "actionability", "completeness"]
SHORT = {"clarity": "clar", "severity_justification": "sev",
         "specificity": "spec", "actionability": "act",
         "completeness": "comp"}
TOOLS = ["semgrep", "codeql", "bearer"]
VULNS = ["sqli", "xss", "path-traversal", "cmd-injection"]
LANGUAGES = ["java", "python", "javascript"]
PRIMARY_RUN = 1


def read(path, run, skip=()):
    """One median score per warning per dimension, plus what each warning is.

    The median is taken across the three models. Where a model refused a
    warning its median comes from the two that answered, which is recorded
    rather than smoothed over."""
    raw = defaultdict(lambda: defaultdict(list))
    about = {}
    for r in csv.DictReader(open(path)):
        if r["run"] != str(run) or r["output_id"] in skip:
            continue
        about[r["output_id"]] = (r["example_id"], r["tool"],
                                 r["vuln_type"], r["language"])
        for d in DIMENSIONS:
            raw[r["output_id"]][d].append(int(f'{r[d + "_score"]}'))
    if not raw:
        raise SystemExit(f"no run {run} rows in {path}")
    median = {o: {d: statistics.median(v) for d, v in dims.items()}
              for o, dims in raw.items()}
    short = {o: len(dims[DIMENSIONS[0]]) for o, dims in raw.items()
             if len(dims[DIMENSIONS[0]]) < 3}
    return median, about, short


def table(rows, label, groups, key):
    """Mean of the per warning medians, for each group and dimension."""
    by = defaultdict(lambda: defaultdict(list))
    for output, dims in rows.items():
        for d in DIMENSIONS:
            by[key(output)][d].append(dims[d])
    print(f"\n{label:16s} {'n':>4s}   "
          + " ".join(f"{SHORT[d]:>6s}" for d in DIMENSIONS))
    print("-" * (23 + 7 * len(DIMENSIONS)))
    for g in groups:
        if not by[g]:
            continue
        n = len(by[g][DIMENSIONS[0]])
        line = f"{g:16s} {n:4d}   "
        line += " ".join(f"{statistics.mean(by[g][d]):6.2f}" for d in DIMENSIONS)
        print(line)
    return by


def frequencies(rows, about):
    """How often each score from 1 to 5 occurs, overall and per tool.

    A mean of 3 can come from every warning scoring 3 or from half scoring 1
    and half scoring 5, and those are different findings.

    A median can land on a half when a warning was scored by an even number
    of models, which happens where one model refused. Those values match no
    column, so they are counted separately and named underneath rather than
    being dropped. A row that quietly totals one less than the others is the
    kind of thing nobody notices until someone adds up the table."""
    print(f"\n{'dimension':24s} {'tool':9s} " + " ".join(f"{v:>5d}" for v in range(1, 6)))
    print("-" * 68)
    uncounted = []
    for d in DIMENSIONS:
        for tool in ["all"] + TOOLS:
            vals = [dims[d] for o, dims in rows.items()
                    if tool == "all" or about[o][1] == tool]
            counts = [sum(1 for v in vals if v == n) for n in range(1, 6)]
            name = d if tool == "all" else ""
            print(f"{name:24s} {tool:9s} " + " ".join(f"{c:5d}" for c in counts))
            if tool == "all":
                uncounted += [(o, d, dims[d]) for o, dims in rows.items()
                              if dims[d] not in range(1, 6)]
        print()
    for output_id, d, value in uncounted:
        print(f"not counted above: {output_id} {d} {value}, "
              f"median of an even number of models")


def matched(rows, about):
    """The same code seen by more than one tool.

    An example is one vulnerable location. Where two or three tools reported
    the same location, their warnings can be compared with the code held
    constant, which the overall table cannot do."""
    by_example = defaultdict(dict)
    for output, dims in rows.items():
        example, tool, _v, _l = about[output]
        by_example[example].setdefault(tool, dims)

    for want, label in ((2, "flagged by two or more tools"),
                        (3, "flagged by all three tools")):
        examples = {e: t for e, t in by_example.items() if len(t) >= want}
        print(f"\n{label}: {len(examples)} examples")
        if not examples:
            continue
        print(f"{'tool':16s} {'n':>4s}   "
              + " ".join(f"{SHORT[d]:>6s}" for d in DIMENSIONS))
        print("-" * (23 + 7 * len(DIMENSIONS)))
        for tool in TOOLS:
            mine = [t[tool] for t in examples.values() if tool in t]
            if not mine:
                continue
            line = f"{tool:16s} {len(mine):4d}   "
            line += " ".join(
                f"{statistics.mean([m[d] for m in mine]):6.2f}"
                for d in DIMENSIONS)
            print(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scores", type=Path, nargs="?", default=SCORES,
                    help="agent scores file, default runs/agents/scores_2.csv")
    ap.add_argument("--run", type=int, default=PRIMARY_RUN,
                    help="which run to use as the measurement")
    ap.add_argument("--skip-output", action="append", default=[],
                    metavar="OUTPUT_ID", help="output_id to leave out")
    ap.add_argument("--matched", action="store_true",
                    help="only the comparisons that hold the code constant")
    ap.add_argument("--frequencies", action="store_true",
                    help="how often each score from 1 to 5 occurs")
    args = ap.parse_args()

    rows, about, short = read(args.scores, args.run, set(args.skip_output))
    print(f"{len(rows)} warnings, run {args.run}")
    if args.skip_output:
        print(f"left out: {', '.join(args.skip_output)}")
    if short:
        for o, n in sorted(short.items()):
            print(f"note: {o} scored by {n} models rather than 3")

    if not args.matched:
        table(rows, "tool", TOOLS, lambda o: about[o][1])
        table(rows, "vulnerability", VULNS, lambda o: about[o][2])
        table(rows, "language", LANGUAGES, lambda o: about[o][3])
        if args.frequencies:
            frequencies(rows, about)

    matched(rows, about)


if __name__ == "__main__":
    main()
