#!/usr/bin/env python3
"""Put the agent scores next to the participant ratings and show the gaps.

This is the comparison step inside calibration. The agents score the twelve
calibration outputs, this script shows where they differ from the people who
rated the same twelve, and those differences are what a prompt revision would
be responding to. It is used again on the validation twelve after the prompt
is frozen, which is the fair test, since those outputs took no part in
calibration.

Both sides are summarised by the median. Participants give ten ratings per
output and the agents give six, being three models twice each, so a median
is the fairest single number to compare and it is not pulled about by one
unusual rater.

The --without flag repeats the comparison with one participant left out.
Nobody is excluded from the study. The flag exists so that a finding can be
shown to hold without a particular person's answers rather than resting on
them, and the write-up reports both figures.

    python3 scripts/compare_scores.py runs/agents/calibration_1.csv
    python3 scripts/compare_scores.py runs/agents/calibration_1.csv --outputs
    python3 scripts/compare_scores.py runs/agents/calibration_1.csv \\ --without R_850OPE9kP69Qmdz
"""

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RATINGS = ROOT / "survey" / "responses" / "ratings.csv"

SCALES = ["clarity", "severity_justification", "specificity",
          "actionability", "completeness"]
SHORT = {"clarity": "clar", "severity_justification": "sev",
         "specificity": "spec", "actionability": "act",
         "completeness": "comp"}
# A gap this size or larger is worth reading the reasoning behind. It is a
# reporting threshold, not a rule about when the prompt gets changed.
NOTABLE = 2
# Each agent scores every output twice. The first run is the measurement and
# the second is kept back to check run-to-run stability, so only the first is
# used here.
PRIMARY_RUN = 1


def read_people(without=None):
    """Participant ratings, keyed by output and scale.

    Who rated which output is tracked as well, so the participant count
    reports the people who saw this half of the survey rather than everyone
    in the file."""
    scores = defaultdict(lambda: defaultdict(list))
    raters = defaultdict(set)
    for r in csv.DictReader(open(RATINGS)):
        if without and r["response_id"] in without:
            continue
        raters[r["output_id"]].add(r["response_id"])
        for s in SCALES:
            scores[r["output_id"]][s].append(int(r[s]))
    return scores, raters


def read_agents(path, run=PRIMARY_RUN):
    """Agent scores from one run, keyed by output and scale.

    Only the primary run is used. Each agent scores every output twice, and
    the second run is the independent check on whether a model gives the same
    answer again. Folding it into the median here would put the second run
    inside the number it is supposed to be checking."""
    every = defaultdict(lambda: defaultdict(list))
    per_model = defaultdict(lambda: defaultdict(list))
    models = set()
    for r in csv.DictReader(open(path)):
        if r["run"] != str(run):
            continue
        models.add(r["model"])
        for s in SCALES:
            every[r["output_id"]][s].append(int(r[f"{s}_score"]))
            per_model[r["model"]][s].append(int(r[f"{s}_score"]))
    if not models:
        raise SystemExit(f"no rows for run {run} in {path}")
    return every, per_model, sorted(models)


def agreement(people, agents, shared, scale):
    """The three agreement measures, comparing one median against another.

    Exact match is how often the two medians are the same, within one is how
    often they differ by no more than a point, and the median absolute
    difference is the typical size of the gap. A median can land on a half
    when the number of raters is even, so an exact match allows for that."""
    diffs = [statistics.median(agents[o][scale]) - statistics.median(people[o][scale])
             for o in shared]
    exact = sum(1 for d in diffs if abs(d) < 0.5) / len(diffs)
    within = sum(1 for d in diffs if abs(d) <= 1) / len(diffs)
    return exact, within, statistics.median([abs(d) for d in diffs])


def tools_by_output():
    return {r["output_id"]: r["tool"] for r in csv.DictReader(open(RATINGS))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scores", type=Path,
                    help="an agent scores file, such as "
                         "runs/agents/calibration_1.csv")
    ap.add_argument("--outputs", action="store_true",
                    help="show every output rather than the summary")
    ap.add_argument("--without", action="append", default=[],
                    help="response_id to leave out, repeatable")
    args = ap.parse_args()

    people, raters = read_people(set(args.without))
    agents, per_model, models = read_agents(args.scores)
    shared = sorted(set(people) & set(agents))
    if not shared:
        raise SystemExit("no outputs appear in both files")
    kept = set().union(*(raters[o] for o in shared))

    print(f"{len(shared)} outputs, {len(kept)} participants, "
          f"{len(models)} models")
    if args.without:
        print(f"left out: {', '.join(args.without)}")
    print()

    header = f"{'scale':24s} {'people':>7s} {'agents':>7s} {'gap':>6s}   "
    header += " ".join(f"{m:>8s}" for m in models)
    print(header)
    print("-" * len(header))
    for s in SCALES:
        p = statistics.median([v for o in shared for v in people[o][s]])
        a = statistics.median([v for o in shared for v in agents[o][s]])
        line = f"{s:24s} {p:7.1f} {a:7.1f} {a - p:+6.1f}   "
        line += " ".join(f"{statistics.median(per_model[m][s]):8.1f}"
                         for m in models)
        print(line)

    # Exact match, within one point, and the typical gap. These are what
    # decide whether another calibration round has improved anything, so they
    # are compared between rounds rather than read once.
    print(f"\n{'scale':24s} {'exact':>7s} {'within 1':>9s} {'median diff':>12s}")
    print("-" * 54)
    for s in SCALES:
        exact, within, typical = agreement(people, agents, shared, s)
        print(f"{s:24s} {exact:6.0%} {within:9.0%} {typical:12.1f}")
    overall = [agreement(people, agents, shared, s) for s in SCALES]
    print(f"{'all five together':24s} "
          f"{sum(e for e, _, _ in overall) / 5:6.0%} "
          f"{sum(w for _, w, _ in overall) / 5:9.0%} "
          f"{statistics.mean(t for _, _, t in overall):12.1f}")

    # How often the two sides land far apart, which says more than the
    # overall medians. A scale can look level and still disagree on half the
    # outputs, with the differences cancelling out.
    print(f"\ngaps of {NOTABLE} or more, counted per output")
    for s in SCALES:
        n = [o for o in shared
             if abs(statistics.median(agents[o][s])
                    - statistics.median(people[o][s])) >= NOTABLE]
        print(f"  {s:24s} {len(n):2d} of {len(shared)}"
              + (f"   {' '.join(n)}" if n else ""))

    if args.outputs:
        tool = tools_by_output()
        print(f"\n{'output':8s} {'tool':9s} "
              + " ".join(f"{SHORT[s]:>11s}" for s in SCALES))
        print(f"{'':18s} " + " ".join(f"{'ppl ag gap':>11s}" for _ in SCALES))
        for o in shared:
            row = f"{o:8s} {tool.get(o, ''):9s} "
            for s in SCALES:
                p = statistics.median(people[o][s])
                a = statistics.median(agents[o][s])
                row += f"{p:4.1f}{a:4.1f}{a - p:+4.0f} "
            print(row)


if __name__ == "__main__":
    main()
