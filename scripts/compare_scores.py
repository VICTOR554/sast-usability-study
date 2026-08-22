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

A calibration round, under each prompt:

    python3 scripts/compare_scores.py runs/agents/calibration_1.csv
    python3 scripts/compare_scores.py runs/agents/calibration_2.csv

The full runs, on each half separately:

    python3 scripts/compare_scores.py runs/agents/scores_1.csv \\
        --version calibration
    python3 scripts/compare_scores.py runs/agents/scores_1.csv \\
        --version validation
        
    python3 scripts/compare_scores.py runs/agents/scores_2.csv \\
        --version calibration
    python3 scripts/compare_scores.py runs/agents/scores_2.csv \\
        --version validation

Every output rather than the summary, one participant left out, and one
warning left out:

    python3 scripts/compare_scores.py runs/agents/scores_2.csv --outputs
    python3 scripts/compare_scores.py runs/agents/scores_2.csv \\
        --without R_850OPE9kP69Qmdz
    python3 scripts/compare_scores.py runs/agents/scores_2.csv \\
        --skip-output OUT063
"""

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RATINGS = ROOT / "survey" / "responses" / "ratings.csv"

DIMENSIONS = ["clarity", "severity_justification", "specificity",
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


def read_people(without=None, version=None):
    """Participant ratings, keyed by output and dimension.

    Who rated which output is tracked as well, so the participant count
    reports the people who saw this half of the survey rather than everyone
    in the file.

    The two halves have to be reported separately. The calibration twelve
    were looked at while the prompt was being settled and the validation
    twelve were not, so mixing them would hide whether the prompt had been
    fitted to the outputs it was tuned on."""
    scores = defaultdict(lambda: defaultdict(list))
    raters = defaultdict(set)
    for r in csv.DictReader(open(RATINGS)):
        if version and r["version"] != version:
            continue
        if without and r["response_id"] in without:
            continue
        raters[r["output_id"]].add(r["response_id"])
        for s in DIMENSIONS:
            scores[r["output_id"]][s].append(int(r[s]))
    return scores, raters


def read_agents(path, run=PRIMARY_RUN):
    """Agent scores from one run, keyed by output and scale.

    Only the primary run is used. Each agent scores every output twice, and
    the second run is the independent check on whether a model gives the same
    answer again. Folding it into the median here would put the second run
    inside the number it is supposed to be checking."""
    every = defaultdict(lambda: defaultdict(list))
    # Kept per output as well as per model, so that a column can be limited to
    # whichever outputs are being compared rather than always covering the
    # whole file.
    per_model = defaultdict(lambda: defaultdict(dict))
    models = set()
    for r in csv.DictReader(open(path)):
        if r["run"] != str(run):
            continue
        models.add(r["model"])
        for s in DIMENSIONS:
            every[r["output_id"]][s].append(int(r[f"{s}_score"]))
            per_model[r["model"]][s][r["output_id"]] = int(r[f"{s}_score"])
    if not models:
        raise SystemExit(f"no rows for run {run} in {path}")
    return every, per_model, sorted(models)


def agreement(people, agents, shared, dimension):
    """The three agreement measures, comparing one median against another.

    Exact match is how often the two medians are the same, within one is how
    often they differ by no more than a point, and the median absolute
    difference is the typical size of the gap.

    A difference of exactly half a point counts as an exact match. Ten
    participants rate each output, so their median is the midpoint of the
    fifth and sixth ratings and lands on a half about a third of the time.
    The agents' median comes from three models and is always a whole number.
    Counting a half as a miss would mean a third of comparisons could never
    match however well the agents did, and that ceiling would apply to the
    agents while the participant baseline, which compares each person against
    an odd number of others, escapes it. A participant median of 4.5 means the
    ten of them split evenly between 4 and 5, so an agent choosing either has
    landed on their median."""
    diffs = [statistics.median(agents[o][dimension])
             - statistics.median(people[o][dimension])
             for o in shared]
    strict = sum(1 for d in diffs if abs(d) < 0.5) / len(diffs)
    loose = sum(1 for d in diffs if abs(d) <= 0.5) / len(diffs)
    within = sum(1 for d in diffs if abs(d) <= 1) / len(diffs)
    return strict, loose, within, statistics.median([abs(d) for d in diffs])


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
    # One warning was refused by one model, so its agent median comes from
    # two models rather than three. Leaving it out shows whether a result
    # rests on it. Nothing is dropped from the study either way.
    ap.add_argument("--skip-output", action="append", default=[],
                    metavar="OUTPUT_ID",
                    help="output_id to leave out, repeatable")
    ap.add_argument("--version", choices=("calibration", "validation"),
                    help="one half of the survey rather than both")
    args = ap.parse_args()

    people, raters = read_people(set(args.without), args.version)
    agents, per_model, models = read_agents(args.scores)
    shared = sorted((set(people) & set(agents)) - set(args.skip_output))
    if not shared:
        raise SystemExit("no outputs appear in both files")
    kept = set().union(*(raters[o] for o in shared))

    print(f"{len(shared)} outputs, {len(kept)} participants, "
          f"{len(models)} models")
    if args.version:
        print(f"version: {args.version}")
    if args.without:
        print(f"participants left out: {', '.join(args.without)}")
    if args.skip_output:
        print(f"outputs left out: {', '.join(args.skip_output)}")
    print()

    header = f"{'dimension':24s} {'people':>7s} {'agents':>7s} {'gap':>6s}   "
    header += " ".join(f"{m:>8s}" for m in models)
    print(header)
    print("-" * len(header))
    for s in DIMENSIONS:
        p = statistics.median([v for o in shared for v in people[o][s]])
        a = statistics.median([v for o in shared for v in agents[o][s]])
        line = f"{s:24s} {p:7.1f} {a:7.1f} {a - p:+6.1f}   "
        for m in models:
            mine = [per_model[m][s][o] for o in shared if o in per_model[m][s]]
            line += f"{statistics.median(mine):8.1f}" if mine else f"{'-':>8s}"
            line += " "
        print(line.rstrip())

    # Within one point is the measure to lead with, because it treats both
    # sides alike. Exact match is given as a range: a half point difference
    # counts as a miss under the strict reading and as a match under the
    # loose one, and neither convention is neutral. See agreement() above.
    print(f"\n{'dimension':24s} {'exact: strict':>14s} {'loose':>7s} "
          f"{'within 1':>10s} {'median diff':>12s}")
    print("-" * 68)
    for s in DIMENSIONS:
        strict, loose, within, typical = agreement(people, agents, shared, s)
        print(f"{s:24s} {strict:13.0%} {loose:7.0%} {within:10.0%} "
              f"{typical:12.1f}")
    overall = [agreement(people, agents, shared, s) for s in DIMENSIONS]
    print(f"{'all five together':24s} "
          f"{statistics.mean(x[0] for x in overall):13.0%} "
          f"{statistics.mean(x[1] for x in overall):7.0%} "
          f"{statistics.mean(x[2] for x in overall):10.0%} "
          f"{statistics.mean(x[3] for x in overall):12.1f}")

    # How often the two sides land far apart, which says more than the
    # overall medians. A scale can look level and still disagree on half the
    # outputs, with the differences cancelling out.
    print(f"\ngaps of {NOTABLE} or more, counted per output")
    for s in DIMENSIONS:
        n = [o for o in shared
             if abs(statistics.median(agents[o][s])
                    - statistics.median(people[o][s])) >= NOTABLE]
        print(f"  {s:24s} {len(n):2d} of {len(shared)}"
              + (f"   {' '.join(n)}" if n else ""))

    if args.outputs:
        tool = tools_by_output()
        print(f"\n{'output':8s} {'tool':9s} "
              + " ".join(f"{SHORT[s]:>11s}" for s in DIMENSIONS))
        print(f"{'':18s} " + " ".join(f"{'ppl ag gap':>11s}" for _ in DIMENSIONS))
        for o in shared:
            row = f"{o:8s} {tool.get(o, ''):9s} "
            for s in DIMENSIONS:
                p = statistics.median(people[o][s])
                a = statistics.median(agents[o][s])
                row += f"{p:4.1f}{a:4.1f}{a - p:+4.0f} "
            print(row)


if __name__ == "__main__":
    main()
