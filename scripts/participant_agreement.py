#!/usr/bin/env python3
"""How much the participants agree with each other, and how they used the scale.

This is the human baseline. compare_scores.py reports how often the agents
match the participant median, but that figure means little on its own. If ten
developers rating the same output agree with each other 40 per cent of the
time, an agent at 38 per cent is performing as well as a person. If they agree
75 per cent of the time, the same figure reads very differently. The agents
should not be held to a stricter standard than the participants themselves
meet, and this is what supplies that standard.

Each participant is compared against the median of the others rather than
against everyone. Including their own rating in the benchmark would pull it
towards their answer and make agreement look better than it is.

Two checks on how the scale was used are reported alongside. The first counts
outputs where a participant gave the same score to all five dimensions, which
suggests one overall impression rather than five separate judgements. The
second counts scale points that cannot apply to any output in this survey,
since every one of them carries a severity label and a code location.

    python3 scripts/participant_agreement.py
    python3 scripts/participant_agreement.py --version calibration
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
# Scale points that describe an output with no severity label, no location or
# no reference to the code. Every output in the survey has all three, so a
# rating of 1 on these three scales cannot apply to anything shown.
IMPOSSIBLE = {"severity_justification": 1, "completeness": 1, "specificity": 1}


def read(version=None):
    rows = [r for r in csv.DictReader(open(RATINGS))
            if version is None or r["version"] == version]
    if not rows:
        raise SystemExit(f"no ratings for version {version!r}")
    return rows


def leave_one_out(rows, scale):
    """Each rating against the median of the other people who saw that output.

    Returns the three measures used everywhere else: how often a rating lands
    on that median, how often it is within a point, and the typical gap."""
    by_output = defaultdict(list)
    for r in rows:
        by_output[r["output_id"]].append((r["response_id"], int(r[scale])))

    diffs = []
    for _output, rated in by_output.items():
        for who, mine in rated:
            others = [v for other, v in rated if other != who]
            if not others:
                continue
            diffs.append(mine - statistics.median(others))
    exact = sum(1 for d in diffs if abs(d) < 0.5) / len(diffs)
    within = sum(1 for d in diffs if abs(d) <= 1) / len(diffs)
    return exact, within, statistics.median([abs(d) for d in diffs]), diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", choices=("calibration", "validation"),
                    help="one half of the survey rather than both")
    args = ap.parse_args()

    rows = read(args.version)
    people = {r["response_id"] for r in rows}
    outputs = {r["output_id"] for r in rows}
    print(f"{len(people)} participants, {len(outputs)} outputs, "
          f"{len(rows)} rated outputs, {len(rows) * len(SCALES)} ratings")
    if args.version:
        print(f"version: {args.version}")
    print()

    # How much people vary on each scale, and how their answers sit across
    # the five points. A scale where everyone chooses 5 tells you less than
    # one where the answers are spread out.
    print(f"{'scale':24s} {'mean':>5s} {'sd':>5s}   "
          + " ".join(f"{v:>5d}" for v in range(1, 6)))
    print("-" * 60)
    for s in SCALES:
        vals = [int(r[s]) for r in rows]
        counts = [sum(1 for v in vals if v == n) for n in range(1, 6)]
        print(f"{s:24s} {statistics.mean(vals):5.2f} "
              f"{statistics.stdev(vals):5.2f}   "
              + " ".join(f"{c:5d}" for c in counts))

    # The human baseline. Each rating is compared against the median of the
    # other participants who saw the same output, so a participant is never
    # part of the benchmark they are measured against.
    print(f"\nagreement between participants, each against the median of the "
          f"others")
    print(f"{'scale':24s} {'exact':>7s} {'within 1':>9s} {'median diff':>12s}")
    print("-" * 54)
    totals = []
    for s in SCALES:
        exact, within, typical, _ = leave_one_out(rows, s)
        totals.append((exact, within, typical))
        print(f"{s:24s} {exact:6.0%} {within:9.0%} {typical:12.1f}")
    print(f"{'all five together':24s} "
          f"{statistics.mean(e for e, _, _ in totals):6.0%} "
          f"{statistics.mean(w for _, w, _ in totals):9.0%} "
          f"{statistics.mean(t for _, _, t in totals):12.1f}")

    # How the scale was used, reported per participant rather than in total.
    # A problem concentrated in one person means something different from the
    # same number of answers spread across everyone.
    flat = defaultdict(int)
    impossible = defaultdict(int)
    words = defaultdict(list)
    for r in rows:
        if len({int(r[s]) for s in SCALES}) == 1:
            flat[r["response_id"]] += 1
        for s, point in IMPOSSIBLE.items():
            if int(r[s]) == point:
                impossible[r["response_id"]] += 1
        words[r["response_id"]].append(len(r["written_feedback"].split()))

    rated = len(rows) // len(people)
    print(f"\nhow the scale was used, per participant")
    print(f"{'participant':20s} {'version':11s} {'same on all five':>17s} "
          f"{'impossible':>11s} {'words':>6s}")
    print("-" * 70)
    ver = {r["response_id"]: r["version"] for r in rows}
    for p in sorted(people, key=lambda p: (-flat[p], -impossible[p])):
        print(f"{p:20s} {ver[p]:11s} {flat[p]:12d} of {rated:2d} "
              f"{impossible[p]:11d} "
              f"{statistics.mean(words[p]):6.0f}")

    print(f"\nsame score on all five dimensions: "
          f"{sum(flat.values())} of {len(rows)} rated outputs")
    print(f"ratings on scale points that cannot apply: "
          f"{sum(impossible.values())} of {len(rows) * len(IMPOSSIBLE)}")


if __name__ == "__main__":
    main()
