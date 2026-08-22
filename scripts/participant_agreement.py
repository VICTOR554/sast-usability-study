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
    python3 scripts/participant_agreement.py --version validation

Whenever compare_scores.py is run with --without, this is run the same way,
so the agents and the baseline are measured over the same people:

    python3 scripts/participant_agreement.py --version validation \\
        --without R_850OPE9kP69Qmdz
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
# Scale points that describe an output with no severity label, no location or
# no reference to the code. Every output in the survey has all three, so a
# rating of 1 on these three scales cannot apply to anything shown.
IMPOSSIBLE = {"severity_justification": 1, "completeness": 1, "specificity": 1}


def read(version=None, without=()):
    """The ratings, optionally limited to one half and with people left out.

    Leaving someone out changes the baseline the agent figures are read
    against, so whenever the agent comparison is run without a participant
    this has to be run the same way. Comparing agents measured without
    someone against a human baseline that still includes them would favour
    the agents. Nobody is excluded from the study either way."""
    rows = [r for r in csv.DictReader(open(RATINGS))
            if (version is None or r["version"] == version)
            and r["response_id"] not in without]
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
    # Both readings of an exact match are reported, matching the agent
    # comparison. Here they come out the same, because each participant is
    # measured against an odd number of others so the median never lands on
    # a half. That is exactly why the agent figure needs both.
    strict = sum(1 for d in diffs if abs(d) < 0.5) / len(diffs)
    loose = sum(1 for d in diffs if abs(d) <= 0.5) / len(diffs)
    within = sum(1 for d in diffs if abs(d) <= 1) / len(diffs)
    return strict, loose, within, statistics.median([abs(d) for d in diffs])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", choices=("calibration", "validation"),
                    help="one half of the survey rather than both")
    ap.add_argument("--without", action="append", default=[],
                    help="response_id to leave out, repeatable")
    args = ap.parse_args()

    rows = read(args.version, set(args.without))
    people = {r["response_id"] for r in rows}
    outputs = {r["output_id"] for r in rows}
    print(f"{len(people)} participants, {len(outputs)} outputs, "
          f"{len(rows)} rated outputs, {len(rows) * len(DIMENSIONS)} ratings")
    if args.version:
        print(f"version: {args.version}")
    if args.without:
        print(f"participants left out: {', '.join(args.without)}")
    print()

    # How much people vary on each scale, and how their answers sit across
    # the five points. A scale where everyone chooses 5 tells you less than
    # one where the answers are spread out.
    print(f"{'dimension':24s} {'mean':>5s} {'sd':>5s}   "
          + " ".join(f"{v:>5d}" for v in range(1, 6)))
    print("-" * 60)
    for s in DIMENSIONS:
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
    print(f"{'dimension':24s} {'exact: strict':>14s} {'loose':>7s} "
          f"{'within 1':>10s} {'median diff':>12s}")
    print("-" * 68)
    totals = []
    for s in DIMENSIONS:
        got = leave_one_out(rows, s)
        totals.append(got)
        print(f"{s:24s} {got[0]:13.0%} {got[1]:7.0%} {got[2]:10.0%} "
              f"{got[3]:12.1f}")
    print(f"{'all five together':24s} "
          f"{statistics.mean(x[0] for x in totals):13.0%} "
          f"{statistics.mean(x[1] for x in totals):7.0%} "
          f"{statistics.mean(x[2] for x in totals):10.0%} "
          f"{statistics.mean(x[3] for x in totals):12.1f}")

    # How the scale was used, reported per participant rather than in total.
    # A problem concentrated in one person means something different from the
    # same number of answers spread across everyone.
    flat = defaultdict(int)
    impossible = defaultdict(int)
    words = defaultdict(list)
    for r in rows:
        if len({int(r[s]) for s in DIMENSIONS}) == 1:
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
