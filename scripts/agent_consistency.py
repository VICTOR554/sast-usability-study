#!/usr/bin/env python3
"""How much the agents agree with themselves and with each other.

This is the consistency half of RQ1, and it needs no participant data, so it
runs across every warning in a scores file rather than only the 24 the survey
covered. compare_scores.py answers a different question, whether the agents
agree with people, and can only work where participant ratings exist.

Consistency is two things and they are reported separately.

Run to run is whether one model gives the same answer twice on the same
warning. Each agent scores everything twice, and the second run exists for
this measurement rather than to be averaged into the first.

Between models is whether the three models land in the same place on the same
warning. This is measured on the primary run only, since mixing runs would
confuse disagreement between models with a model disagreeing with itself.

Both are reported with the same three measures used everywhere else, so the
figures can be read against the agent to participant comparison and against
how much the participants agree with each other.

    python3 scripts/agent_consistency.py runs/agents/calibration_1.csv
    python3 scripts/agent_consistency.py runs/agents/calibration_2.csv

    python3 scripts/agent_consistency.py runs/agents/scores_1.csv
    
    python3 scripts/agent_consistency.py runs/agents/scores_2.csv
    python3 scripts/agent_consistency.py runs/agents/scores_2.csv --dimensions
    python3 scripts/agent_consistency.py runs/agents/scores_2.csv --run 2

"""

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DIMENSIONS = ["clarity", "severity_justification", "specificity",
              "actionability", "completeness"]
PRIMARY_RUN = 1
# A spread this size between the highest and lowest model is worth looking at
# rather than treating as ordinary variation.
WIDE = 2


def read(path):
    """Every score, keyed by output, model and run."""
    scores = defaultdict(dict)
    models, runs = set(), set()
    for r in csv.DictReader(open(path)):
        models.add(r["model"])
        runs.add(int(r["run"]))
        for d in DIMENSIONS:
            scores[(r["output_id"], d)][(r["model"], int(r["run"]))] = \
                int(r[f"{d}_score"])
    if not scores:
        raise SystemExit(f"no rows in {path}")
    return scores, sorted(models), sorted(runs)


def measures(diffs):
    """Exact, within one, and the typical gap, from a list of differences."""
    exact = sum(1 for d in diffs if d == 0) / len(diffs)
    within = sum(1 for d in diffs if abs(d) <= 1) / len(diffs)
    return exact, within, statistics.median([abs(d) for d in diffs])


def run_to_run(scores, model, first, second):
    """One model against itself, comparing its two runs on the same warning."""
    diffs = []
    for key, by_who in scores.items():
        a = by_who.get((model, first))
        b = by_who.get((model, second))
        if a is not None and b is not None:
            diffs.append(b - a)
    return diffs


def between_models(scores, models, run):
    """Every pair of models on the same warning, and the spread across all three.

    Pairs answer how close any two models are. The spread answers how far
    apart the whole set is, which is what decides whether a median is standing
    in for a consensus or hiding a disagreement."""
    pairs = defaultdict(list)
    spreads = []
    for key, by_who in scores.items():
        got = {m: by_who[(m, run)] for m in models if (m, run) in by_who}
        if len(got) < 2:
            continue
        names = sorted(got)
        for i, one in enumerate(names):
            for other in names[i + 1:]:
                pairs[(one, other)].append(got[other] - got[one])
        if len(got) == len(models):
            spreads.append((key, max(got.values()) - min(got.values())))
    return pairs, spreads


def direction(scores, models, run, dimension=None):
    """Which way a pair disagrees, not only how often.

    between_models() reports how close two models are. It cannot say whether
    one of them sits above the other, because a pair that disagrees evenly in
    both directions and a pair that agrees almost always both produce a small
    typical gap.

    Differences are taken as first minus second, so a positive mean means the
    first model scored higher. Counts are returned as well as the mean, since
    a mean near zero can come from close agreement or from disagreement in
    both directions cancelling out, and only the counts separate those."""
    out = {}
    for i, one in enumerate(models):
        for other in models[i + 1:]:
            diffs = []
            for (_output, d), by_who in scores.items():
                if dimension and d != dimension:
                    continue
                a, b = by_who.get((one, run)), by_who.get((other, run))
                if a is not None and b is not None:
                    diffs.append(a - b)
            if not diffs:
                continue
            n = len(diffs)
            out[(one, other)] = {
                "n": n,
                "higher": sum(1 for d in diffs if d > 0) / n,
                "same": sum(1 for d in diffs if d == 0) / n,
                "lower": sum(1 for d in diffs if d < 0) / n,
                "mean": statistics.mean(diffs),
                "sizes": [sum(1 for d in diffs if abs(d) == k) / n
                          for k in (0, 1, 2)]
                         + [sum(1 for d in diffs if abs(d) >= 3) / n],
            }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scores", type=Path,
                    help="an agent scores file, such as "
                         "runs/agents/scores_2.csv")
    ap.add_argument("--dimensions", action="store_true",
                    help="break the figures down by dimension")
    ap.add_argument("--run", type=int, default=PRIMARY_RUN,
                    help="which run to treat as the primary one")
    ap.add_argument("--direction", action="store_true",
                    help="which way each pair of models disagrees")
    args = ap.parse_args()

    scores, models, runs = read(args.scores)
    outputs = {o for o, _ in scores}
    print(f"{len(outputs)} outputs, {len(models)} models, "
          f"{len(runs)} runs, {len(scores) * len(models)} scores")
    print()

    if len(runs) < 2:
        print("only one run in this file, so run to run cannot be measured")
    else:
        first, second = runs[0], runs[1]
        print(f"run to run, each model against itself "
              f"(run {first} against run {second})")
        print(f"{'model':12s} {'same':>7s} {'within 1':>9s} "
              f"{'median diff':>12s}")
        print("-" * 44)
        for m in models:
            diffs = run_to_run(scores, m, first, second)
            same, within, typical = measures(diffs)
            print(f"{m:12s} {same:6.0%} {within:9.0%} {typical:12.1f}")

        if args.dimensions:
            print(f"\nrun to run by dimension")
            print(f"{'dimension':24s} " + " ".join(f"{m:>10s}" for m in models))
            print("-" * (24 + 11 * len(models)))
            for d in DIMENSIONS:
                row = f"{d:24s} "
                for m in models:
                    diffs = [b - a for (o, dim), by_who in scores.items()
                             if dim == d
                             for a, b in [(by_who.get((m, first)),
                                           by_who.get((m, second)))]
                             if a is not None and b is not None]
                    row += f"{measures(diffs)[0]:9.0%} "
                print(row)

    pairs, spreads = between_models(scores, models, args.run)
    if not pairs:
        raise SystemExit(f"\nno run {args.run} rows to compare between models")

    print(f"\nbetween models, on run {args.run}")
    print(f"{'pair':26s} {'same':>7s} {'within 1':>9s} {'median diff':>12s}")
    print("-" * 58)
    for (one, other), diffs in sorted(pairs.items()):
        same, within, typical = measures(diffs)
        print(f"{one + ' and ' + other:26s} {same:6.0%} {within:9.0%} "
              f"{typical:12.1f}")

    if args.direction:
        # first minus second, so a positive mean means the first model scored
        # higher. The counts sit beside the mean because a mean near zero can
        # mean the pair agrees or that it disagrees both ways in equal measure.
        rows = direction(scores, models, args.run)
        print(f"\ndirection between models, on run {args.run}")
        print(f"{'pair':26s} {'n':>5s} {'higher':>8s} {'same':>7s} "
              f"{'lower':>7s} {'mean signed diff':>18s}")
        print("-" * 74)
        for (one, other), v in sorted(rows.items()):
            print(f"{one + ' - ' + other:26s} {v['n']:5d} {v['higher']:7.0%} "
                  f"{v['same']:6.0%} {v['lower']:6.0%} {v['mean']:18.2f}")

        print(f"\ndirection by dimension")
        print(f"{'pair':22s} {'dimension':24s} {'n':>4s} {'higher':>7s} "
              f"{'same':>6s} {'lower':>6s} {'mean':>7s}")
        print("-" * 80)
        for (one, other) in sorted(rows):
            for i, d in enumerate(DIMENSIONS):
                v = direction(scores, models, args.run, d)[(one, other)]
                name = f"{one} - {other}" if i == 0 else ""
                print(f"{name:22s} {d:24s} {v['n']:4d} {v['higher']:6.0%} "
                      f"{v['same']:5.0%} {v['lower']:5.0%} {v['mean']:7.2f}")
            print()

        print(f"size of the differences")
        print(f"{'pair':26s} {'n':>5s} {'0':>7s} {'1':>7s} {'2':>7s} "
              f"{'3 or more':>11s}")
        print("-" * 68)
        for (one, other), v in sorted(rows.items()):
            z, a, b, c = v["sizes"]
            print(f"{one + ' - ' + other:26s} {v['n']:5d} {z:7.0%} {a:7.0%} "
                  f"{b:7.0%} {c:11.0%}")

    if spreads:
        wide = [key for key, gap in spreads if gap >= WIDE]
        allsame = sum(1 for _key, gap in spreads if gap == 0)
        print(f"\nall three models on the same warning and dimension")
        print(f"  identical: {allsame} of {len(spreads)} "
              f"({allsame / len(spreads):.0%})")
        print(f"  spread of {WIDE} or more: {len(wide)} of {len(spreads)} "
              f"({len(wide) / len(spreads):.0%})")
        if wide and args.dimensions:
            by_dim = defaultdict(int)
            for _o, d in wide:
                by_dim[d] += 1
            print("  where the wide spreads are:")
            for d in DIMENSIONS:
                if by_dim[d]:
                    print(f"    {d:24s} {by_dim[d]:3d}")


if __name__ == "__main__":
    main()
