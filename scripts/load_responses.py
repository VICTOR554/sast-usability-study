#!/usr/bin/env python3
"""Turn the Qualtrics export into two tables the analysis can read.

The export is 290 columns wide and has three header rows, so nothing should
have to read it more than once. This script reads it and writes
survey/responses/ratings.csv and survey/responses/participants.csv.

The export does not say which example each block held. Qualtrics only
exports columns for questions that take an answer, and the code snippet is a
descriptive text question, so the example ID that was set as its label never
comes through. The mapping is kept in survey/responses/block_map.csv
instead, and was confirmed against the block names in Qualtrics.

Column names cannot be trusted on their own, because the export reuses them.
Q4 is both a screening question and a rating on one of the blocks, and Q6 is
both as well. Every column is therefore found by position, and the blocks
are found by the timing columns that Qualtrics writes around each one.

Randomising the order the blocks were shown in does not affect any of this.
Qualtrics fixes the question IDs per block, so the same columns hold the
same block for every participant no matter what order they saw them in.

    python3 scripts/load_responses.py
"""

import csv
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESP = ROOT / "survey" / "responses"
EXPORT = RESP / "survey_response.csv"
BLOCK_MAP = RESP / "block_map.csv"
RATINGS = RESP / "ratings.csv"
PARTICIPANTS = RESP / "participants.csv"

SCALES = ["Clarity", "Severity Justification", "Specificity",
          "Actionability", "Completeness"]
# The column name the analysis uses for each scale, matching the agent
# scores so the two tables join on the same names.
SCALE_KEY = {"Clarity": "clarity",
             "Severity Justification": "severity_justification",
             "Specificity": "specificity",
             "Actionability": "actionability",
             "Completeness": "completeness"}

# Screening questions, by position rather than by name.
PERSON_COLS = {
    27: "programs",
    28: "languages_proficient",
    29: "ability_java",
    30: "ability_python",
    31: "ability_javascript",
    32: "used_sast_before",
    37: "understood_study",
}


def find_blocks(h1, h2):
    """Finds the six answer columns belonging to each block.

    Qualtrics writes four timing columns before each block and four after
    it. The rating questions sit between them, so the timing columns are
    what mark where one block ends and the next begins."""
    blocks, current = defaultdict(list), None
    for i, name in enumerate(h1):
        started = re.match(r"^(TC\d+|TV\d+)_Click Count$", name)
        if started:
            current = started.group(1)
            continue
        if current and re.match(r"^(TC\d+|TV\d+)_", name):
            current = None
        if current is None:
            continue
        if h2[i] in SCALES:
            blocks[current].append((i, SCALE_KEY[h2[i]]))
        elif h2[i].startswith("Please explain"):
            blocks[current].append((i, "written_feedback"))
    return blocks


def survey_outputs():
    """The one warning each survey example was shown with.

    display_survey.py takes the first warning from the tool the grid assigns
    to that cell. The same one is taken here, so a participant rating and an
    agent score for the same example refer to the same warning."""
    grid = {(r["language"], r["vuln_type"]): r["tool"]
            for r in csv.DictReader(open(ROOT / "survey_grid.csv"))}
    idx = {r["example_id"]: r
           for r in csv.DictReader(open(ROOT / "dataset_index.csv"))}
    chosen = {}
    for w in csv.DictReader(open(ROOT / "normalised" / "outputs.csv")):
        ex = idx[w["example_id"]]
        if w["tool"] != grid[(ex["language"], ex["vuln_type"])]:
            continue
        chosen.setdefault(w["example_id"], w["output_id"])
    return chosen


def check(rows, people, blocks):
    """Stops the run if the two tables do not come out the size they should.

    A quiet mistake here would attach ratings to the wrong warning, and
    nothing further down would show it."""
    problems = []
    expected = len(people) * 12
    if len(rows) != expected:
        problems.append(f"{len(rows)} ratings, expected {expected}")
    if len(blocks) != 24:
        problems.append(f"{len(blocks)} blocks found, expected 24")
    bad = [r for r in rows
           if any(r[s] not in ("1", "2", "3", "4", "5")
                  for s in SCALE_KEY.values())]
    if bad:
        problems.append(f"{len(bad)} ratings are blank or outside 1 to 5")
    per_person = defaultdict(set)
    for r in rows:
        per_person[r["response_id"]].add(r["example_id"])
    odd = [p for p, ex in per_person.items() if len(ex) != 12]
    if odd:
        problems.append(f"{len(odd)} people did not rate exactly 12 examples")
    return problems


def main():
    rows = list(csv.reader(open(EXPORT)))
    h1, h2, data = rows[0], rows[1], rows[3:]
    blocks = find_blocks(h1, h2)
    outputs = survey_outputs()
    mapping = {r["block"]: r for r in csv.DictReader(open(BLOCK_MAP))}
    vi, ri = h1.index("version"), h1.index("ResponseId")

    ratings, people = [], []
    for r in data:
        version = r[vi]
        tag = "TC" if version == "calibration" else "TV"
        people.append({
            "response_id": r[ri], "version": version,
            "final_feedback": r[h1.index("QID612")],
            **{name: r[i] for i, name in PERSON_COLS.items()},
        })
        for block, cols in blocks.items():
            if not block.startswith(tag):
                continue
            m = mapping[block]
            row = {"response_id": r[ri], "version": version, "block": block,
                   "example_id": m["example_id"],
                   "output_id": outputs[m["example_id"]],
                   "language": m["language"], "vuln_type": m["vuln_type"],
                   "tool": m["tool"]}
            for i, key in cols:
                row[key] = r[i].strip()
            ratings.append(row)

    problems = check(ratings, people, blocks)
    if problems:
        for p in problems:
            print(" ", p)
        raise SystemExit("stopping: the export did not come out as expected")

    ratings.sort(key=lambda r: (r["response_id"], r["example_id"]))
    with open(RATINGS, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(ratings[0].keys()))
        w.writeheader()
        w.writerows(ratings)
    with open(PARTICIPANTS, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(people[0].keys()))
        w.writeheader()
        w.writerows(people)

    print(f"wrote {len(ratings)} ratings to {RATINGS.relative_to(ROOT)}")
    print(f"wrote {len(people)} participants to "
          f"{PARTICIPANTS.relative_to(ROOT)}")
    counts = defaultdict(int)
    for p in people:
        counts[p["version"]] += 1
    print("  by version:", dict(counts))


if __name__ == "__main__":
    main()
