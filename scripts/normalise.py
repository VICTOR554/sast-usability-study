#!/usr/bin/env python3
"""Turn the three tools' output into one table of warnings.

Each tool reports findings in its own shape, so nothing can be compared
until they are written the same way. This reads runs/, keeps the warnings
that land on the chosen examples, and writes normalised/outputs.csv.

The finding text and the rule text are kept in separate columns. The tools
split their explanation differently: Semgrep puts the advice in the finding,
CodeQL keeps the finding to one sentence and explains at rule level, Bearer
uses a separate description. Scoring only the finding would make CodeQL
look far worse than it is to a developer, who sees both.

Two kinds of warning are left out. A tool sometimes reports a different
vulnerability at the same line, and an example stands for one vulnerability,
so those are dropped. Two rules from the same tool sometimes produce word
for word the same message, and only one of those is kept. Warnings that are
worded differently are all kept, since a developer would see each of them.

Nothing is reworded or shortened. What a tool wrote is what gets stored.

    python3 scripts/normalise.py
"""

import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from coverage import (load_json, scan_files, norm_path, classify,
                      cwe_from_semgrep, cwe_from_codeql)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "normalised" / "outputs.csv"

FIELDS = ["output_id", "example_id", "language", "vuln_type", "tool",
          "rule_id", "severity", "line", "column",
          "message", "rule_description", "reference_url"]


def strip_markdown(text):
    """Bearer writes markdown headings and links. The words are kept as the
    tool wrote them. Only the formatting marks come out."""
    if not text:
        return ""
    t = re.sub(r"^#+\s*", "", text, flags=re.M)
    t = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", t)
    t = re.sub(r"`{1,3}", "", t)
    return re.sub(r"\n{2,}", "\n", t).strip()


def wanted_examples():
    """The chosen examples, keyed by source and file so findings can be
    matched back to them."""
    want = {}
    with open(ROOT / "dataset_index.csv") as f:
        for r in csv.DictReader(f):
            proj, rel = r["source_path"].split("/", 1)
            want[(proj, rel, int(r["line"]))] = r
    return want


def collect_semgrep(want, rows):
    for p in scan_files("semgrep", ".json"):
        proj = p.name.split(".")[0]
        for r in load_json(p).get("results", []):
            key = (proj, norm_path(r["path"]), r.get("start", {}).get("line"))
            ex = want.get(key)
            if not ex:
                continue
            vt, _ = classify(r["check_id"], cwe_from_semgrep(r))
            if vt != ex["vuln_type"]:
                continue
            extra = r.get("extra", {})
            md = extra.get("metadata", {})
            refs = md.get("references") or []
            rows.append({
                "example_id": ex["example_id"], "language": ex["language"],
                "vuln_type": ex["vuln_type"], "tool": "semgrep",
                "rule_id": r["check_id"],
                "severity": extra.get("severity", ""),
                "line": r.get("start", {}).get("line", ""),
                "column": r.get("start", {}).get("col", ""),
                "message": (extra.get("message") or "").strip(),
                # Semgrep has no rule-level text beyond the message
                "rule_description": "",
                "reference_url": refs[0] if refs else "",
            })


def collect_codeql(want, rows):
    for p in scan_files("codeql", ".sarif"):
        proj = p.name.split(".")[0]
        run = load_json(p)["runs"][0]
        rules = {x["id"]: x for x in run["tool"]["driver"].get("rules", [])}
        for r in run.get("results", []):
            loc = r["locations"][0]["physicalLocation"]
            key = (proj, norm_path(loc["artifactLocation"]["uri"]),
                   loc["region"].get("startLine"))
            ex = want.get(key)
            if not ex:
                continue
            rule = rules.get(r.get("ruleId"), {})
            vt, _ = classify(r.get("ruleId"), cwe_from_codeql(rule))
            if vt != ex["vuln_type"]:
                continue
            desc = (rule.get("fullDescription", {}).get("text")
                    or rule.get("shortDescription", {}).get("text") or "")
            rows.append({
                "example_id": ex["example_id"], "language": ex["language"],
                "vuln_type": ex["vuln_type"], "tool": "codeql",
                "rule_id": r.get("ruleId", ""),
                "severity": rule.get("defaultConfiguration", {}).get("level", ""),
                "line": loc["region"].get("startLine", ""),
                "column": loc["region"].get("startColumn", ""),
                "message": r["message"]["text"].strip(),
                "rule_description": desc.strip(),
                "reference_url": "",
            })


def collect_bearer(want, rows):
    for p in scan_files("bearer", ".json"):
        proj = p.name.split(".")[0]
        d = load_json(p)
        for sev in ("critical", "high", "medium", "low", "warning"):
            for x in d.get(sev) or []:
                key = (proj, norm_path(x.get("filename") or ""),
                       x.get("line_number"))
                ex = want.get(key)
                if not ex:
                    continue
                cwes = [str(int(c)) for c in (x.get("cwe_ids") or [])
                        if str(c).isdigit()]
                vt, _ = classify(x.get("id"), cwes)
                if vt != ex["vuln_type"]:
                    continue
                rows.append({
                    "example_id": ex["example_id"], "language": ex["language"],
                    "vuln_type": ex["vuln_type"], "tool": "bearer",
                    "rule_id": x.get("id", ""),
                    "severity": sev,
                    "line": x.get("line_number", ""),
                    # Bearer reports no column
                    "column": "",
                    "message": (x.get("title") or "").strip(),
                    "rule_description": strip_markdown(x.get("description")),
                    "reference_url": x.get("documentation_url", ""),
                })


def main():
    """Writes one row per warning and checks it against dataset_index.csv."""
    want = wanted_examples()
    rows = []
    collect_semgrep(want, rows)
    collect_codeql(want, rows)
    collect_bearer(want, rows)

    # two rules from one tool sometimes produce the same sentence
    seen, deduped, dropped = set(), [], 0
    for r in rows:
        key = (r["example_id"], r["tool"], r["message"])
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        deduped.append(r)
    rows = deduped

    rows.sort(key=lambda r: (r["example_id"], r["tool"]))
    for i, r in enumerate(rows, 1):
        r["output_id"] = f"OUT{i:03d}"

    # every example should produce exactly the warnings its tools column lists
    expected = {}
    with open(ROOT / "dataset_index.csv") as f:
        for r in csv.DictReader(f):
            expected[r["example_id"]] = set(r["tools"].split("|"))
    got = {}
    for r in rows:
        got.setdefault(r["example_id"], set()).add(r["tool"])
    missing = {e: expected[e] - got.get(e, set()) for e in expected
               if expected[e] - got.get(e, set())}

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})

    from collections import Counter
    print(f"wrote {len(rows)} warnings to {OUT.relative_to(ROOT)}")
    print(f"  dropped as word-for-word repeats: {dropped}")
    print("  by tool:", dict(Counter(r["tool"] for r in rows)))
    print("  examples covered:", len(got), "of", len(expected))
    blank = sum(1 for r in rows if not r["message"])
    print("  warnings with no message text:", blank)
    if missing:
        print("\nexpected warnings that did not come through:")
        for e, tools in list(missing.items())[:10]:
            print(f"  {e}: {sorted(tools)}")


if __name__ == "__main__":
    main()
