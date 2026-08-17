#!/usr/bin/env python3
"""Build the 24 survey outputs as HTML ready to paste into Qualtrics.

Each output is a window of code with the warning below it. The layout is
identical for every tool and the wording is left exactly as the tool wrote
it, so what varies between outputs is how the tool communicates rather than
how its interface looks.

Line numbers are the file's own. The window is not renumbered from one, and
give-away comments are replaced with a blank line rather than deleted, so a
warning pointing at line 48 lands on the row marked 48. Specificity is
scored on whether the output identifies the exact line, so those have to
agree.

Nothing identifies which tool produced a warning. People can hold opinions about
these tools and a visible name can bring bias.

    python3 scripts/display_survey.py
    python3 scripts/display_survey.py --window 20
"""

import argparse
import csv
import html
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SURVEY = ROOT / "survey"
WINDOW = 15

# Comments that name the vulnerability. Juliet writes POTENTIAL FLAW,
# DjanGoat writes "intended vulnerability", and Juice Shop tags its training
# code with vuln-code-snippet markers. One of those markers, vuln-line, sits
# on the vulnerable line itself. That is as complete a give away as it gets.
GIVEAWAY = re.compile(
    r"(POTENTIAL FLAW|FLAW:|BAD SOURCE|BAD SINK|intended vulnerability"
    r"|vulnerability for|/\* *BAD *\*/|# *BAD\b|INCIDENTAL:|FIX:"
    r"|vuln-code-snippet)",
    re.I)

# A comment sitting on its own line, as opposed to trailing real code.
COMMENT_ONLY = re.compile(r"^\s*(//|#|/\*|\*)")
# A trailing comment, so the code before it can be kept.
TRAILING = re.compile(r"\s*(//|#).*$")


def strip_giveaways(lines, start):
    """Takes out comments that name the vulnerability.

    A comment on its own line becomes blank, so the line count and every
    line number below it stay the same. A comment trailing real code has
    only the comment removed. Juice Shop puts its vuln-line marker at the
    end of the vulnerable line itself, so blanking that whole line would
    delete the very code the warning is about."""
    removed, out = [], []
    for i, text in enumerate(lines):
        if not GIVEAWAY.search(text):
            out.append(text)
            continue
        removed.append((start + i, text.strip()))
        if COMMENT_ONLY.match(text):
            out.append("")
        else:
            out.append(TRAILING.sub("", text).rstrip())
    return out, removed


def check_copy(row, paths):
    """The copy in dataset/ has to match the file the tools read.

    If it does not, every line number is wrong and the survey highlights the
    wrong code. This happened once. A stale copy differed from its source by
    two lines, so the flagged line pointed at a return statement instead of
    the query that caused the warning."""
    proj, rel = row["source_path"].split("/", 1)
    src = ROOT / paths[proj] / rel
    if not src.exists():
        return f"{row['example_id']}: source missing ({src})"
    if src.read_bytes() != (ROOT / row["dataset_path"]).read_bytes():
        return (f"{row['example_id']}: dataset copy differs from "
                f"{row['source_path']} - re-run select_examples.py")
    return None


def window(path: Path, line: int, size: int):
    """The lines around the flagged one, with their real numbers."""
    all_lines = path.read_text(errors="replace").splitlines()
    first = max(1, line - size)
    last = min(len(all_lines), line + size)
    return all_lines[first - 1:last], first, last, len(all_lines)


# Styles are written onto each element rather than kept in a stylesheet.
# Qualtrics strips <style> from question HTML, and without it the code loses
# its monospace font, its indentation and its column widths.
MONO = "font-family:Menlo,Consolas,'Courier New',monospace;font-size:13px;line-height:1.45"
S_TABLE = ("border-collapse:collapse;width:100%;background:#fafafa;"
           "border:1px solid #e5e5e5;margin-bottom:22px")
S_LN = (f"{MONO};color:#999;text-align:right;padding:0 8px 0 6px;"
        "border-right:1px solid #e5e5e5;width:46px;"
        "vertical-align:top;-webkit-user-select:none;user-select:none")
S_SRC = f"{MONO};padding:0 8px;white-space:pre;vertical-align:top"
S_WTAB = "border-collapse:collapse;width:100%;font-size:14px"
# The warning sits in its own panel. Without one it reads as loose text
# under the code block rather than as a separate thing being judged.
S_WPANEL = ("border:1px solid #e5e5e5;background:#fff;border-left:3px solid #bbb;"
            "padding:12px 14px")
S_WTH = ("text-align:left;vertical-align:top;padding:4px 12px 4px 0;"
         "width:96px;color:#555;font-weight:600")
S_WTD = "padding:4px 0;vertical-align:top;white-space:pre-wrap"
# Headings so a participant can see where the code stops and the tool's
# words begin. The wording is kept neutral. Naming the tool or the
# vulnerability type would give away more than the warning does.
S_HEAD = ("font-family:-apple-system,Segoe UI,sans-serif;font-size:13px;"
          "font-weight:700;letter-spacing:.08em;text-transform:uppercase;"
          "color:#000;margin:0 0 8px")


def code_html(text):
    """Escapes a line and makes its indent non-breaking.

    white-space:pre already holds the indentation, but editors that drop the
    style attribute collapse runs of spaces and the code loses its shape.
    Non-breaking spaces survive that. Tabs become four spaces first, so a
    file mixing tabs and spaces still lines up."""
    text = text.replace("\t", "    ")
    stripped = text.lstrip(" ")
    indent = len(text) - len(stripped)
    return "&nbsp;" * indent + html.escape(stripped) if stripped else "&nbsp;"


def render(ex, warning, code_lines, first, flagged):
    """One survey output: the code, then the warning underneath."""
    rows = []
    for i, text in enumerate(code_lines):
        n = first + i
        bg = ' style="background:#fff4e5"' if n == flagged else ""
        rows.append(f'<tr{bg}><td style="{S_LN}">{n}</td>'
                    f'<td style="{S_SRC}">{code_html(text)}</td></tr>')

    guidance = warning["rule_description"].strip()
    if warning["reference_url"]:
        guidance = (guidance + "\n" + warning["reference_url"]).strip()
    if not guidance:
        guidance = "None provided"

    loc = f"line {warning['line']}"
    if warning["column"]:
        loc += f", column {warning['column']}"

    def wrow(label, value):
        return (f'<tr><th style="{S_WTH}">{label}</th>'
                f'<td style="{S_WTD}">{html.escape(value)}</td></tr>')

    return f"""<div style="border:1px solid #d0d0d0;border-radius:6px;padding:14px;margin:24px 0">
<p style="{S_HEAD}">Code snippet</p>
<table style="{S_TABLE}">
{chr(10).join(rows)}
</table>
<p style="{S_HEAD}">SAST output</p>
<div style="{S_WPANEL}">
<table style="{S_WTAB}">
{wrow('Severity', warning['severity'] or 'None given')}
{wrow('Rule', warning['rule_id'])}
{wrow('Location', loc)}
{wrow('Message', warning['message'])}
{wrow('Guidance', guidance)}
</table>
</div>
</div>"""


# Only the preview page uses this. The blocks themselves carry their styles
# inline so they survive being pasted into Qualtrics.
STYLE = ("<style>body{font:15px/1.5 -apple-system,Segoe UI,sans-serif;"
         "margin:2rem auto;max-width:56rem;color:#222}"
         "h1{font-size:20px}h2{font-size:14px;color:#666;margin-top:2.5rem;"
         "font-weight:600}</style>")


def main():
    """Writes one HTML file per output plus a preview page per version."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=WINDOW,
                    help="lines shown either side of the flagged line")
    args = ap.parse_args()

    grid = {(r["language"], r["vuln_type"]): r["tool"]
            for r in csv.DictReader(open(ROOT / "survey_grid.csv"))}
    warnings = defaultdict(list)
    for w in csv.DictReader(open(ROOT / "normalised" / "outputs.csv")):
        warnings[(w["example_id"], w["tool"])].append(w)

    rows = [r for r in csv.DictReader(open(ROOT / "dataset_index.csv"))
            if r["survey_role"] != "dataset_only"]

    paths = {r["source_id"]: r["local_path"]
             for r in csv.DictReader(open(ROOT / "sources.csv"))}
    stale = [m for m in (check_copy(r, paths) for r in rows) if m]
    if stale:
        for m in stale:
            print(m)
        raise SystemExit("\nstopping: line numbers would not match the code")

    all_removed, long_snips = [], []
    for role in ("calibration", "validation"):
        out_dir = SURVEY / role / "display"
        out_dir.mkdir(parents=True, exist_ok=True)
        for f in out_dir.glob("*.html"):
            f.unlink()

        blocks = []
        for r in sorted(rows, key=lambda x: x["example_id"]):
            if r["survey_role"] != role:
                continue
            tool = grid[(r["language"], r["vuln_type"])]
            w = warnings[(r["example_id"], tool)][0]
            path = ROOT / r["dataset_path"]
            line = int(r["line"])
            lines, first, last, total = window(path, line, args.window)
            lines, removed = strip_giveaways(lines, first)
            for n, text in removed:
                all_removed.append((r["example_id"], n, text))
            if last - first > 60:
                long_snips.append(r["example_id"])

            block = render(r, w, lines, first, line)
            (out_dir / f"{r['example_id']}.html").write_text(
                f"<!doctype html><meta charset=utf-8>{STYLE}{block}")
            blocks.append(f"<h2>{r['example_id']} &mdash; "
                          f"{path.name} (lines {first}&ndash;{last} of {total})</h2>"
                          + block)

        (SURVEY / role / "preview.html").write_text(
            f"<!doctype html><meta charset=utf-8><title>{role}</title>{STYLE}"
            f"<h1>{role.title()} &mdash; {len(blocks)} outputs</h1>"
            + "".join(blocks))
        print(f"{role}: {len(blocks)} outputs -> survey/{role}/display/")

    print(f"\ncomments blanked: {len(all_removed)}")
    for ex, n, text in all_removed[:15]:
        print(f"  {ex} line {n}: {text[:70]}")
    if len(all_removed) > 15:
        print(f"  ... and {len(all_removed) - 15} more")
    if long_snips:
        print(f"\nsnippets over 60 lines, worth a look: {long_snips}")
    print("\nread survey/calibration/preview.html and "
          "survey/validation/preview.html before building anything")


if __name__ == "__main__":
    main()
