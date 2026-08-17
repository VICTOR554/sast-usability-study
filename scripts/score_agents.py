#!/usr/bin/env python3
"""Score every warning with three models and write runs/agents/scores.csv.

This script scores all 104 warnings with three models, twice each. The
repeat run is done to answer the consistency part of RQ1. Agreement between
the three models is one measure of consistency. Whether a single model gives
the same answer twice on the same warning is another measure, and the repeat
run is what provides it.

The agents are shown the same thing the participants were shown. The code
snippet is built using the same window and the same give-away stripping as
display_survey.py. Those two functions are imported from that file rather
than copied into this one. If a copy was kept here, it would become out of
date as soon as one file was edited and the other was not. The prompt and
the five scales are read from rubric/rubric.md for the same reason.

Each row is written as soon as it arrives, and any work already in the file
is skipped. This means a run that stops part way can be started again.
Nothing is lost and no call is paid for twice.

    python3 scripts/score_agents.py --dry-run    # print one prompt, call nothing
    python3 scripts/score_agents.py --limit 3    # three warnings, to check it works
    python3 scripts/score_agents.py              # the full run
"""

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from display_survey import window, strip_giveaways, WINDOW

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "runs" / "agents" / "scores.csv"
RUBRIC = ROOT / "rubric" / "rubric.md"
ENV = ROOT / ".env"
RUNS_PER_MODEL = 2


def load_env():
    """Reads the API keys out of the .env file at the top of the repository.

    Python does not read a .env file on its own. The keys are kept in that
    file rather than in this script because the file is listed in .gitignore
    and will never be committed. A key already set in the shell is left
    alone, so it can be overridden for one run without editing the file."""
    if not ENV.exists():
        return
    for line in ENV.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        os.environ.setdefault(name.strip(), value.strip().strip("'\""))

# The dated model name goes here rather than the moving alias that a
# provider also offers. An alias always points at whatever version is
# newest. If an alias was used, two runs made months apart would be recorded
# under the same name while actually being different raters. Every call also
# stores the version the API reports back. This means a provider moving to a
# new version underneath the script will still show up in the data.
#
# All three models run at temperature 1. Gemini is set to 1 here. ChatGPT
# permits no other value, which its API says when sent a 0: "Only the default
# (1) value is supported." Claude shows a temperature of 1 in the Anthropic
# Workbench and no longer accepts the parameter over the API, so it is sent
# without one.
#
# Setting all three to 0 was the original plan and is not possible. That
# matters less than it first appeared, because temperature 0 never guaranteed
# identical output on any of these models. The repeat run measures the
# variation that remains, and RQ1 reports it rather than treating it as a
# fault in the method.
MODELS = {
    "claude": {"provider": "anthropic", "model": "claude-opus-5",
               "key": "ANTHROPIC_API_KEY", "temperature": None},
    "chatgpt": {"provider": "openai", "model": "gpt-5.5-2026-04-23",
                "key": "OPENAI_API_KEY", "temperature": None},
    "gemini": {"provider": "google", "model": "gemini-3.1-pro-preview",
               "key": "GOOGLE_API_KEY", "temperature": 1},
}

SCALES = ["clarity", "severity_justification", "specificity",
          "actionability", "completeness"]

FIELDS = (["output_id", "example_id", "language", "vuln_type", "tool",
           "model", "model_version", "run"]
          + [f"{s}_{p}" for s in SCALES for p in ("score", "why")]
          + ["written_feedback", "scored_at"])


def load_rubric():
    """Reads the five scales and the prompt template from rubric/rubric.md."""
    text = RUBRIC.read_text()
    start = text.index("## Clarity")
    scales = text[start:text.index("## Written Feedback")].strip()
    block = re.search(r"## Agent prompt.*?```\n(.*?)```", text, re.S)
    if not block:
        raise SystemExit("no fenced prompt block under '## Agent prompt'")
    return scales, block.group(1).strip()


def load_rows():
    """Reads every warning together with the example it belongs to."""
    idx = {r["example_id"]: r
           for r in csv.DictReader(open(ROOT / "dataset_index.csv"))}
    rows = []
    for w in csv.DictReader(open(ROOT / "normalised" / "outputs.csv")):
        rows.append((w, idx[w["example_id"]]))
    return rows


def build_prompt(template, scales, warning, example, size):
    """Builds one prompt.

    The output fields are laid out in the same order that display_survey.py
    uses for the participants. This is done so that both are judging the
    same thing."""
    path = ROOT / example["dataset_path"]
    lines, first, _last, _total = window(path, int(example["line"]), size)
    lines, _removed = strip_giveaways(lines, first)
    code = "\n".join(f"{first + i:5d}  {t}" for i, t in enumerate(lines))

    guidance = warning["rule_description"].strip()
    if warning["reference_url"]:
        guidance = (guidance + "\n" + warning["reference_url"]).strip()
    location = f"line {warning['line']}"
    if warning["column"]:
        location += f", column {warning['column']}"

    out = template
    for token, value in (("[[RUBRIC]]", scales),
                         ("[[CODE]]", code),
                         ("[[SEVERITY]]", warning["severity"] or "None given"),
                         ("[[RULE]]", warning["rule_id"]),
                         ("[[LOCATION]]", location),
                         ("[[MESSAGE]]", warning["message"]),
                         ("[[GUIDANCE]]", guidance or "None provided")):
        out = out.replace(token, value)
    left = re.findall(r"\[\[[A-Z]+\]\]", out)
    if left:
        raise SystemExit(f"prompt still holds {left} - token names disagree "
                         f"with rubric/rubric.md")
    return out


def safe(url):
    """Removes an API key from a URL before it is printed.

    Google takes its key as a query parameter. Without this the key would be
    printed in every error message and would end up in any saved log."""
    return re.sub(r"([?&]key=)[^&]+", r"\1HIDDEN", url)


def post(url, body, headers, timeout=120):
    """Makes one HTTP call and retries when a provider says it is busy.

    Rate limits and short outages are normal across six hundred calls. If
    the run was lost to one of them, the calls already made would have to be
    paid for a second time."""
    data = json.dumps(body).encode()
    for attempt in range(6):
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            # A 429 means either "too fast" or "out of credit". The first is
            # worth waiting out and the second never is, so an account with
            # no money left stops the run instead of retrying every call
            # six times.
            out_of_credit = "quota" in detail.lower()
            if e.code in (429, 500, 502, 503, 529) and attempt < 5 \
                    and not out_of_credit:
                wait = 2 ** attempt
                print(f"    {e.code}, waiting {wait}s")
                time.sleep(wait)
                continue
            raise SystemExit(f"{e.code} from {safe(url)}\n{detail}")
        except urllib.error.URLError as e:
            if attempt < 5:
                time.sleep(2 ** attempt)
                continue
            raise SystemExit(f"cannot reach {url}: {e}")
    raise SystemExit(f"gave up on {url}")


# The endpoints below are written as each provider documents them.
def call_anthropic(cfg, prompt):
    body = {"model": cfg["model"], "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}]}
    if cfg["temperature"] is not None:
        body["temperature"] = cfg["temperature"]
    d = post("https://api.anthropic.com/v1/messages", body,
             {"x-api-key": os.environ[cfg["key"]],
              "anthropic-version": "2023-06-01",
              "content-type": "application/json"})
    text = "".join(b.get("text", "") for b in d["content"]
                   if b.get("type") == "text")
    return text, d.get("model", cfg["model"])


def call_openai(cfg, prompt):
    body = {"model": cfg["model"],
            "messages": [{"role": "user", "content": prompt}]}
    if cfg["temperature"] is not None:
        body["temperature"] = cfg["temperature"]
    d = post("https://api.openai.com/v1/chat/completions", body,
             {"Authorization": f"Bearer {os.environ[cfg['key']]}",
              "Content-Type": "application/json"})
    return d["choices"][0]["message"]["content"], d.get("model", cfg["model"])


def call_google(cfg, prompt):
    body = {"contents": [{"parts": [{"text": prompt}]}]}
    if cfg["temperature"] is not None:
        body["generationConfig"] = {"temperature": cfg["temperature"]}
    # The key goes in a header rather than the query string, so it cannot
    # appear in an error message or a saved log.
    d = post(f"https://generativelanguage.googleapis.com/v1beta/models/"
             f"{cfg['model']}:generateContent", body,
             {"Content-Type": "application/json",
              "x-goog-api-key": os.environ[cfg["key"]]})
    parts = d["candidates"][0]["content"]["parts"]
    text = "".join(p.get("text", "") for p in parts if "text" in p)
    return text, d.get("modelVersion", cfg["model"])


CALLERS = {"anthropic": call_anthropic, "openai": call_openai,
           "google": call_google}


def parse_reply(text):
    """Takes the JSON out of a reply.

    A reply may arrive on its own, inside a code fence, or with a sentence
    before or after it. The first complete JSON object is read and anything
    following it is ignored. Replies vary in shape between calls, so the
    parser cannot assume the model returned nothing else."""
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*", "", t)
        t = re.sub(r"\s*```$", "", t).strip()
    start = t.find("{")
    if start == -1:
        return None, "no JSON in reply"
    try:
        d, _end = json.JSONDecoder().raw_decode(t[start:])
    except json.JSONDecodeError as e:
        return None, f"bad JSON: {e}"
    for s in SCALES:
        if s not in d or "score" not in d.get(s, {}):
            return None, f"missing {s}"
        if d[s]["score"] not in (1, 2, 3, 4, 5):
            return None, f"{s} score is {d[s]['score']!r}, not 1-5"
    return d, None


def done_already():
    """Reads what is already in the CSV.

    A restarted run uses this so that work is not done a second time."""
    if not OUT.exists():
        return set()
    return {(r["output_id"], r["model"], r["run"])
            for r in csv.DictReader(open(OUT))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="print one prompt and stop, calling nothing")
    ap.add_argument("--limit", type=int,
                    help="score only this many warnings")
    ap.add_argument("--models", help="comma-separated subset of the models")
    ap.add_argument("--runs", type=int, default=RUNS_PER_MODEL,
                    help="passes per model")
    ap.add_argument("--window", type=int, default=WINDOW,
                    help="lines shown either side of the flagged line")
    args = ap.parse_args()

    load_env()
    scales, template = load_rubric()
    rows = load_rows()
    if args.limit:
        rows = rows[:args.limit]

    if args.dry_run:
        print(build_prompt(template, scales, *rows[0], args.window))
        print(f"\n--- {len(rows)} warnings, {args.runs} runs each ---")
        return

    chosen = args.models.split(",") if args.models else list(MODELS)
    for name in chosen:
        if name not in MODELS:
            raise SystemExit(f"unknown model {name}, expected {list(MODELS)}")
        if not MODELS[name]["model"]:
            raise SystemExit(f"no model id set for {name} - fill in MODELS")
        if not os.environ.get(MODELS[name]["key"]):
            raise SystemExit(f"{MODELS[name]['key']} is not set. Put it in "
                             f"{ENV.name} at the top of the repository.")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    seen = done_already()
    new = OUT.exists() and OUT.stat().st_size > 0
    f = open(OUT, "a", newline="")
    writer = csv.DictWriter(f, fieldnames=FIELDS)
    if not new:
        writer.writeheader()

    total = len(rows) * len(chosen) * args.runs
    n, skipped, failed = 0, 0, []
    for run in range(1, args.runs + 1):
        for warning, example in rows:
            prompt = build_prompt(template, scales, warning, example,
                                  args.window)
            for name in chosen:
                n += 1
                key = (warning["output_id"], name, str(run))
                if key in seen:
                    skipped += 1
                    continue
                cfg = MODELS[name]
                reply, version = CALLERS[cfg["provider"]](cfg, prompt)
                parsed, problem = parse_reply(reply)
                if problem:
                    failed.append((warning["output_id"], name, run, problem))
                    print(f"  [{n}/{total}] {warning['output_id']} {name} "
                          f"run {run}: {problem}")
                    continue
                row = {"output_id": warning["output_id"],
                       "example_id": warning["example_id"],
                       "language": warning["language"],
                       "vuln_type": warning["vuln_type"],
                       "tool": warning["tool"],
                       "model": name, "model_version": version, "run": run,
                       "written_feedback": parsed.get("written_feedback", ""),
                       "scored_at": datetime.now(timezone.utc).isoformat()}
                for s in SCALES:
                    row[f"{s}_score"] = parsed[s]["score"]
                    row[f"{s}_why"] = parsed[s].get("why", "")
                writer.writerow(row)
                f.flush()
                print(f"  [{n}/{total}] {warning['output_id']} {name} run {run}")
    f.close()

    print(f"\nwrote to {OUT.relative_to(ROOT)}")
    if skipped:
        print(f"  already scored, skipped: {skipped}")
    if failed:
        print(f"  no usable reply: {len(failed)}")
        for out_id, name, run, problem in failed[:10]:
            print(f"    {out_id} {name} run {run}: {problem}")
        print("  re-running the script retries only these")


if __name__ == "__main__":
    main()
