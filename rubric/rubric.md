# Rubric

The five scales below are what participants answered in Qualtrics, copied
word for word. They are also what the agents score against. Both have to
read the same wording, or RQ1 compares two different rubrics and the
agreement figures mean nothing.

The scale text will not be edited. The survey is live, and changing a word
now creates a version no participant saw. Anything found wrong with it is
recorded and reported as a finding instead.

---

## What is being scored

For this study, a SAST output means all developer facing information
directly associated with one reported security issue. This may include,
where provided, the warning message, rule name or identifier, severity
label, code location, highlighted code, an explanation of why the code is
vulnerable, and remediation guidance available in the finding or through
rule documentation linked from it. Only information captured and presented
to both participants and agents will be scored.

In the survey this is the panel under the SAST OUTPUT heading: severity,
rule, location, message and guidance. The code snippet above it is context
for judging the output, not part of it.

---

## Clarity

1. The output is very hard to understand.
2. The output is hard to understand, aside from a few clear parts.
3. The output can be understood, but requires some effort.
4. The output is easy to understand, aside from a few unclear parts.
5. The output is easy to understand.

## Severity Justification

1. The output has no severity label.
2. The output gives a severity label, without explaining why the issue is serious.
3. The output gives a severity label, with a broad explanation of why this type of issue is serious.
4. The output gives a severity label, with an explanation of why the issue is serious in relation to the code snippet.
5. The output gives a severity label, with an explanation of why the issue is serious in relation to the code snippet and what could happen if it were exploited.

## Specificity

1. The output makes no reference to the code snippet.
2. The output identifies a broad area of the code snippet only.
3. The output identifies the relevant function or section.
4. The output identifies the exact code line.
5. The output identifies the exact code line and the specific part of the line that is responsible.

## Actionability

1. The output suggests no fix.
2. The output suggests a broad fix that could apply to similar issues.
3. The output suggests what to change in the code snippet.
4. The output suggests what to change in the code snippet, with some guidance on how to apply it.
5. The output suggests what to change in the code snippet, with complete guidance on how to apply it.

## Completeness

The five expected parts are:

- A severity label
- A description of the reported issue
- The code location
- An explanation of why the code is vulnerable
- Remediation guidance (advice on how to fix the issue)

1. The output includes none or one of the five parts.
2. The output includes two of the five parts.
3. The output includes three of the five parts.
4. The output includes four of the five parts.
5. The output includes all five parts.

## Written Feedback

Please explain your ratings in your own words. What made the output clear or
unclear, specific or vague, easy or hard to act on, and was anything missing
or unexplained?

---

## Agent prompt

Frozen on 20 August 2026, after one calibration round. That round compared
the agents against the twelve calibration outputs and found no revision worth
changing. Replaced on 22 August 2026 by rubric_2.md.

The rubric text is fixed, so the prompt loads the scale sections above rather
than repeating them.

```
Scoring the usability of a single static analysis tool warning.

Below is a code snippet, then the tool's output about that code. Score the
OUTPUT only. The code is context for judging whether the output describes it
well; the code itself is not being assessed, and neither is whether the
warning is correct.

<rubric>
[[RUBRIC]]
</rubric>

<code_snippet>
[[CODE]]
</code_snippet>

<sast_output>
Severity: [[SEVERITY]]
Rule: [[RULE]]
Location: [[LOCATION]]
Message: [[MESSAGE]]
Guidance: [[GUIDANCE]]
</sast_output>

For each of the five scales, first say in one sentence what in the output
decides the score, quoting the words it rests on, then give the score from
1 to 5.

Then answer the question below as written. It is the question participants
answered, and it is not a summary of the five sentences above:

Please explain your ratings in your own words. What made the output clear or
unclear, specific or vague, easy or hard to act on, and was anything missing
or unexplained?

Return JSON only:
{"clarity": {"why": "...", "score": n},
 "severity_justification": {"why": "...", "score": n},
 "specificity": {"why": "...", "score": n},
 "actionability": {"why": "...", "score": n},
 "completeness": {"why": "...", "score": n},
 "written_feedback": "..."}
```
