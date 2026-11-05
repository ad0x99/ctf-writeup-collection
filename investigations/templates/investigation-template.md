# Security Investigation: [Target / Challenge Name]

## Table of Contents

[Always include this section, right after the title, regardless of
document length. Link each `## N. ...` section heading and each
`### Phase N: ...` heading inside the Investigation Log to its own
auto-generated GitHub-flavored slug (lowercase, strip punctuation that
isn't a letter/number/space/hyphen, replace spaces with hyphens). The
`#### ...` sub-headings inside each phase are too granular for the TOC.
Rebuild this list whenever a phase or section is added, removed, or
renamed.]

## 1. Investigation Overview

- Target / Challenge:
- Platform / Program:
- Investigation Type: Bug Bounty / CTF / Personal Lab
- Scope:
- Restrictions:
- Start Date:
- Status: In Progress
- Primary Objective:

## 2. Current Investigation Status

### Summary

### Confirmed Findings

### Active Hypotheses

### Open Questions

### Next Steps

## 3. Scope and Environment

### Authorized Targets

### Restrictions

### Environment

### Initial Information

## 4. Investigation Log

Chronological investigation records.

### Phase 1: [Phase Name]

#### Objective

#### Observations

#### Hypotheses

#### Actions and Experiments

[Paste the actual command(s), request(s), or payload(s) run, in order, each in a fenced code block with the right language tag. Not a prose description of what was tried — the real thing that was typed or sent.]

#### Results

[Paste the actual output/response, fenced, matching each action above. Not a paraphrase of what happened. Truncate only genuinely large output (a full port sweep, a long process-monitor log) with a short note pointing at the evidence file holding the rest, but keep enough real output inline to show what actually happened.]

#### Analysis

#### Failed Attempts / Dead Ends

#### Findings

#### Evidence

[Embed any screenshot directly with `![caption](evidence/images/<file>.png)` (a path relative to this investigation.md file, since `evidence/` is right beside it) so it renders inline here, not just as a path or filename in text. Reference non-image evidence (raw notes, disclosed source files, logs) by path the same way.

Any script or code written to support this phase (an exploit payload, a forgery script, an automation helper) is saved to `evidence/scripts/<name>.<ext>`, distinct from `evidence/sources/` (code pulled *from* the target). Reference it here; if short, also embed its full content as a fenced code block in Actions and Experiments above, at the point it's used.]

#### Remaining Questions

#### Next Steps

### Phase 2: [Phase Name]

Repeat the phase structure above as needed.

## 5. Vulnerability Candidates

### Candidate 1: [Vulnerability Title]

- Status: Hypothesis / Under Investigation / Confirmed / Disproven
- Affected Asset:
- Affected Endpoint / Functionality:
- Vulnerability Class:
- Observation:
- Hypothesis:
- Testing Performed:
- Evidence:
- Validation Status:
- Demonstrated Impact:
- Potential Impact:
- Remaining Questions:
- Next Steps:

## 6. Confirmed Vulnerabilities

Document each sufficiently validated vulnerability.

Include:

- Title
- Affected asset
- Preconditions
- Underlying behavior or root cause
- Reproduction steps
- Supporting evidence
- Expected behavior
- Actual behavior
- Demonstrated impact
- Limitations and uncertainties
- Remediation ideas

## 7. Rabbit Holes and Disproven Hypotheses

For each relevant investigation:

- Initial reasoning
- What we tried
- Results
- Why it failed or was disproven
- What we learned

## 8. Evidence and Artifacts

| ID    | Description | Location | Related Finding |
| ----- | ----------- | -------- | --------------- |
| E-001 |             |          |                 |

## 9. Technical Knowledge and Lessons Learned

### Concepts

### Techniques

### Lessons

### Future Applications

## 10. Final Investigation Summary

### Investigation Outcome

### Confirmed Vulnerabilities

### Unsuccessful Investigations

### Unresolved Issues

### Final Status

## 11. Writeup Handoff

- Investigation File:
- Final Writeup:
- Writeup Status:
- Important Narrative Events:
- Evidence References:
- Special Instructions:
