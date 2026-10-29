# Writeups

Polished, readable writeups of completed (or partially completed) investigations. Each file is `writeups/<target-name>.md` and corresponds to `investigations/<target-name>/investigation.md`.

## Supported sources

- CTF challenges (TryHackMe, Hack The Box, events) and personal labs: narrative writeup.
- Bug bounty engagements: vulnerability report structure (summary, affected asset, steps to reproduce, impact, remediation) instead of a flag section.

Writeups written before the investigation workflow existed live under `TryHackMe/<Room>/` and are left as they are.

## Generating a writeup

```
/ctf-writeup <target-name>
```

The skill locates the investigation, reads it in full, inspects referenced evidence, and writes a separate document here. If several investigations exist and none is named, it asks which one. If a writeup already exists, it asks whether to update it, create a new version, or use another destination. It never modifies the investigation file.

## Investigation notes vs. writeups

|         | Investigation                                  | Writeup                                  |
| ------- | ---------------------------------------------- | ---------------------------------------- |
| Purpose | Live source of truth                           | Final narrative for readers              |
| Written | During the work, after each phase              | On request, from the investigation       |
| Content | Everything, including raw detail and dead ends | Curated story with the relevant evidence |
| Voice   | Notes                                          | First-person narrative ("we"/"I")        |

## Active challenges and disclosure

- Do not publish flags, answers, or full solutions for active challenges or competitions whose rules forbid it. Use `[REDACTED]` and note it in the writeup.
- Respect platform and bug bounty program disclosure rules. Do not publish bug bounty findings before permission or resolution.
- Remove live credentials, tokens, personal data, and out-of-scope details.
