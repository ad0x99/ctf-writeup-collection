# Writeups

Polished, readable writeups of completed (or partially completed) investigations. Each file is `writeups/<platform>/<target-name>.md` and corresponds to `investigations/<platform>/<target-name>/investigation.md`. Writeups are grouped by `<platform>` for the same reason investigations are: it keeps the collection navigable as it grows.

## Supported sources

- CTF challenges (TryHackMe, Hack The Box, events) and personal labs: narrative writeup.
- Bug bounty engagements: vulnerability report structure (summary, affected asset, steps to reproduce, impact, remediation) instead of a flag section.

## Generating a writeup

```
/ctf-writeup <target-name>
```

Naming it by `<target-name>` alone is enough; the skill searches across every platform folder in `investigations/` for a match and asks if there's ambiguity (the same target name under more than one platform) or no name given. You can also give the full `<platform>/<target-name>` directly if you already know it. The skill locates the investigation, reads it in full, inspects referenced evidence, and writes a separate document here, under the matching `writeups/<platform>/` folder. If several investigations exist and none is named, it asks which one. If a writeup already exists, it asks whether to update it, create a new version, or use another destination. It never modifies the investigation file.

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
