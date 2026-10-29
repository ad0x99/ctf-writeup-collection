# Investigations

Each directory here is the live working record of one bug bounty engagement, CTF challenge, or personal lab. The `investigation.md` file is the **primary source of truth** for what we investigated, observed, suspected, tested, learned, confirmed, and left unresolved.

## Layout and naming

```
investigations/
├── templates/investigation-template.md
└── <target-name>/
    ├── investigation.md
    └── evidence/
        ├── E-001.txt
        └── E-002.txt
```

`<target-name>` is lowercase, ASCII, hyphen-separated, with no spaces or special characters (e.g. `silent-monitor`). The same name is used for the final writeup: `writeups/<target-name>.md`.

## Continuous documentation workflow

1. **Start:** the assistant establishes scope, creates `investigation.md` from the template, and reports the path. If the investigation already exists it is continued, never duplicated or overwritten.
2. **Investigate:** testing proceeds within scope, using safe, non-destructive methods.
3. **After every meaningful phase** (recon, attack surface discovery, auth/authz analysis, business logic, input validation, hypothesis development, validation, impact assessment, final review) the assistant must:
   - summarize the phase in chat,
   - update `investigation.md` (observations, hypotheses, actions, results, evidence, findings, open questions, status, next steps),
   - confirm which sections were updated and whether the save succeeded.
4. **Finish:** complete the Final Investigation Summary and Writeup Handoff sections, and remove unnecessary empty sections.

## Evidence storage

- Small snippets (a request, a short response) go inline in the log.
- Large artifacts (scan output, full responses, source dumps, screenshots) go in `evidence/` as `E-NNN.<ext>`, registered in the Evidence and Artifacts table (section 8) with a description and related finding.
- Do not store live credentials, real flags of active challenges, or unnecessary sensitive data. Redact with `[REDACTED]`.

## Relationship to writeups

Investigations are raw, chronological, and complete, including dead ends. Writeups are polished narratives generated from them with `/ctf-writeup`. The writeup skill reads the investigation but never modifies it.
