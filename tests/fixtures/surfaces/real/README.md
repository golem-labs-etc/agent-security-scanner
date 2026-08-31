# Real bundled skill files, verbatim

Three skill files taken unmodified from a stock Hermes install. They are here
because every other negative fixture in this suite is short, hand-written, and
has its payload on one line, and a suite made only of those fixtures passed
green while the scanner produced 1508 critical findings on an ordinary machine.

Length is the point. A real skill file has YAML frontmatter, fenced shell
blocks with an API key in them, bulleted lists of commands, and prose that
wraps. Every defect these files caught was a rule whose window was wider than
the thing it was reading:

| File | What it caught |
|---|---|
| `R1_fitness_nutrition.SKILL.md` | a code fence that masked its opening line and one line of body and no more, so the documented `curl` was scanned as prose |
| `R2_github_repo_management.SKILL.md` | the file that exists in 22 profiles, byte-identical, and was reported as 22 separate problems |
| `R3_google_workspace.SKILL.md` | frontmatter joined into one "sentence", so a credential filename on one key and a URL on another became an exfiltration instruction |

They assert zero critical and zero high. Nothing about them is asserted more
finely than that, because the claim being made is the one that matters: a
scanner that fires on a stock install is a scanner nobody runs twice.

## Provenance and licence

All three are MIT, from the Hermes agent distribution
(<https://github.com/NousResearch/hermes>), MIT License, Copyright (c) 2025
Nous Research. Individual authorship as declared in each file's frontmatter:

- `R1` — Hailey Marshall (haileymarshall), Hermes Agent
- `R2` — Hermes Agent
- `R3` — Nous Research

They are unmodified. The `.SKILL.md` suffix keeps the original name visible
while letting the three sit in one directory.
