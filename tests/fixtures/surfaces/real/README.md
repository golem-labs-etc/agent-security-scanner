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

# Eight real files from ECC, verbatim — the quoted-directive class

`ECC1`–`ECC8` are the security-content false positives of issue #51: files that
state a defence and quote the attack they forbid, plus a detector's own
`INJECTION_PATTERNS` list in English and in its zh-CN translation. On 1.5.5 the
eight produced six HIGH `prompt_injection` and two MEDIUM `fenced_directive` —
a project that writes injection defences got the scanner's worst report.

They assert **nothing above info, under `balanced` only**. Both halves matter:

- Not "no `prompt_injection` finding". The fix downgrades the severity and keeps
  the category, because a prohibition wrapping a payload is attacker-controllable
  text and must stay visible. A category-absence check would pass only if the
  finding had been suppressed, which is the one outcome this class may not have.
  The finding also keeps its id: the class travels in `context`, not in the
  fingerprinted evidence.
- Not under `strict`. Under `strict` these files still report HIGH, by design.

The three remaining ECC false positives (a DuckDNS `curl` and a Mailtrap
endpoint, firing `exfiltration_instruction`) were deliberately absent while #52
was open. They are `ECC9`–`ECC10` below.

## Provenance and licence

All eight are from `affaan-m/ECC` (<https://github.com/affaan-m/ECC>), MIT
License, Copyright (c) 2026 Affaan Mustafa, taken verbatim at commit
`e04ea0b9cc8248686edf5ac751cadff550e162b8`:

| Fixture | Path in ECC |
|---|---|
| `ECC1` | `skills/deep-research/SKILL.md` |
| `ECC2` | `skills/github-ops/SKILL.md` |
| `ECC3` | `skills/jira-integration/SKILL.md` |
| `ECC4` | `skills/lead-intelligence/SKILL.md` |
| `ECC5` | `skills/tdd-workflow/SKILL.md` |
| `ECC6` | `skills/x-api/SKILL.md` |
| `ECC7` | `skills/llm-trading-agent-security/SKILL.md` |
| `ECC8` | `docs/zh-CN/skills/llm-trading-agent-security/SKILL.md` |

`ECC5` earns its place twice over: its prohibition sits past the 200-character
evidence cap, so a check reading the evidence string rather than the full line
misses it.

# Two more real files from ECC, verbatim — the documented-outbound-call class

`ECC9`–`ECC10` are the `exfiltration_instruction` false positives of issue #52:
an ordinary outbound API call, quoted in a documentation code fence, reported as
the highest severity the scanner emits. On 1.5.5 the two produced one MEDIUM
`fenced_directive` each under `balanced` and one CRITICAL
`exfiltration_instruction` each under `strict`.

They assert **no findings at all, under both policies**, and both halves of that
differ from the `ECC1`–`ECC8` group above on purpose:

- Nothing at all, not "nothing above info". The #51 class downgrades because a
  prohibition wrapping a payload is attacker-controllable and a reviewer has to
  see it. Nothing here quotes an attack or addresses an agent. There is nothing
  to adjudicate, so a finding kept at info would be noise rather than evidence.
- Both policies, not `balanced` only. `strict` is the half that bites: under
  `balanced` the fence downgrade renames both to `fenced_directive`/medium, so a
  balanced-only assertion would pass while the rule still called a documented
  API call CRITICAL — which is exactly what #52 reports.

| Fixture | Path in ECC | Line | What fired |
|---|---|---|---|
| `ECC9` | `skills/homelab-wireguard-vpn/SKILL.md` | 233 | a DuckDNS updater presenting DuckDNS's own `${DUCKDNS_TOKEN}` |
| `ECC10` | `skills/mailtrap-email-integration/SKILL.md` | 56 | a Mailtrap endpoint built from `process.env.MAILTRAP_INBOX_ID` |

Both are from `affaan-m/ECC` (<https://github.com/affaan-m/ECC>), MIT License,
Copyright (c) 2026 Affaan Mustafa, taken verbatim at the same commit
`e04ea0b9cc8248686edf5ac751cadff550e162b8` as `ECC1`–`ECC8`.

`ECC10` earns its place beyond the count: what fired there was `.env`, matched
inside `process.env`. The property access and the dotfile spell the same four
characters, and the value it made a credential was an inbox number.
