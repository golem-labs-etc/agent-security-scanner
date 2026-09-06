# Standing external regression corpus

Every real-repo candidate this scanner had been pointed at turned out to be a
known false positive, and there was no standing external target — so a precision
regression stayed invisible until somebody scanned something by hand. This pins
one real repository at one commit and diffs against a recorded finding set.

```bash
npm run corpus:external                 # clone the pin, diff `surfaces`
node tools/external-corpus.js --root <path>        # use an existing checkout
node tools/external-corpus.js --with-analyze       # also assert `analyze` criticals
```

Not part of `npm test`, which stays offline and fast. Run it before a release
and whenever prompt rules or secret rules change.

## The expected set is not "zero findings"

`ecc.expected.json` records twelve findings at `affaan-m/ECC`
@ `e04ea0b9`, each tagged with the class it belongs to:

| Class | n | What it means |
|---|---:|---|
| `true-positive` | 1 | `unpinned_remote_exec` on `.mcp.json` — a real finding, must keep firing |
| `negation-proximity` | 6 | quoted directives under a prohibition, must be present **at info** |
| `pattern-list` | 2 | a detector's own `INJECTION_PATTERNS`, must be present **at info** |
| `known-open:#52` | 3 | `exfiltration_instruction` on ordinary API calls — a real open bug, recorded so the job stays green while it is unfixed |

The eight quoted-directive entries are expected **present at info**, not absent.
That is the point of recording them this way: the class downgrades rather than
suppresses, because a prohibition wrapping a payload is attacker-controllable
text. A run that made those eight disappear is as wrong as one that put them
back at high, and the diff fails on both.

The three `known-open:#52` rows are the honest alternative to either pretending
they are fixed or letting the job go red forever. When #52 ships, their expected
severity changes and this file changes with it.

## Why `--with-analyze` exists

Sub-class 3 of #51 (synthetic placeholders in test files) lives on the `analyze`
path, so a `surfaces`-only diff cannot regress-test it — reverting that check
would leave the job green. The flag adds an assertion that `analyze` reports
**zero criticals** on the pin. Only the critical count is asserted: `analyze`'s
medium total moves by one or two between runs because of semgrep chunking, so a
full diff would be flaky for no gain.

## Controls

The job refuses to report success on a run that examined nothing, which is the
failure mode it exists to prevent:

- the checkout must be at the pinned commit, or it exits 2;
- the expected set must be non-empty, or it exits 2;
- the scan must return at least one finding, or it exits 2;
- `--with-analyze` exits 2 if semgrep cannot run, rather than passing.

Note that `surfaces` exits 1 whenever it finds anything above its threshold, so
the runner reads stdout regardless of exit status. The exit code is not the
signal here; the JSON is. (The exit-code contract itself is BL-6.)

## Verified both directions

Reverting any one of the three checks fails the job and names the class:

| Reverted | Result |
|---|---|
| negation proximity | `REGRESSED: negation-proximity` — 6 MISSING at info, 6 NEW at high |
| pattern-list containment | `REGRESSED: pattern-list` — 2 MISSING at info, 2 NEW at medium |
| synthetic test secrets | `REGRESSED: test-placeholder` — 3 criticals return |

## Provenance

`affaan-m/ECC`, MIT License, Copyright (c) 2026 Affaan Mustafa. Nothing from the
repository is vendored here; the eight files used as in-repo fixtures live in
`tests/fixtures/surfaces/real/` with their own provenance note.
