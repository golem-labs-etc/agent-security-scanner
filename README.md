# Glance Scanner

Reads code and tells you what is already wrong in it. Built for the files an AI
agent runs on: skills, MCP server definitions, hooks, and the repositories an
agent has been pointed at.

Part of [Glance](https://glance-scanner.vercel.app). This package is the half
that reads code at rest. The half that watches a running agent, Glance guard,
is in early access and is not in this package.

MIT licensed. Runs locally. Nothing is uploaded unless you turn on AI analysis,
and then only to the provider whose key you supply.

## Try it in one line

```bash
npx glance-scanner analyze --repo https://github.com/Panniantong/Agent-Reach
```

That clones a public repository to a temporary directory, scans it, prints a
report and deletes the clone. No key, no install, no configuration.

To scan something of your own:

```bash
npx glance-scanner analyze --path .        # a directory, recursively
npx glance-scanner analyze --file app.js   # one file
```

## What you get without a key

Two real static engines, no API key, no account:

| Engine | Finds | Needs |
| --- | --- | --- |
| [semgrep](https://semgrep.dev) `p/default` | 1074 rules: injection, traversal, XSS, deserialisation, leaked credentials | one install, see below |
| `rules/` in this repo | SQL injection built by string concatenation in JavaScript, which `p/default` misses | nothing, it ships here |
| `npm audit` | dependencies with published advisories | a `package.json` and a lockfile |

Every line number comes from the engine that found it. Nothing here recomputes
or guesses one. **A finding that has no line number is printed without one** —
an `npm audit` advisory is about a dependency, not a place in your code, so it
gets no line rather than a made-up one.

The scan names both engines every time it runs, and says why either one did not:

```
Static analysis (no API key). Add --ai for semantic analysis.
  semgrep (p/default + glance rules): 23 findings in 19.4s
  npm audit: 144 findings in 2.1s
```

If neither is available it says so and returns nothing. It never falls back to
invented output.

**A partial scan is never printed as a clean one.** semgrep applies its own
ignore list, and pointed at a directory it can decline to open a single file
while still exiting 0 with "Findings: 0". So the number of files semgrep says
it scanned is checked against the number it was given, and any shortfall is
printed as a warning naming the paths — on stderr as well as in the report, and
in `--json` under `engines`. If it scanned nothing at all, the engine is
reported as not having run:

```
  semgrep: did not run — scanned 0 of 1 path(s) — semgrep skipped everything it
  was given. This is NOT a clean result.
```

### Installing semgrep

```bash
npx glance-scanner install-tools --semgrep     # or: pipx install semgrep
```

The first semgrep run downloads its rules to `~/.semgrep`. After that it runs
with no network at all. The CLI tells you when that download is about to happen.
`--metrics=off` is passed on every invocation, always.

If `pip` refuses with `externally-managed-environment`, that is
[PEP 668](https://peps.python.org/pep-0668/): your Python is managed by
Homebrew or your distribution and pip will not write into it. `--user` fails the
same way, so re-running pip is not the fix. `install-tools` detects this,
retries through pipx — which puts semgrep in its own virtualenv, which PEP 668
allows — and if pipx is missing or fails it names the interpreter to install
rather than repeating the command that just failed.

### Known gaps, so you are not surprised by them

Measured, not assumed:

- **SQL injection built with a template literal is missed.**
  ``db.all(`SELECT * FROM orders WHERE id = ${req.params.id}`)`` produces no
  finding. The `+` form — `"SELECT * FROM users WHERE id = '" + id + "'"` —
  *is* caught, by `rules/js-sql-concat.yaml` in this repository, which
  `p/default` misses. That rule requires `+` on purpose: without the
  requirement it flagged a correctly parameterised query whose table name is
  interpolated and validated against an allowlist, because semgrep's open-source
  taint analysis cannot see a guard like `if (!ALLOWED.includes(t)) return`.
  Zero false positives was worth the template-literal case. `--ai` covers it.
- `npm audit` is skipped when a project has a `package.json` but no lockfile.
  A scanner should not write files into the tree you pointed it at, so run
  `npm install --package-lock-only` yourself if you want it covered. The one
  exception is `--repo`, where the tree is a shallow clone in `/tmp` that this
  process made and deletes: there the lockfile is generated for you, with
  `--ignore-scripts`, and the report says it happened.
- semgrep's own `.semgrepignore` excludes test directories and untracked files
  when it is given a directory. glance-scanner passes explicit file paths
  instead, so what you asked to scan is what gets scanned, and it checks
  semgrep's own count of scanned files afterwards.
- Neither engine reasons about intent. A parameterised query that merely looks
  like concatenation, or a test fixture that looks like a leaked key, will still
  be reported. `--ai --filter-fp` is the pass that drops those.

We have not measured a false-positive rate against a public benchmark, so this
README does not quote one.

## What you get with a key

Semantic analysis reads the code the way a reviewer would. It reasons about
intent rather than shape, so it covers the gaps above — including SQL built with
a template literal. It costs whatever your provider charges, which for a small
repository is cents.

`AI_API_KEY` is **your AI provider's key**, not a Glance account. There is no
Glance signup and nothing to pay us for. Get a key from
[Anthropic](https://console.anthropic.com),
[OpenAI](https://platform.openai.com/api-keys) or
[OpenRouter](https://openrouter.ai/keys), and note that an API key is billed
separately from any chat subscription you may already have.

```bash
export AI_API_KEY="your provider key"
export AI_PROVIDER="anthropic"     # anthropic, openai, or openrouter

npx glance-scanner analyze --path . --ai
```

`AI_PROVIDER` defaults to `anthropic`, so if you're using Anthropic you can
skip it. If you already have `ANTHROPIC_API_KEY` set, for instance from
Claude Code, the scanner picks it up automatically and you can skip
`AI_API_KEY` too.

Add `--filter-fp` and each finding gets a second pass that asks whether it is
real before it reaches your report. Parameterised queries flagged as SQL
injection, test fixtures flagged as leaked secrets, and the rest of the usual
noise get dropped with a stated reason:

```bash
npx glance-scanner analyze --path . --ai --filter-fp
```

We have not measured the false-positive rate against a public benchmark, so
this README does not quote one.

## The extra Python scanners

These are optional and separate from the default scan. Install them once and
glance-scanner will call them and merge their findings, deduplicated.

```bash
npx glance-scanner install-tools
```

| Tool | Finds | Applies to |
| --- | --- | --- |
| detect-secrets | API keys, tokens, credentials | every file type |
| bandit | command injection, unsafe file operations, hardcoded passwords | Python |
| pylint | undefined names, unused imports, errors | Python |
| pip-audit | dependencies with known vulnerabilities | requirements.txt, pyproject.toml |

Then add them to a scan:

```bash
npx glance-scanner analyze --path . --with-all-checks
```

Or one at a time with `--with-secrets`, `--with-bandit`, `--with-linting`,
`--with-dependencies`. These need Python on your machine. Nothing else here
does.

## Every flag

| Flag | What it does |
| --- | --- |
| `--file <path>` | scan one file |
| `--path <dir>` | scan a directory, recursively |
| `--repo <url>` | clone a repository to a temporary directory, scan it, delete it |
| `--ai` | semantic analysis, needs `AI_API_KEY` (or `ANTHROPIC_API_KEY`) |
| `--filter-fp` | second pass that drops findings it judges unreal, needs `--ai` |
| `--with-secrets` | add detect-secrets |
| `--with-bandit` | add bandit |
| `--with-linting` | add pylint |
| `--with-dependencies` | add pip-audit |
| `--with-all-checks` | add all four |
| `--semgrep` (on `install-tools`) | install semgrep only |
| `--json` | machine-readable report on stdout |
| `--verbose` | print the code around each finding |
| `--no-cache` | rescan even if the content has not changed |

`--semantic` is an alias for `--ai`. `--semantic-only` is a deprecated alias
for the same thing.

Caching applies to `--ai` only, where it is keyed by file content so scanning
the same code twice costs nothing. The cache is a JSON file in your home
directory and `--no-cache` skips it. The static engines are not cached: they
are local and fast, and a stale security result is worth less than the seconds
it saves.

## What it looks for

sql_injection, command_injection, path_traversal, hardcoded_secrets,
xxe_attack, xss, csrf, insecure_deserialization, weak_crypto, missing_auth,
hardcoded_config, unvalidated_redirect, information_disclosure,
insecure_random, unsafe_pickle, vulnerable_dependency.

semgrep rules that do not map onto one of these keep their own rule id as the
category rather than being forced into a bucket they do not fit. Coverage of
each depends on the mode you ran in. See the two sections above.

## Building from source

You do not need this to use the scanner. `npx` is enough.

```bash
git clone https://github.com/golem-labs-etc/agent-security-scanner.git
cd agent-security-scanner
npm install
npm run build
node dist/cli.js analyze --path .
npm test
```

## Reporting something

Bugs and false positives both go to
[the issue tracker](https://github.com/golem-labs-etc/agent-security-scanner/issues),
or to golem@forwardemail.net. If the scanner flagged your project and it was
wrong, we want the case, because that is the part that is hard to get right.

## License and scope

The scanner in this repository is MIT licensed. Use it, fork it, ship it,
sell it. That is deliberate: a tool that claims to run locally and upload
nothing is only worth believing if you can read it.

**Glance guard and Glance fixes are not covered by this licence.** They are
separate products and no part of them lives in this repository. Glance guard
is free for one developer on your own model key, which is a price, not a
licence. Nothing here grants a right to their source.

MIT. Golem Labs.
