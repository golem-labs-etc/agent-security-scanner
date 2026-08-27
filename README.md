# Glance site

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

Pattern detection runs by default. It is free, offline and fast, and it is
genuinely limited: it matches shapes in code, so it finds the mistakes that
look like themselves and misses the ones that do not.

Known gaps in pattern detection, so you are not surprised by them:

- Command injection through shell exec is not detected.
- Cross-site scripting is caught in EJS templates only. Assignments to
  `innerHTML` are missed.
- Path traversal in Python via `os.path.join` with user input is not covered.

The CLI prints a line telling you which mode it ran in. Believe that line.

## What you get with a key

Semantic analysis reads the code the way a reviewer would, so it catches the
three gaps above and reasons about intent rather than shape. It costs whatever
your provider charges, which for a small repository is cents.

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

## The four open-source scanners

These are separate tools, not bundled. Install them once and glance-scanner
will call them and merge their findings with its own, deduplicated.

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
| `--json` | machine-readable report on stdout |
| `--verbose` | print the code around each finding |
| `--no-cache` | rescan even if the content has not changed |

`--semantic` is an alias for `--ai`. `--semantic-only` is a deprecated alias
for the same thing.

Results are cached by file content, so scanning the same code twice is close to
free. The cache is a JSON file in your home directory and `--no-cache` skips it.

## What it looks for

sql_injection, command_injection, path_traversal, hardcoded_secrets,
xxe_attack, xss, csrf, insecure_deserialization, weak_crypto, missing_auth,
hardcoded_config, unvalidated_redirect, information_disclosure,
insecure_random, unsafe_pickle.

Coverage of each depends on the mode you ran in. See the two sections above.

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
