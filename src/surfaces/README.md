# Agent surfaces

```
glance-scanner surfaces --inventory <path.json> --json
glance-scanner surfaces --root <dir> --json
glance-scanner surfaces ... --evidence
```

An **agent surface** is a file an agent reads as instruction or configuration
rather than as code: an MCP server entry, a skill or prompt markdown file.
`npm audit` reads neither. semgrep reads neither. They are a distinct scan
target, and they are the same on every host, so they live in the shipped CLI
and every platform adapter gets them for free.

This engine has no knowledge of any host. A platform adapter produces an
inventory; this consumes it.

## Inventory schema

```json
{
  "schema": 1,
  "mcp_servers": [
    {"source": "profiles/trader/config.yaml", "name": "fs",
     "transport": "stdio", "command": "npx", "args": ["-y", "pkg"],
     "url": null, "env_keys": ["FOO"], "env_values_hashed": ["..."]}
  ],
  "prompt_files": [{"path": "skills/x/SKILL.md"}],
  "code_files": [{"path": "plugins/y/plugin.py"}]
}
```

`code_files` route to the existing static engine unchanged. `env_keys` are
names only and can never raise a finding — a name is not a secret. An adapter
that can distinguish an inline value from a reference may send `env` with the
literal values; one that cannot should omit it and accept the missed
detection.

## Rules: MCP server entries

| Category | Severity | Fires on |
|---|---|---|
| `unencrypted_transport` | high | a plain `http://` URL whose host is not loopback |
| `secret_in_config` | critical | an env value that is a literal secret rather than a reference |
| `command_injection_risk` | high | shell metacharacters that would actually be interpreted |
| `unpinned_remote_exec` | info | `npx -y`, `uvx`, `deno run`, `pip run` fetching an unpinned package |

Loopback means `localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0` and `*.local`,
matched against the parsed hostname and never against a substring of the URL —
`http://localhost.evil.com/` is not loopback and does fire.

`command_injection_risk` does not fire on a metacharacter sitting in an
argument, because arguments handed to `execve` are not shell-interpreted. It
fires when the command is itself a shell, when the metacharacter is in the
command, or when an argument carries a substitution some wrapper will expand.

**`unpinned_remote_exec` is `info`, and stays `info`.** `npx -y` is how very
nearly every MCP server in the ecosystem ships. Raising it turns the status
chip red on a clean machine, and a tool that is red on install is a tool people
learn to ignore.

## Rules: prompt files

These are prompt rules, not code rules. semgrep is never run on them.

| Category | Severity | Fires on |
|---|---|---|
| `prompt_injection` | high | instruction-override phrasing directed at the agent |
| `hidden_instruction` | critical | text present to the parser and absent to the reader |
| `exfiltration_instruction` | critical | instruction to send a local file or env value to a network destination |
| `credential_leak` | critical | a literal secret value in the file |

### Fenced code is documentation

Fenced and inline code is blanked before the instruction rules run. Offsets and
newlines are preserved, so every reported line number still points at the real
line.

This is what lets a security skill quote `ignore all previous instructions` as
an example without tripping the scanner that reads it. A scanner that cannot
read its own threat documentation without alarming is not shippable.

**Known limitation, stated plainly:** a payload placed inside a fence is not
reported. Fenced content renders verbatim to a human reader — in a markdown
viewer and in an editor — so by the definition above it is not hidden, and
treating it as documentation is a deliberate choice, not an oversight. An agent
reading raw markdown does still see it. If that trade turns out to be wrong in
dogfooding, the fix is a separate lower-severity category for fenced
directives, not a change to these four.

### `hidden_instruction` is a reveal test

NFKC does **not** fold Cyrillic and Greek homoglyphs. They are distinct
characters, not compatibility forms, so `'о'` (U+043E) survives
`.normalize('NFKC')` unchanged. Detection therefore needs an explicit
confusable mapping, and `src/surfaces/text.ts` carries one that is small enough
to audit by reading it.

Detection is a fair place for a confusables table. A security boundary is not:
folding is lossy, and two distinct inputs collapse to one.

The rule does not blacklist characters. It de-obfuscates — NFKC, then the
homoglyph map, then zero-width and bidi controls — and asks whether a directive
appeared that the raw bytes did not contain. Matching spans are mapped back to
raw offsets and re-tested, so:

- a homoglyph or zero-width split that reveals a directive fires `critical`
- a plain directive is `prompt_injection`, not `hidden_instruction`
- an emoji ZWJ sequence and a leading BOM fire nothing, because removing them
  reveals no directive

HTML comments carrying agent-directed imperatives, and HTML styled to be
unreadable (`display:none`, `visibility:hidden`, `opacity:0`, zero font size,
`color` equal to `background`), are the other two `hidden_instruction` shapes.
Both read prose, so a hidden-comment payload quoted in a fence is documentation
like any other.

## Output

```json
{
  "schema": 1,
  "engine_version": "1.3.0",
  "scanned_at": "2026-08-30T00:00:00Z",
  "total_scanned": 217,
  "counts": {"critical": 0, "high": 0, "medium": 0, "info": 4},
  "findings": [
    {"id": "a3f1c209", "category": "prompt_injection", "severity": "high",
     "surface": "prompt", "path": "skills/x/SKILL.md", "line": 12}
  ]
}
```

**Findings carry no matched text by default.** An `evidence` string is attached
only when `--evidence` is passed. That default lives in the engine rather than
in the caller because the caller is sometimes an LLM prompt, and a scanner that
quotes an injection payload into an agent's context has delivered the payload.

`id` is a stable fingerprint over category, path, line and *normalized*
evidence, so callers can dedupe and baseline across runs. Normalized, because a
whitespace or case edit should not mint a new id, and because an attacker
should not be able to defeat a baseline by re-hiding the same directive a
different way.

`id` includes the path, so an absolute path makes the fingerprint
machine-specific. A baseline is per-machine unless the adapter emits
host-relative paths.

The process exits `1` when anything critical or high was found, `0` otherwise,
`2` on a usage or read error.

## Tests

`node tests/surfaces.js`, wired into `npm test`. Fixtures are in
`tests/fixtures/surfaces/` and were written for this suite. The suite asserts
the seven positives, the five negatives, and — by substring search over the
report rather than by reading it — that no fixture content reaches default
output.
