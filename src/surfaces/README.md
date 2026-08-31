# Agent surfaces

```
glance-scanner surfaces --inventory <path.json> --json
glance-scanner surfaces --root <dir> --json
glance-scanner surfaces ... --evidence
glance-scanner surfaces ... --policy strict|balanced
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
`http://localhost.evil.invalid/` is not loopback and does fire.

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
| `prompt_injection` | high | instruction-override phrasing aimed at prior instructions, identity or mode |
| `hidden_instruction` | critical | text present to the parser and absent to the reader |
| `exfiltration_instruction` | critical | a verb, a named credential store and an off-machine destination inside one 240-character window |
| `credential_leak` | critical | a literal secret value in the file, by vendor shape |
| `fenced_directive` | medium | a directive quoted inside a code fence: unproven, not benign |
| `obfuscated_text` | high | zero-width or bidi controls, or a Cyrillic letter inside a Latin word |

### What each prompt rule refuses to fire on

Every line below is a narrowing made after a scan of a stock agent install
returned 1508 critical and 77 high findings across 2110 files, none of which
was an attack. The numbers matter more than the reasoning: a rule that is
right in principle and wrong 1508 times in a row is a rule nobody reads.

**`prompt_injection` reads override phrasing only.** "Ignore all previous
instructions", "you are now", "enter developer mode". It does *not* fire on
"don't tell the user to run `/skin`" or "never tell a user to put a
non-credential setting in `.env`". Concealment is not override, and on visible
prose it is how skills are written -- 54 of 65 findings were that one shape,
including "Do NOT explain how @mention works to the user", which matched
because `@mention` contains `mention`. The concealment phrases still fire
where the text carrying them is *itself* hidden: inside an HTML comment, or
revealed by undoing a homoglyph. Hidden text saying keep this from the user is
the attack; the same sentence written plainly is documentation.

**`exfiltration_instruction` needs a named credential store, not a noun.**
`.ssh`, `.aws`, `.npmrc`, `.netrc`, `.gnupg`, `.kube`, `.pgpass`, `.pypirc`,
`.git-credentials`, `.env`, an SSH private key filename, `/etc/passwd`. The
words *secret*, *credential*, *api key*, *password*, *token* and *cookie* are
not sources: they are what a skill documenting an HTTP call says in its own
prose. Nor is every hidden directory a credential store -- `~/.local/bin` and
`~/.hermes/cache` are not, and treating them as such made three ordinary
installers critical.

**A credential variable used to authenticate is not a source.** A `$VAR` whose
name ends in KEY, TOKEN, SECRET, PASSWORD or CREDENTIAL counts as a source
only when it is *not* inside the destination URL, *not* after a header whose
name contains key/token/auth/secret/credential, *not* the argument to
`curl -u`, and *not* the right-hand side of an uppercase shell assignment.
Those four positions are what a documented API call looks like, and one of
them alone was 25 of 30 criticals on a stock install. The cost is stated
rather than discovered: a stolen token sent to an attacker's endpoint in an
auth header looks identical to a legitimate one and is missed.

**Loopback is not a destination.** `http://localhost:8644/health` crosses no
network. `unencrypted_transport` already knew that; this rule now agrees.

**The window is 240 characters and the reported span is exact.** It used to be
"one sentence", and a paragraph-joining step had quietly made a sentence as
long as a paragraph -- twenty lines of YAML frontmatter reported as one
critical finding at line 1. Lines join only where prose actually wraps, never
across a list item, heading, table row, block quote or YAML key, and inside a
fence only across a trailing backslash. `end_line` is set whenever a finding
covers more than one line.

**`obfuscated_text` is Cyrillic, not Greek.** A Cyrillic letter inside a Latin
word has no innocent explanation. A Greek one does: every Greek hit on a real
machine was a finance document writing `ΔAR` or `ΔCommon Stock`. Greek
stays in the homoglyph fold used by `hidden_instruction`, which additionally
requires a directive phrase to appear once the folding is undone.

### One problem, every address it has

A prompt finding's id is a fingerprint over its category, line, normalised
evidence and the SHA-256 of the file's contents -- not over its path. A skill
file that exists in twenty-two profiles is one file twenty-two times, and it is
reported once, with `occurrences: 22` and the other twenty-one paths in
`also_in`. Keying on content rather than path also means the id survives a
profile being added or removed, which a path-derived id did not.

MCP and code findings keep the path in the fingerprint. There is no file
content to key them on.

### `credential_leak` uses vendor shapes only, and `secret_in_config` does not

The two secret rules are deliberately not symmetric.

`secret_in_config` judges an MCP env **value**, so it can afford a generic
high-entropy fallback: the value is already known to be a configured credential
slot, and the only question is whether it holds a literal or a reference.

`credential_leak` scans free **prose**, where a long high-entropy token is far
more often a checksum, a UUID, a commit sha or a base64 blob than a key. It
therefore matches the vendor prefixes only: `sk-`, `sk-ant-`, `ghp_`, `AKIA`,
`AIza`, `xox`, `glpat-`, `npm_`, `hf_`, a JWT, a PEM private key header. A
39-character high-entropy string in a paragraph does not fire.

The cost is a real miss: a bearer token from a vendor with no recognisable
prefix, pasted into a skill file, is not detected. That is a known limit, not
an oversight, and `N13` in the suite pins it so it stays a decision rather than
becoming an accident. Raise it only with a fixture that shows what the noise
looks like.

### Fenced code, and the policy that governs it

Fenced and inline code is blanked before the instruction rules run. Offsets and
newlines are preserved, so every reported line number still points at the real
line. This is what lets a security skill quote `ignore all previous
instructions` as an example without tripping the scanner that reads it.

A directive found inside a fence is not dropped. It is reported under the
policy:

| Signal found inside a fence | `balanced` (default) | `strict` |
|---|---|---|
| `prompt_injection` | `fenced_directive`, medium | `prompt_injection`, high |
| `exfiltration_instruction` | `fenced_directive`, medium | `exfiltration_instruction`, critical |
| `hidden_instruction` by concealed characters | `hidden_instruction`, critical | `hidden_instruction`, critical |
| `hidden_instruction` by HTML comment or CSS | `fenced_directive`, medium | `hidden_instruction`, critical |
| `obfuscated_text` | `obfuscated_text`, high | `obfuscated_text`, high |

Medium, not info. Info is where `unpinned_remote_exec` lives, and that is
genuinely benign. A directive in a fence is not benign, it is unproven, and the
severity should say so.

**Why one `hidden_instruction` row follows the fence and the other does not.**
The category covers two kinds of concealment, and a fence defeats only one of
them. An HTML comment or a `display:none` span hides by *rendering*: quote it
in a fence and the reader sees it plainly, so it follows the policy. A
homoglyph or a zero-width split is invisible in a fence and out of one, so it
never downgrades.

That split is what makes the two rules consistent rather than arbitrary:
**fence-immunity applies to concealment a fence does not defeat.** It is also
load-bearing. Without it, a page documenting hidden instructions cannot show a
hidden-comment example, which is the single most likely thing such a page
contains, and the "reads its own documentation" property fails.

**Precedence: concealed characters are evaluated independently of the fence
policy, and they win.** A homoglyph or zero-width split inside an HTML comment
inside a fence resolves to `hidden_instruction` critical under every policy,
never to `fenced_directive` medium. The fence made the *comment* visible; it did
nothing to the homoglyph, so that concealment survives and the downgrade path
cannot swallow it. Each finding is judged on its own span, so a plainly visible
directive elsewhere in the same comment still downgrades on its own merits.

An agent consuming raw markdown never sees a fence, which is why Part B passes
`strict`.

**Known and accepted:** a plain fenced HTML comment remains a bypass under
`balanced`. It is the same bypass plain fenced text already has, so the split
widens nothing, and under `strict` it is critical anyway.

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
Both conceal by rendering, so both follow the fence policy above. The reveal
test does not.

### `obfuscated_text` is the signal that needs no phrase list

`hidden_instruction` reads the payload, so its recall is bounded by the
directive patterns. `obfuscated_text` makes the other claim — *text is hidden*
— and depends on no phrase list at all. They are separate categories on
purpose: the false-positive data then says which signal is noisy instead of
averaging the two.

Three signals, all fence-immune, all `high`:

1. **A zero-width character between two ASCII letters** (U+200B, U+200C,
   U+200D, U+FEFF). The framing is load-bearing. ZWNJ is a real letter-joining
   control in Persian and Hindi, but it sits between Arabic and Devanagari
   letters. ZWJ builds emoji sequences and sits between emoji. A byte-order
   mark sits at offset 0, where it has no preceding letter. **U+00AD soft
   hyphen is excluded outright**, because it legitimately appears inside words
   in text pasted from Word; it stays in the reveal test, where it is harmless.
2. **A Cyrillic or Greek character inside an otherwise Latin word** of three or
   more characters, where the Latin letters outnumber the foreign ones. A whole
   Russian sentence has words that are entirely Cyrillic, so nothing fires.
   `Ignоre` fires.
3. **Bidirectional controls** U+202A–U+202E and U+2066–U+2069, anywhere in a
   prompt file. This is Trojan Source, CVE-2021-42574: the characters reorder
   what is displayed without changing what the parser reads. Published, named,
   and with no benign use in a prompt file.

Evidence names the signal and counts characters. It never reproduces the
concealed text, so even `--evidence` cannot deliver a payload into a context.

## Policy, and where it may come from

`--policy balanced|strict`. The CLI defaults to `balanced`; Part B passes
`strict`.

**There is no `off` level, and asking for one is an error rather than a silent
fallback.** A level that silences a category is the first thing a person
reaches for when a tool is noisy, and from then on they are blind to every
future instance of it. Suppression already exists at the right granularity: the
baseline, per finding id, one finding at a time.

**Config is never read from the tree being scanned.** A `.glance.json` inside a
scanned repository or skill directory is an attack, not a convenience: ship a
repository that turns detection off on itself and the scan reports clean. Policy
comes from `--policy` or from the user's own config location
(`$XDG_CONFIG_HOME/glance/config.json`, else `~/.glance/config.json`). A config
file found inside the scan target is ignored and named in a warning.

## Output

```json
{
  "schema": 1,
  "engine_version": "1.3.0",
  "scanned_at": "2026-08-30T00:00:00Z",
  "policy": "balanced",
  "evidence": false,
  "warnings": [],
  "total_scanned": 217,
  "counts": {"critical": 0, "high": 0, "medium": 0, "info": 4},
  "findings": [
    {"id": "a3f1c209", "category": "prompt_injection", "severity": "high",
     "surface": "prompt", "path": "skills/x/SKILL.md", "line": 12},
    {"id": "9c2e0011", "category": "exfiltration_instruction", "severity": "critical",
     "surface": "prompt", "path": "profiles/a/skills/y/SKILL.md", "line": 40,
     "end_line": 41, "occurrences": 22,
     "also_in": ["profiles/b/skills/y/SKILL.md", "..."]}
  ]
}
```

Every result carries `policy` and `evidence`. A report that cannot be
interpreted without knowing which policy produced it is not auditable, and a
forgotten or tampered setting should be visible rather than silent.

**Findings carry no matched text by default.** An `evidence` string is attached
only when `--evidence` is passed. That default lives in the engine rather than
in the caller because the caller is sometimes an LLM prompt, and a scanner that
quotes an injection payload into an agent's context has delivered the payload.

`id` is a stable fingerprint over category, line and *normalized* evidence,
plus either the file's SHA-256 (prompt findings) or its path (MCP and code
findings). Normalized, because a whitespace or case edit should not mint a new
id, and because an attacker should not be able to defeat a baseline by
re-hiding the same directive a different way.

`end_line` is present when a finding covers more than one line. `occurrences`
and `also_in` are present when the same finding was reached at more than one
path -- see *One problem, every address it has* above.

An MCP or code finding's `id` includes an absolute path, which makes it
machine-specific. A prompt finding's does not, so it is stable across machines
and across which copies of a file happen to exist.

The process exits `1` when anything critical or high was found, `0` otherwise,
`2` on a usage or read error.

## Tests

`node tests/surfaces.js`, wired into `npm test`. Fixtures are in
`tests/fixtures/surfaces/` and were written for this suite. The suite asserts
the positives, the negatives, and -- by substring search over the report rather
than by reading it -- that no fixture content reaches default output.

**Invented attacker destinations end in `.invalid`.** That is the whole of the
rule, and its scope is narrow on purpose: it covers hosts that stand in for a
place an attack would send data. It is not a rule about every hostname in the
repo.

RFC 2606 reserves `.invalid`, `.test`, `.example`, `.localhost` and the
second-level names `example.com`, `example.net` and `example.org`. A name is
reserved or it is registrable and there is nothing in between, so a host that
merely *looks* fake -- `attacker.com`, or anything beginning `example-` --- is an
ordinary domain somebody can buy. In a public repo that hands a squatter a
target they can find by reading the source, and it points every copy-paste of a
payload at a host under someone else's control. `.invalid` can never resolve, by
standard.

**Real hosts stay real.** Naming `api.github.com` in a comment about excluding
auth headers is accurate and is clearer than a placeholder, because the rule it
describes is one that real GitHub calls trip. Replacing it would make the
comment vaguer and no safer: nothing here is a destination for anything. The
same goes for `registry.npmjs.org`, `api.openai.com` and every other service the
scanner genuinely talks about.

**Verbatim third-party content stays verbatim.** `tests/fixtures/surfaces/real/`
reproduces stock skill files exactly as they ship, so the real hosts inside them
are left alone. Editing them would make them no longer the files under test,
which is the entire reason they are here.

Two additions are worth knowing about, because the suite was 61 for 61 green
while the scanner produced 1508 critical findings on an ordinary install.

**`tests/fixtures/surfaces/real/` holds three stock skill files, verbatim,**
asserted at zero critical and zero high under *both* policies. Every other
negative here is short, hand-written, and has its payload on one line. None of
them is long enough, structured enough or fenced enough to reach the rules that
were wrong. Provenance and licence are in that directory's README.

**`FENCE` is a structural check rather than a fixture.** When the fence
terminator regressed -- a `$` under the `m` flag, so a fence masked its opening
line and one line of body and no more -- no fixture failed, because the other
narrowings kept the real files clean either way. The check asserts the extent
directly, on inert content.

### The fenced-exfiltration pair

`P20_fenced_multiline_exfil.md` and `N14_documented_api_call.md` are the same
shape with one ingredient different, and they are only worth anything as a
pair. Both are fenced, multi-line, backslash-continued `curl` calls to hosts
this scanner has never seen. P20 uploads a credentials file; N14 does not send
anything sensitive at all.

P20 asserts under **both** policies, because the difference is the assertion:
balanced downgrades it to `fenced_directive`/medium, strict reports it as
`exfiltration_instruction`/critical. Its source is on line 20 and its
destination on line 21, so it exercises the fence range, the continuation join
and the sensitive-source requirement together -- the three things that were
each wrong in a different way on the first real scan.

Measured teeth, by reverting one fix at a time in `dist/` and rerunning:

| reverted | what fails |
|---|---|
| fence terminator | P20a reports critical under balanced, and FENCE |
| sensitive-source requirement | N14, N14s, R1s, R2s, R3s |

Both halves of N14 bite, but only after the assertions were tightened, and the
way the first two attempts failed is worth keeping.

`no critical, no high` does not work under balanced: with the rule broken, the
fence downgrade turns both calls into mediums and the count assertion stays
true. `no exfiltration_instruction` is the obvious repair and is also wrong,
because the downgrade **renames** the category, so a broken rule surfaces as
`fenced_directive`/medium and a check on the exfiltration category never sees
it. The balanced half therefore asserts **no findings at all**, which is the
correct expectation for a clean documentation file and the only assertion here
that fails when the rule does.

### Known gap

No positive fixture for a credential variable posted as data rather than as
authentication. That boundary is currently held by the auth-exclusion logic and
by R2, which carries 25 real authenticated API calls, but not by a positive
that would fail if the exclusion were widened too far.
