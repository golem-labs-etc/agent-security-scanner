# Changelog

Notable changes to `glance-scanner`. Newest first.

This file starts at 1.3.0. Earlier releases predate it; their history is in the
git log.

## Unreleased

### Changed

- **Findings at the same file and line collapse into one.** Two semgrep rules
  firing on one `res.send('<h1>' + req.query.q + '</h1>')` were two
  descriptions of a single problem and were counted twice. Totals drop as a
  result: the fixture corpus goes from 12 to 10, and a sample project from 6 to
  5. Nothing is lost. Every contributing rule is listed on the finding under
  `Rules:`, and when the collapsed rules disagree about what the problem is,
  the extra taxonomy ids are printed beside the category as `(also: ...)`.
  Dependency advisories, which have no line, still key on their message, so
  two advisories against the same `package.json` stay two findings.
- **`npm audit` findings quote the matched advisory's own affected range.**
  They previously quoted `v.range`, npm's aggregate across every advisory for
  that package. On lodash 4.17.11 that printed `<=4.17.23` beside
  GHSA-35jh-r3h4-6jhm, whose actual range is `<4.17.21`, which overstated the
  named issue by two patch versions. Where a package is affected only
  transitively and no advisory object is available, the aggregate is still
  shown, labelled `package affected overall:` so the two cannot be confused.
  The count of further advisories for the same package is appended.

### Fixed

- **Local rule ids no longer carry the install path.** semgrep names a rule
  loaded from `--config=<dir>` after that directory, so our own rule was
  reported as `Users.<name>.agent-security-scanner.rules.glance-js-sql-injection`,
  and from npm would have carried the user's `node_modules` path. It now reads
  `glance-js-sql-injection`. Only ids matching our own `glance-` prefix are
  rewritten; registry rules keep the name semgrep gave them.

## 1.3.0

The default no-API-key scan now runs real static analysis engines. **What a
scan returns has changed**, and in places the finding count goes down. That is
the point of the release: the old numbers were partly fabricated.

### Removed

- **`MockAnalyzer` is deleted.** It matched substrings and returned canned
  findings with hardcoded line numbers: `sql_injection` always claimed line 7,
  `command_injection` always line 5. Being an if/else chain, it reported at
  most one problem per file. Those invented numbers were fed into `--verbose`
  code context, so the tool printed the wrong lines of your own file with
  complete confidence. Measured on this repository's own fixtures, 4 of 9
  findings pointed at comment lines and one labelled a hardcoded secret as
  command injection.

### Added

- **semgrep `p/default`**, 1074 rules, invoked as
  `semgrep --config=p/default --metrics=off --json --quiet`. Line numbers come
  from semgrep and are never recomputed.
- **`npm audit`** for dependency advisories. These findings carry **no line
  number**, because an advisory is about a dependency rather than a place in
  your code, and a made-up `package.json:1` would be the same lie the mock told.
- **`rules/js-sql-concat.yaml`**, shipped with the package. semgrep's
  `p/default` misses SQL injection built by string concatenation in
  JavaScript. So do `p/javascript` and `p/sql-injection`, both measured at zero
  findings on the case. The rule is taint mode, request data to the query
  argument of a database call, and it requires `+` concatenation deliberately.
  Measured at zero false positives on OWASP NodeGoat and on 972 library files.
- **A skipped-scan guard.** semgrep applies its own ignore list, and pointed at
  a directory it can decline to open a single file while still exiting 0 with
  "Findings: 0". The number of files semgrep reports scanning is now checked
  against the number it was given. A shortfall prints a warning naming the
  paths, on stderr and in the report. A scan where nothing was read is reported
  as an engine that did not run, never as a clean result.
- **`engines` in `--json` output**, so a machine consumer can tell a clean scan
  from a scan that never happened. `findings: []` alone could not.
- **Lockfile generation under `--repo` only.** When a cloned repository has a
  `package.json` and no lockfile, one is generated inside the temporary clone
  with `--ignore-scripts`, so `npm audit` has something to read. The report says
  when this happened. This never applies to `--path` or `--file`: a scanner
  should not write into a tree you pointed it at.
- **PEP 668 handling in `install-tools`.** When pip refuses with
  `externally-managed-environment`, the command no longer suggests the pip
  invocation that just failed. It skips the retry that fails identically, goes
  through pipx, and names the interpreter to install when pipx has nowhere left
  to go.

### Fixed

- **Deduplication key now includes the file path.** It previously did not, so
  findings in different files collided and were silently dropped. On this
  repository's fixtures the count went from 6 to 9 on identical inputs, purely
  from this fix. No finding count from a previous release is trustworthy.
- **`--json` is parseable.** Two causes: progress lines interleaved with the
  report, and a dotenv banner written to stdout at import.
- **semgrep is given explicit file paths** rather than a directory, because its
  built-in `.semgrepignore` excludes test directories and untracked files.

### Changed

- Two test fixtures were replaced. `snippet2_secrets.js` held
  `sk_live_REDACTED_FOR_DEMO`, which is not a credential shape, and
  `snippet4_xss.js` held its XSS inside a comment, with no template on disk.
  Neither could be found by any honest engine, so the suite was measuring the
  fixtures rather than the scanner.
- The test suite records an expectation and a reason per case, and fails only
  on regressions. It previously scored 5/5 by checking whether the mock
  recognised the fixtures the mock was written for.
- README title corrected. It said "Glance site", which is a different
  repository.

### Known gaps, measured rather than assumed

- SQL injection built with a template literal is missed. The `+` form is
  caught. Requiring `+` is what keeps a correctly parameterised query whose
  table name is validated against an allowlist from being flagged, since
  semgrep's open-source taint analysis cannot see that guard. `--ai` covers the
  template case.
- `npm audit` is skipped when a project has a `package.json` and no lockfile,
  outside `--repo`.
- Neither engine reasons about intent. `--ai --filter-fp` is the pass that
  drops shape-only matches.

No false-positive rate is quoted anywhere, because none has been measured
against a public benchmark.

### Packaging

- `rules/` is included in the published package.
- `prepublishOnly` runs the build and the test suite. `dist/` is gitignored, so
  without it a publish could ship a stale or empty build.
- A stale `README.md.bak-2026-08-26` was being swept into the tarball by npm,
  which force-includes any root file matching `README*` regardless of `files`
  or `.gitignore`. It described the deleted mock mode as current and contained
  an unmeasured competitor figure. Moved out of the package root.
