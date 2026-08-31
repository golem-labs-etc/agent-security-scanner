# Working in this repository

**This repo is PUBLIC and MIT licensed.** Everything committed here is world
readable, permanently, including anything later deleted, because the history is
public too. Private material has reached this repo before. Read the boundary
below before committing.

## The three-repo structure (settled 27 Aug 2026)

| Repo | Visibility | Holds |
|---|---|---|
| `agent-security-scanner` | **public**, MIT | the `glance-scanner` CLI and its platform adapters |
| `glance-guard` | **private**, UNLICENSED | Glance guard: detectors, judge, hook adapter |
| `glance-site` | **private** | marketing site, build system, `api/` endpoints |

They are separate repos on purpose, and the reasons are recorded in the private
`COORDINATION.md`. Do not recombine them.

## What belongs here

`src/*.ts` scanner modules, `tests/` scanner suites, `README.md`, `LICENSE`,
`package.json`, `tsconfig.json`.

### Scope amendment, 30 Aug 2026: `adapters/`

Approved by Eitan on 30 Aug 2026. Until then this table said the CLI and
nothing else, so this is a deliberate change and not a drift.

`adapters/<platform>/` holds the code that maps one host's layout onto the
scanner's inventory schema: where that host keeps its MCP configs and its
skill files, and how it surfaces a finding to its own agent. `adapters/hermes/`
is the first.

An adapter is in scope here because it holds **no detection logic**. It
discovers paths, shells out to `glance-scanner surfaces`, and formats the
result. Every rule, threshold and severity stays in `src/surfaces/`, which is
already public and MIT.

The boundary is unchanged and is what decides the question. **No adapter may
contain, import, or vendor guard material** — no detector, no judge, no
sanitizer, no corpus case, no fixture copied from one. Blocking is the guard's
job, the guard is not MIT, and it stays in `glance-guard`. An adapter that
needs to block has crossed the line and belongs in the other repo.

Adapter fixtures are written fresh. Reaching for an existing attack case to
test an adapter is how the corpus leaks.

## What must NEVER be committed here

- **Guard source.** `src/guard/`, `dist/guard/`, `tests/guard/`, `guard/`.
  It belongs in `glance-guard`. If you find it in this working copy, it is a
  leftover, not the source of truth. `~/glance-guard` is.
- **Glance fixes source.** Same rule.
- **Internal documents**, listed in the private `COORDINATION.md`. Specs,
  handoffs and strategy notes. One of them carries the guard's full adversarial
  corpus, which doubles as a list of attack shapes; guard source being private
  is a business decision, the corpus being private is a security one. The names
  are not repeated here because an enumerated list of private filenames is
  itself a map.
- **The site.** Marketing pages, its build system and its HTTP endpoints all
  live in `glance-site`. Its file layout is recorded there and in the private
  `COORDINATION.md`, not here.
- **Diagnostic HTTP endpoints.** Never ship one to a deployed site, in any
  repo. The incident that produced this rule is written up in the private
  `COORDINATION.md`.
- **Build output.** `dist/` is gitignored.

A `pre-push` hook blocks most of this. If it fires, the hook is right.

## The licence decision, and why

The scanner is MIT because "runs locally, uploads nothing" is unverifiable if
nobody can read the code. That openness is the credibility behind the claim.

The guard is **not** MIT. Free for one developer on their own model key is a
price, not a licence. If the guard ships MIT, a fork takes the actual product and
we keep the support burden. `LICENSE` here states the guard's source is not
published in this repo. Adding guard code makes that statement false.

## Before you rewrite history in this repo

Squash, orphan commit, rebase, force push: check first that nothing untracked is
about to be swept in, and afterwards that nothing was dropped.

```bash
git status --porcelain | grep '^??'          # would a squash sweep these in?
git ls-files | grep -iE 'guard|SPEC|golem-'  # must be empty after
```

Those grep patterns stay, for the same reason `.github/workflows/boundary.yml`
keeps its: a check that cannot name what it is looking for cannot run. Patterns
are accepted here; enumerated filenames are not.

## Changing any of this

Ask Eitan. Do not settle it in a commit message.

## Parallel sessions

More than one session has worked on this tree at once, and it has cost both
leaked material and lost work. Rules:

- **One session per working copy.** Need two? `git worktree add ../work -b topic`, or `tools/session.sh` in the scanner repo.
- **Never rewrite shared history**: no `--force`, `--orphan`, `reset --hard` or
  squash of pushed commits on `main`. That is Eitan's call, not a task step.
- **Commit before going idle.** Untracked work is what gets swept in or dropped.
- **Before any destructive op**, run `git status --porcelain | grep '^??'`. If it
  lists files you did not create, another session is live. Stop.
- **Never force past a rejected push.** Rejection means someone moved; merge.
- **Work on a branch, never commit to `main` directly.** Name it for your task:
  `guard/m4`, `site/pricing-copy`. Open a PR and merge. `main` is protected:
  force-push and deletion are refused by GitHub, and CI must pass.
- **Rollback is a revert, not a rewrite.** `git revert <merge-sha>` undoes a bad
  merge without touching anyone else's history. Never reach for `reset --hard`
  or `--force` on a shared branch.
- **Claim the tree**: append a line to `.WORKING` (gitignored) when you start,
  read it before destroying anything, clear it when done. This is advisory; git
  has no real file locking, so it only works if both sessions honour it.
- **If the tree is in a state you did not create**, say so and stop. Do not
  reconcile it silently.

Full reasoning: `COORDINATION.md`.
