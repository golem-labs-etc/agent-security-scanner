# Working in this repository

**This repo is PUBLIC and MIT licensed.** Everything committed here is world
readable, permanently, including anything later deleted, because the history is
public too. Three separate leaks of private material have happened through this
repo. Read the boundary below before committing.

## The three-repo structure (settled 27 Aug 2026)

| Repo | Visibility | Holds |
|---|---|---|
| `agent-security-scanner` | **public**, MIT | the `glance-scanner` CLI, nothing else |
| `glance-guard` | **private**, UNLICENSED | Glance guard: detectors, judge, hook adapter |
| `glance-site` | **private** | marketing site, build system, `api/` endpoints |

They are separate repos on purpose. Until today all three lived in this one, with
two working copies pointing at the same remote, and that is what caused every
leak. Do not recombine them.

## What belongs here

`src/*.ts` scanner modules, `tests/` scanner suites, `README.md`, `LICENSE`,
`package.json`, `tsconfig.json`.

## What must NEVER be committed here

- **Guard source.** `src/guard/`, `dist/guard/`, `tests/guard/`, `guard/`.
  It belongs in `glance-guard`. If you find it in this working copy, it is a
  leftover, not the source of truth. `~/glance-guard` is.
- **Glance fixes source.** Same rule.
- **Internal documents.** `GLANCE-GUARD-SPEC.md`, `GUARDIAN-MVP.md`,
  `BRAND_SPEC.md`, `HANDOFF-TO-CLAUDE-CODE.md`, `golem-*.md`,
  `mvp-technical-architecture.md`, `glance-market-read.md`,
  `glance-blue-ocean.md`. The spec carries the full adversarial A-corpus, which
  doubles as the list of attack shapes to avoid. Guard source being private is a
  business decision; the corpus being private is a security one.
- **The site.** `public/`, `data/`, `api/`, `partials/`, `vercel.json`,
  `src/build.js`, `src/shell.js`, `src/provenance.js`, `src/home.*`,
  `src/pro.html`, `src/brand.css`, `src/scan-demo.svg`.
- **Diagnostic HTTP endpoints.** `api/debug-*.js` were live and unauthenticated
  in production; one accepted an arbitrary `?to=` and sent mail from the Golem
  inbox. Never ship a debug endpoint to a deployed site.
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

## Changing any of this

Ask Eitan. Do not settle it in a commit message.
