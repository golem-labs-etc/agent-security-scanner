#!/usr/bin/env bash
# Run Hermes' own plugin_guard against the mirror tree.
#
#   tools/plugin-guard.sh            gate:    the pinned commit, deterministic
#   tools/plugin-guard.sh --head     watcher: upstream HEAD, may change under us
#
# Prints a one-line verdict and exits non-zero on a dangerous one. The mirror
# tree is built exactly as .github/workflows/mirror.yml builds it -- same three
# excludes -- because a different copy would test a tree nobody ships.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF="pinned"
REV="$(grep -E '^HERMES_PIN=' "$ROOT/tools/plugin-guard-pin.txt" | cut -d= -f2)"
if [ "${1:-}" = "--head" ]; then REF="head"; REV="HEAD"; fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/hermes" && cd "$WORK/hermes"
git init -q
git remote add origin https://github.com/NousResearch/hermes-agent.git
git config core.sparseCheckout true
printf 'tools/\n' > .git/info/sparse-checkout
# --filter=blob:none keeps the fetch to the blobs the sparse checkout needs.
git fetch -q --depth 1 --filter=blob:none origin "$REV"
git checkout -q FETCH_HEAD
ACTUAL="$(git rev-parse HEAD)"

mkdir -p "$WORK/mirror"
rsync -a --exclude='__pycache__/' --exclude='*.pyc' --exclude='tests/' \
  "$ROOT/adapters/hermes/" "$WORK/mirror/"

python3 - "$WORK/hermes" "$WORK/mirror" "$ROOT/adapters/hermes" "$REF" "$ACTUAL" <<'PY'
import sys
from pathlib import Path
guard_dir, mirror, with_tests, ref, actual = sys.argv[1:6]
sys.path.insert(0, guard_dir)
from tools.plugin_guard import scan_plugin

def verdict(p):
    r = scan_plugin(Path(p), source="golem-labs-etc/glance-hermes")
    return getattr(r, "verdict", "?"), len(getattr(r, "findings", []) or [])

mv, mn = verdict(mirror)
tv, tn = verdict(with_tests)
print(f"plugin_guard ({ref} {actual[:12]}): mirror={mv} ({mn}) with-tests={tv} ({tn})")

problems = []
if mv == "dangerous":
    problems.append(
        "the MIRROR TREE is dangerous to plugin_guard. Every public install of\n"
        "  golem-labs-etc/glance-hermes is blocked, and --force does not override\n"
        "  a dangerous verdict. Something outside tests/ now reads as an attack."
    )
if tv != "dangerous":
    problems.append(
        "the tree WITH tests is no longer dangerous. That verdict is the stated\n"
        "  reason the mirror exists, in the README and in mirror.yml. If it has\n"
        "  changed, the reason is now wrong and must be rewritten."
    )
if problems:
    print("\nplugin_guard gate FAILED:")
    for p in problems:
        print("- " + p)
    sys.exit(1)
PY
