#!/usr/bin/env bash
# Give a session its own working copy of a repo, so two sessions never share one.
#   bash tools/session.sh guard m4-hardening
#   bash tools/session.sh site pricing-copy
set -euo pipefail
case "${1:-}" in
  scanner) BASE="$HOME/agent-security-scanner" ;;
  guard)   BASE="$HOME/glance-guard" ;;
  site)    BASE="$HOME/glance-site" ;;
  *) echo "usage: session.sh <scanner|guard|site> <topic>"; exit 1 ;;
esac
TOPIC="${2:?need a topic, e.g. m4-hardening}"
DIR="$BASE-$TOPIC"

cd "$BASE"
find .git -name '*.lock' -delete 2>/dev/null || true
if [ -n "$(git status --porcelain | grep -v '^??' || true)" ]; then
  echo "STOP: $BASE has uncommitted changes. Commit them first, or another"
  echo "session is mid-task. Do not branch off a dirty tree."
  git status --short; exit 1
fi
git worktree add -b "$TOPIC" "$DIR" 2>/dev/null || git worktree add "$DIR" "$TOPIC"
echo ""
echo "Working copy ready:  $DIR   (branch: $TOPIC)"
echo "Point the session at that path, not at $BASE."
echo ""
echo "When finished:"
echo "  cd $DIR && git push -u origin $TOPIC"
echo "  then open a PR, let CI run, and merge."
echo "  cd $BASE && git worktree remove $DIR"
