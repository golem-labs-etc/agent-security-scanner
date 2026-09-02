import * as path from 'path';

/**
 * Rewrite finding paths so they name a file the reader can actually open.
 *
 * `--repo` clones to `/tmp/glance-repo-<timestamp>/`, scans, prints, and
 * deletes the clone. Every engine reports absolute paths inside that clone, so
 * the report told the reader to look at
 * `/tmp/glance-repo-1788292131946/src/heretic/plugin.py:139` — a path that no
 * longer exists by the time they finish reading, and never existed in their own
 * checkout.
 *
 * That is worse than untidy now that findings carry an action sentence. "Open
 * <path> and check whether this value can come from outside the program" is a
 * direct instruction, and it named a file that was already gone.
 *
 * Applied ONLY to `--repo`. For `--path` and `--file` the path the engine
 * reports is the path the user typed, relative to where they are standing, and
 * rewriting it would be the same mistake in the other direction.
 *
 * Anything outside the clone root is returned untouched rather than forced into
 * a relative form. `package.json` findings from npm audit are inside the root
 * and relativise normally; a path that somehow escaped it keeps its absolute
 * spelling, because a `../../..` chain would be less useful than the truth.
 */
export function toRepoRelative(file: unknown, root: string): string {
  const f = String(file ?? '');
  if (!f || !root) return f;

  const absRoot = path.resolve(root);
  const absFile = path.isAbsolute(f) ? path.resolve(f) : null;
  if (!absFile) return f;

  const rel = path.relative(absRoot, absFile);
  // Outside the root, or resolving to the root itself.
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return f;
  return rel;
}

/** Apply `toRepoRelative` to every finding's `file`, in place-safe fashion. */
export function relativiseFindings<T extends { file?: unknown }>(findings: T[], root: string): T[] {
  return findings.map((f) => (f && f.file ? { ...f, file: toRepoRelative(f.file, root) } : f));
}
