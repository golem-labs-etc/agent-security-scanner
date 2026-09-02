#!/usr/bin/env node
/**
 * Repo-relative paths for `--repo` scans.
 *
 * The clone lives in /tmp and is deleted before the reader acts on the report,
 * so an absolute clone path names a file that does not exist for them and never
 * did. With action sentences on findings this became a direct instruction to
 * open a deleted file.
 *
 * The fixture paths below are the real ones from a `--repo p-e-w/heretic` run,
 * copied verbatim rather than invented, so this asserts the shape the tool
 * actually produces.
 */

const path = require('path');
const { toRepoRelative, relativiseFindings } = require(path.join(__dirname, '..', 'dist', 'finding-paths'));

let failures = 0;
function ok(label, pass, detail) {
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}`);
  if (!pass) { failures++; if (detail) console.log(`        ${detail}`); }
}

console.log('\nRepo-relative finding paths\n');

// Verbatim from the run recorded in the verdict-line PR.
const ROOT = '/tmp/glance-repo-1788292131946';
const HERETIC = [
  { file: `${ROOT}/src/heretic/reproduce.py`, line: 123 },
  { file: `${ROOT}/src/heretic/plugin.py`, line: 139 },
];

ok('P1  heretic source path becomes repo-relative',
  toRepoRelative(HERETIC[1].file, ROOT) === 'src/heretic/plugin.py',
  toRepoRelative(HERETIC[1].file, ROOT));

ok('P1b every heretic finding relativises',
  relativiseFindings(HERETIC, ROOT).every((f) => !f.file.startsWith('/tmp/')),
  JSON.stringify(relativiseFindings(HERETIC, ROOT).map((f) => f.file)));

ok('P1c the line number is untouched',
  relativiseFindings(HERETIC, ROOT)[0].line === 123);

ok('P2  a package.json at the clone root relativises',
  toRepoRelative(`${ROOT}/package.json`, ROOT) === 'package.json',
  toRepoRelative(`${ROOT}/package.json`, ROOT));

// A path outside the clone keeps its absolute spelling. A `../../..` chain
// would be less useful than the truth.
ok('P3  a path outside the clone is left alone',
  toRepoRelative('/etc/hosts', ROOT) === '/etc/hosts',
  toRepoRelative('/etc/hosts', ROOT));

ok('P3b the root itself is left alone',
  toRepoRelative(ROOT, ROOT) === ROOT,
  toRepoRelative(ROOT, ROOT));

// Already-relative paths are what `--path` produces, and must not be touched.
ok('P4  an already-relative path is unchanged',
  toRepoRelative('src/users.js', ROOT) === 'src/users.js');

ok('P5  missing input does not throw',
  toRepoRelative(undefined, ROOT) === '' && toRepoRelative('/a/b', '') === '/a/b');

ok('P5b a finding with no file is passed through',
  relativiseFindings([{ severity: 'HIGH' }], ROOT).length === 1);

console.log(`\n  finding-paths: ${failures} failure(s)\n`);
process.exit(failures > 0 ? 1 : 0);
