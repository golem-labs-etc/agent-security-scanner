#!/usr/bin/env node
/**
 * Standing external regression corpus (BL-2).
 *
 * Every real-repo candidate this scanner has been pointed at so far turned out
 * to be a known false positive, and there was no standing external target — so
 * a precision regression stayed invisible until somebody scanned something by
 * hand. This pins one real repository at one commit, records the finding set it
 * is expected to produce, and diffs.
 *
 * The expected set is NOT "zero findings". It is:
 *   - the one true positive (`unpinned_remote_exec` on `.mcp.json`), and
 *   - eight quoted-directive entries that must be present AT INFO, and
 *   - three `exfiltration_instruction` mediums that are known-open against #52.
 *
 * That an entry is expected at `info` rather than expected absent is the whole
 * point: the quoted-directive class downgrades rather than suppresses, because
 * a prohibition wrapping a payload is attacker-controllable. A run that made
 * those eight disappear would be just as wrong as one that put them back at
 * high, and this diff fails on both.
 *
 * Usage:
 *   node tools/external-corpus.js                # clone the pin into .corpus-cache
 *   node tools/external-corpus.js --root <path>  # use an existing checkout
 *
 * Network is required only on first run. Not part of `npm test`, which stays
 * offline; run it before a release and when touching prompt or secret rules.
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SPEC = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/external/ecc.expected.json'), 'utf8'));

function arg(name) {
  const i = process.argv.indexOf(name);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

function ensureCheckout() {
  const given = arg('--root');
  if (given) return path.resolve(given);
  const cache = path.join(ROOT, '.corpus-cache', 'ecc');
  if (!fs.existsSync(path.join(cache, '.git'))) {
    fs.mkdirSync(path.dirname(cache), { recursive: true });
    console.log(`cloning ${SPEC.repo} …`);
    execFileSync('git', ['clone', '--quiet', SPEC.url, cache], { stdio: 'inherit' });
  }
  execFileSync('git', ['-C', cache, 'checkout', '--quiet', SPEC.commit]);
  return cache;
}

const root = ensureCheckout();

// CONTROL: the checkout must be at the pinned commit. A corpus job that silently
// scanned a moved HEAD would diff against the wrong baseline and "pass".
const head = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
if (head !== SPEC.commit) {
  console.error(`FAIL  checkout is at ${head}, expected the pin ${SPEC.commit}`);
  process.exit(2);
}
if (!SPEC.expected.length) {
  console.error('FAIL  expected set is empty — nothing would be compared');
  process.exit(2);
}

/**
 * Run the CLI and return stdout, whatever the exit status.
 *
 * `surfaces` exits 1 when it finds anything above its threshold, so a run that
 * worked perfectly still throws out of `execFileSync`. Treating that as a tool
 * error made this job crash with a stack trace on precisely the runs it exists
 * to report on. The exit code is not the signal here; the JSON is. (The
 * exit-code contract itself is BL-6.)
 */
function runCli(args) {
  try {
    return execFileSync(process.execPath, [path.join(ROOT, 'dist/cli.js'), ...args],
      { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  } catch (err) {
    if (err && typeof err.stdout === 'string' && err.stdout.trim()) return err.stdout;
    throw err;
  }
}

const report = JSON.parse(runCli(
  ['surfaces', '--root', root, '--evidence', '--json', '--policy', SPEC.policy]
));
const got = (report.findings || []).map((f) => ({
  path: String(f.path || f.file || '').slice(root.length + 1),
  line: f.line,
  category: f.category,
  severity: f.severity,
  id: f.id,
  context: f.context,
}));

// CONTROL: a clean diff produced by scanning nothing is the failure mode this
// whole file exists to prevent.
if (!got.length) {
  console.error('FAIL  the scan produced no findings at all — it examined nothing');
  process.exit(2);
}

const byId = (list) => { const m = {}; for (const e of list) m[e.id] = e; return m; };
const want = byId(SPEC.expected);
const have = byId(got);

const problems = [];
for (const e of SPEC.expected) {
  const g = have[e.id];
  if (!g) {
    problems.push({ cls: e.class, msg: `MISSING  [${e.id}] ${e.severity} ${e.category} ${e.path}:${e.line || ''}` });
  } else if (g.severity !== e.severity || g.category !== e.category) {
    problems.push({ cls: e.class, msg: `CHANGED  [${e.id}] expected ${e.severity} ${e.category}, got ${g.severity} ${g.category}  ${e.path}:${e.line || ''}` });
  } else if ((g.context || null) !== (e.context || null)) {
    // The id survives a downgrade by design, so severity alone cannot detect a
    // finding that stopped being classified. `context` is the check for that.
    problems.push({ cls: e.class, msg: `CONTEXT  [${e.id}] expected context ${e.context || 'none'}, got ${g.context || 'none'}  ${e.path}:${e.line || ''}` });
  }
}
for (const g of got) {
  if (!want[g.id]) {
    problems.push({ cls: 'new', msg: `NEW      [${g.id}] ${g.severity} ${g.category} ${g.path}:${g.line || ''}` });
  }
}

console.log(`\n${SPEC.repo} @ ${SPEC.commit.slice(0, 8)}  policy ${SPEC.policy}`);
console.log(`  expected ${SPEC.expected.length} findings, got ${got.length}\n`);

/**
 * The `analyze` half, opt-in with `--with-analyze`.
 *
 * Sub-class 3 (synthetic placeholders in test files) lives on the `analyze`
 * path, so a surfaces-only diff cannot regress-test it and BL-2's "reverting any
 * one of the three checks fails the job" would quietly not hold for the third.
 *
 * Only the CRITICAL count is asserted, not a full diff. `analyze`'s medium total
 * moves by one or two between runs (semgrep chunking), so diffing all ~1,080
 * findings would be flaky for no gain; the three criticals are the claim.
 */
function analyzeCriticals() {
  const rep = JSON.parse(runCli(['analyze', '--path', root, '--json']));
  const all = rep.findings || [];
  // CONTROL: analyze must have examined something.
  if (!all.length) throw new Error('analyze produced no findings at all — it examined nothing');
  return {
    total: all.length,
    criticals: all.filter((f) => String(f.severity || '').toLowerCase() === 'critical'),
  };
}

let analyzeProblems = [];
if (process.argv.indexOf('--with-analyze') !== -1) {
  let a;
  try {
    a = analyzeCriticals();
  } catch (err) {
    console.error(`FAIL  analyze could not run: ${err && err.message}`);
    console.error('      (semgrep is required for --with-analyze; this is not a pass)');
    process.exit(2);
  }
  console.log(`  analyze: ${a.total} findings, ${a.criticals.length} critical (want 0)`);
  for (const c of a.criticals) {
    analyzeProblems.push({
      cls: 'test-placeholder',
      msg: `CRITICAL [${c.category}] ${String(c.file || '').slice(root.length + 1)}:${c.line || ''}`,
    });
  }
}
problems.push(...analyzeProblems);

if (!problems.length) {
  const counts = {};
  for (const e of SPEC.expected) counts[e.class] = (counts[e.class] || 0) + 1;
  for (const k of Object.keys(counts).sort()) console.log(`  ok    ${String(counts[k]).padStart(2)}  ${k}`);
  console.log('\n  external corpus: 0 failure(s)\n');
  process.exit(0);
}

// Name the sub-class that regressed. "Something changed" sends the reader to
// diff two JSON blobs; "negation-proximity regressed" sends them to the check.
const byClass = {};
for (const p of problems) (byClass[p.cls] = byClass[p.cls] || []).push(p.msg);
for (const cls of Object.keys(byClass).sort()) {
  console.log(`  REGRESSED: ${cls}`);
  for (const m of byClass[cls]) console.log(`      ${m}`);
}
console.log(`\n  external corpus: ${problems.length} failure(s)\n`);
process.exit(1);
