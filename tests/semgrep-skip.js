#!/usr/bin/env node

/**
 * The silent zero.
 *
 * Pointed at a directory, semgrep applies its own `.semgrepignore` — which
 * excludes test directories — and limits itself to files git is tracking. On
 * this repository that meant `semgrep --config=p/default tests/` scanned ZERO
 * files, printed "Findings: 0", and exited 0. Nothing in that output
 * distinguishes "looked and found nothing" from "looked at nothing", and a
 * scanner reporting the second as the first is worse than a scanner that
 * crashes.
 *
 * The fix is that runSemgrep passes explicit file paths. This test is not about
 * the fix: it is about the guard behind it. It hands runSemgrep a path semgrep
 * will skip and asserts that the skip is surfaced rather than rendered as a
 * clean result.
 *
 * If this test ever fails because "semgrep now scans tests/ anyway", do not
 * delete it — find another path semgrep skips. The guard is the thing under
 * test, not semgrep's ignore list.
 */

const path = require('path');
const { ToolsOrchestrator } = require('../dist/tools-orchestrator');
const { StaticAnalyzer } = require('../dist/static-analyzer');

const REPO = path.join(__dirname, '..');
const SKIPPED_DIR = path.join(REPO, 'tests');
const SCANNED_FILE = path.join(REPO, 'src', 'cli.ts');

let failures = 0;

function check(label, ok, detail) {
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) {
    failures++;
    if (detail) console.log(`        ${detail}`);
  }
}

async function main() {
  console.log('\nSemgrep skip guard\n');

  const orchestrator = new ToolsOrchestrator();
  if (!orchestrator.checkToolAvailability().find((t) => t.name === 'semgrep')?.installed) {
    console.log('  SKIPPED  semgrep is not installed, so there is nothing to guard.');
    console.log('           Install it: glance-scanner install-tools --semgrep\n');
    process.exit(0);
  }

  // 1. Everything skipped. This must NOT read as a clean scan.
  const all = await orchestrator.runSemgrep([SKIPPED_DIR]);
  check(
    'a fully skipped path reports ran: false',
    all.run.ran === false,
    `ran=${all.run.ran}, findings=${all.run.findings}`
  );
  check(
    'the reason says how many of how many were scanned',
    /scanned 0 of 1 path/.test(all.run.reason || ''),
    `reason=${all.run.reason}`
  );
  check(
    'the reason states this is not a clean result',
    /not a clean result/i.test(all.run.reason || ''),
    `reason=${all.run.reason}`
  );
  check(
    'the report line says the engine did not run',
    StaticAnalyzer.describe([all.run]).some((l) => /did not run/.test(l)),
    StaticAnalyzer.describe([all.run]).join(' | ')
  );

  // 2. Partly skipped. The run is real, but the skip is still surfaced.
  const partial = await orchestrator.runSemgrep([SCANNED_FILE, SKIPPED_DIR]);
  check('a partly skipped run still reports ran: true', partial.run.ran === true, `ran=${partial.run.ran}`);
  check(
    'the skipped path is named in a warning',
    (partial.run.warnings || []).some((w) => w.includes(SKIPPED_DIR)),
    JSON.stringify(partial.run.warnings)
  );
  check(
    'the warning appears in the report lines',
    StaticAnalyzer.describe([partial.run]).some((l) => /warning:/.test(l)),
    StaticAnalyzer.describe([partial.run]).join(' | ')
  );

  // 3. The ordinary case stays quiet. A guard that cries wolf gets ignored.
  const clean = await orchestrator.runSemgrep([SCANNED_FILE]);
  check('a fully scanned run carries no warning', !clean.run.warnings, JSON.stringify(clean.run.warnings));
  check('a fully scanned run reports ran: true', clean.run.ran === true, `ran=${clean.run.ran}`);

  console.log(failures === 0 ? '\n  All guard assertions hold.\n' : `\n  ${failures} assertion(s) failed.\n`);
  process.exit(failures > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
