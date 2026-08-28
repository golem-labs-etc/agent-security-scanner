#!/usr/bin/env node

/**
 * Coverage check for the default (no-API-key) static scan.
 *
 * WHAT CHANGED AND WHY IT MATTERS.
 *
 * This suite used to run against MockAnalyzer, which returned canned findings
 * keyed off substrings in these exact fixtures. It scored 5/5, and the score
 * meant nothing: it was measuring whether a fixture generator recognised the
 * fixtures it had been written for. Against real engines the same five files
 * score 2 detected, 1 known gap, 2 fixtures that contain nothing findable.
 *
 * So each case now records what is EXPECTED and, where something is not
 * detected, WHY. A known gap is printed as a gap, never quietly counted as a
 * pass. The suite fails on a regression — something that should be detected and
 * is not, or a false positive on the safe file — and not on a limitation that
 * is already written down in the README.
 *
 * Do not "fix" a failure here by moving a case to `known-gap`. If real coverage
 * drops, that is the suite doing its job.
 */

const path = require('path');
const { spawn } = require('child_process');

const TEST_CASES = [
  {
    file: 'snippet1_sql.js',
    expect: 'known-gap',
    why: 'SQL injection by string concatenation in JavaScript. semgrep p/default '
       + 'has no rule for it; the equivalent in Python IS caught. Documented in '
       + 'the README under Known gaps. --ai covers it.',
  },
  {
    file: 'snippet2_secrets.js',
    expect: 'nothing-findable',
    why: 'The fixture holds `sk_live_REDACTED_FOR_DEMO`, which is not a credential '
       + 'shape. No honest secret scanner can flag it, and one that did would be '
       + 'matching the variable name rather than the value. Verified separately: '
       + 'semgrep flags a realistically shaped Stripe key at the correct line.',
  },
  {
    file: 'snippet3_path_traversal.js',
    expect: 'detect',
    expectedCategory: 'path_traversal',
  },
  {
    file: 'snippet4_xss.js',
    expect: 'nothing-findable',
    why: 'The XSS lives in an EJS template that exists only inside a comment on '
       + 'line 12. The .js file passes user input to res.render, which is not by '
       + 'itself a vulnerability. There is no template file on disk to scan.',
  },
  {
    file: 'snippet5_safe.js',
    expect: 'clean',
  },
];

function runScan(file) {
  const filepath = path.join(__dirname, file);
  return new Promise((resolve) => {
    const proc = spawn('node', ['dist/cli.js', 'analyze', '--file', filepath, '--no-cache', '--json'], {
      cwd: path.join(__dirname, '..'),
    });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => { stderr += d.toString(); });
    proc.on('close', (code) => {
      let report = null;
      try { report = JSON.parse(stdout); } catch { /* reported below */ }
      resolve({ report, stdout, stderr, code, filepath });
    });
  });
}

async function main() {
  console.log('\nDefault static scan — coverage check\n');

  let regressions = 0;
  let detected = 0;
  const gaps = [];

  for (const tc of TEST_CASES) {
    process.stdout.write(`  ${tc.file.padEnd(30)}`);
    const { report, stderr, code } = await runScan(tc.file);

    if (code !== 0 || !report) {
      console.log('CLI ERROR');
      if (stderr.trim()) console.log(`      ${stderr.trim().split('\n')[0]}`);
      regressions++;
      continue;
    }

    const findings = report.findings || [];
    // Findings for the file under test only. npm audit findings, if any, are
    // about package.json and are not what this case is asserting.
    const own = findings.filter((f) => String(f.file || '').endsWith(tc.file));
    const categories = [...new Set(own.map((f) => f.category))];

    if (tc.expect === 'detect') {
      const hit = !tc.expectedCategory || categories.includes(tc.expectedCategory);
      if (own.length > 0 && hit) {
        const lines = own.map((f) => f.line).filter((l) => l !== undefined && l !== null);
        console.log(`DETECTED   ${categories.join(', ')}  at line${lines.length === 1 ? '' : 's'} ${lines.join(', ') || '(none)'}`);
        detected++;
      } else {
        console.log(`REGRESSION expected ${tc.expectedCategory}, got ${categories.join(', ') || 'nothing'}`);
        regressions++;
      }
    } else if (tc.expect === 'clean') {
      if (own.length === 0) {
        console.log('CLEAN      no findings, correctly');
        detected++;
      } else {
        console.log(`FALSE POSITIVE  ${categories.join(', ')}`);
        regressions++;
      }
    } else {
      // known-gap and nothing-findable. Both are expected misses, and both are
      // printed. A DETECTION here is good news, not a failure — say so.
      if (own.length > 0) {
        console.log(`NOW DETECTED  ${categories.join(', ')}  (better than recorded; update this case)`);
        detected++;
      } else {
        console.log(tc.expect === 'known-gap' ? 'KNOWN GAP' : 'NOTHING FINDABLE');
        gaps.push(tc);
      }
    }
  }

  console.log(`\n  detected or correctly clean: ${detected}/${TEST_CASES.length}`);
  console.log(`  regressions: ${regressions}`);

  if (gaps.length) {
    console.log('\n  Not detected, and why:\n');
    for (const g of gaps) {
      console.log(`  ${g.file} — ${g.expect}`);
      for (const line of wrap(g.why, 72)) console.log(`      ${line}`);
      console.log('');
    }
  }

  console.log(
    regressions === 0
      ? '  No regressions.\n'
      : `  ${regressions} regression(s). This is a real coverage loss.\n`
  );
  process.exit(regressions > 0 ? 1 : 0);
}

function wrap(text, width) {
  const out = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if ((line + ' ' + word).trim().length > width) { out.push(line.trim()); line = word; }
    else line += ' ' + word;
  }
  if (line.trim()) out.push(line.trim());
  return out;
}

main().catch((e) => { console.error(e); process.exit(1); });
