#!/usr/bin/env node

/**
 * Coverage suite for `glance-scanner surfaces`.
 *
 * Every fixture under tests/fixtures/surfaces/ was written fresh for this
 * suite. None of it is shared with any other corpus, and nothing here is a
 * copy of an existing attack case.
 *
 * The suite is in three parts and all three have to pass:
 *
 *   POSITIVE  the seven things that must be caught
 *   NEGATIVE  the five things that must not fire, which are the ones that
 *             decide whether a person keeps the tool installed
 *   LEAK      no fixture content reaches default output, asserted by
 *             substring search rather than by reading it
 */

const path = require('path');
const fs = require('fs');

const { scanSurfaces } = require('../dist/surfaces');

const FIX = path.join(__dirname, 'fixtures', 'surfaces');
const f = (n) => path.join(FIX, n);

const NOW = '2026-08-30T00:00:00Z';

function promptInv(names) {
  return {
    schema: 1,
    mcp_servers: [],
    prompt_files: names.map((n) => ({ path: f(n) })),
    code_files: [],
  };
}

function jsonInv(name) {
  return JSON.parse(fs.readFileSync(f(name), 'utf8'));
}

// Every case scans surfaces only. The code engine is exercised by the existing
// suites and needs semgrep on PATH, which is not this suite's subject.
const OPTS = { now: NOW, scanCode: false, engineVersion: 'test' };

const POSITIVE = [
  { id: 'P1', fixture: 'P1_override.md', kind: 'prompt',
    want: { category: 'prompt_injection', severity: 'high' } },
  { id: 'P2', fixture: 'P2_homoglyph.md', kind: 'prompt',
    want: { category: 'hidden_instruction', severity: 'critical' } },
  { id: 'P3', fixture: 'P3_zerowidth.md', kind: 'prompt',
    want: { category: 'hidden_instruction', severity: 'critical' } },
  { id: 'P4', fixture: 'P4_html_comment.md', kind: 'prompt',
    want: { category: 'hidden_instruction', severity: 'critical' } },
  { id: 'P5', fixture: 'P5_http_url.json', kind: 'inventory',
    want: { category: 'unencrypted_transport', severity: 'high' } },
  { id: 'P6', fixture: 'P6_inline_secret.json', kind: 'inventory',
    want: { category: 'secret_in_config', severity: 'critical' } },
  { id: 'P7', fixture: 'P7_exfil.md', kind: 'prompt',
    want: { category: 'exfiltration_instruction', severity: 'critical' } },
];

const NEGATIVE = [
  { id: 'N1', fixture: 'N1_typical.json', kind: 'inventory',
    rule: 'no critical, no high',
    check: (r) => r.counts.critical === 0 && r.counts.high === 0 },
  { id: 'N2', fixture: 'N2_loopback.json', kind: 'inventory',
    rule: 'no unencrypted_transport',
    check: (r) => !r.findings.some((x) => x.category === 'unencrypted_transport') },
  { id: 'N3', fixture: 'N3_security_doc.md', kind: 'prompt',
    rule: 'no high, no critical',
    check: (r) => r.counts.critical === 0 && r.counts.high === 0 },
  { id: 'N4', fixture: 'N4_curl_doc.md', kind: 'prompt',
    rule: 'no high',
    check: (r) => r.counts.high === 0 },
  { id: 'N5', fixture: 'N5_env_reference.json', kind: 'inventory',
    rule: 'no secret_in_config',
    check: (r) => !r.findings.some((x) => x.category === 'secret_in_config') },
];

async function scanCase(c) {
  const inv = c.kind === 'prompt' ? promptInv([c.fixture]) : jsonInv(c.fixture);
  return scanSurfaces(inv, OPTS);
}

/**
 * Assert no run of `win` characters from the fixture appears in the report.
 *
 * A substring search, not a read-through. Windows that are only whitespace or
 * punctuation are skipped: they carry no content and would match trivially.
 */
function leakedWindow(fixtureText, reportJson, win, allow) {
  for (let i = 0; i + win <= fixtureText.length; i++) {
    const w = fixtureText.slice(i, i + win);
    if (!/[A-Za-z0-9]{4}/.test(w)) continue;
    // The output schema *requires* `path`, and for an inventory fixture the
    // path is a string the fixture itself declares. Excluding exactly those
    // declared paths keeps the assertion meaningful instead of unsatisfiable:
    // everything else in the fixture -- URLs, env values, prose -- must still
    // be absent.
    if (allow.some((a) => a.indexOf(w) !== -1)) continue;
    if (reportJson.indexOf(w) !== -1) return w;
  }
  return null;
}

/** Paths the report is required to echo back, and therefore may contain. */
function declaredPaths(c) {
  if (c.kind === 'prompt') return [f(c.fixture)];
  const inv = jsonInv(c.fixture);
  const out = [];
  for (const s of inv.mcp_servers || []) if (s.source) out.push(s.source);
  for (const p of inv.prompt_files || []) out.push(p.path);
  // Both the bare path and its JSON-encoded form, so a window that straddles
  // the opening quote is still recognised as the path rather than a leak.
  return out.concat(out.map((x) => JSON.stringify(x)));
}

(async function main() {
  let pass = 0;
  let fail = 0;
  const failures = [];

  console.log('glance-scanner surfaces');
  console.log('platform: ' + process.platform + ' ' + process.arch +
              '  node ' + process.version);
  console.log('');

  console.log('POSITIVE  must be caught');
  for (const c of POSITIVE) {
    const r = await scanCase(c);
    const hit = r.findings.find(
      (x) => x.category === c.want.category && x.severity === c.want.severity
    );
    if (hit) {
      pass++;
      const loc = hit.line ? ':' + hit.line : '';
      console.log('  ok    ' + c.id + '  ' + c.want.category + ' ' +
                  c.want.severity + '  [' + hit.id + ']' + loc);
    } else {
      fail++;
      failures.push(c.id);
      console.log('  FAIL  ' + c.id + '  expected ' + c.want.category + '/' +
                  c.want.severity + ', got ' +
                  (r.findings.map((x) => x.category + '/' + x.severity).join(', ') || 'nothing'));
    }
  }

  console.log('');
  console.log('NEGATIVE  must not fire');
  for (const c of NEGATIVE) {
    const r = await scanCase(c);
    if (c.check(r)) {
      pass++;
      console.log('  ok    ' + c.id + '  ' + c.rule +
                  '  (c' + r.counts.critical + ' h' + r.counts.high +
                  ' m' + r.counts.medium + ' i' + r.counts.info + ')');
    } else {
      fail++;
      failures.push(c.id);
      console.log('  FAIL  ' + c.id + '  ' + c.rule + ' violated: ' +
                  r.findings.map((x) => x.severity + '/' + x.category +
                                 (x.line ? ':' + x.line : '')).join(', '));
    }
  }

  console.log('');
  console.log('LEAK      default output must quote no fixture content');
  const WIN = 12;
  for (const c of POSITIVE) {
    const r = await scanCase(c);
    const json = JSON.stringify(r);
    const text = fs.readFileSync(f(c.fixture), 'utf8');
    const leak = leakedWindow(text, json, WIN, declaredPaths(c));
    // Belt and braces: the field must be structurally absent too.
    const hasEvidenceField = r.findings.some(
      (x) => Object.prototype.hasOwnProperty.call(x, 'evidence')
    );
    if (!leak && !hasEvidenceField) {
      pass++;
      console.log('  ok    ' + c.id + '  no ' + WIN +
                  '-char run of the fixture in default output, no evidence field');
    } else {
      fail++;
      failures.push(c.id + '-leak');
      console.log('  FAIL  ' + c.id + '  ' +
                  (leak ? 'leaked ' + JSON.stringify(leak) : 'evidence field present'));
    }
  }

  // The opposite must also hold: --evidence has to actually produce evidence,
  // or the default proves nothing.
  const ev = await scanSurfaces(promptInv(['P1_override.md']),
                                Object.assign({}, OPTS, { evidence: true }));
  const evOk = ev.findings.length > 0 && ev.findings.every((x) => !!x.evidence);
  if (evOk) {
    pass++;
    console.log('  ok    --evidence attaches evidence when asked');
  } else {
    fail++;
    failures.push('evidence-opt-in');
    console.log('  FAIL  --evidence produced no evidence');
  }

  // Fingerprints must be stable across runs, or baselining is worthless.
  const a = await scanCase(POSITIVE[0]);
  const b = await scanCase(POSITIVE[0]);
  if (JSON.stringify(a.findings.map((x) => x.id)) ===
      JSON.stringify(b.findings.map((x) => x.id))) {
    pass++;
    console.log('  ok    fingerprints stable across runs');
  } else {
    fail++;
    failures.push('fingerprint-stability');
    console.log('  FAIL  fingerprints differ between identical runs');
  }

  console.log('');
  console.log('surfaces: ' + pass + '/' + (pass + fail) + ' passed on ' +
              process.platform);
  if (fail) {
    console.log('failed: ' + failures.join(', '));
    process.exit(1);
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
