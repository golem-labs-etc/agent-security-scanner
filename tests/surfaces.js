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

const { scanSurfaces, resolvePolicy, CATEGORIES } = require('../dist/surfaces');

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

  // Amendment: fence policy, and obfuscation as its own signal.
  { id: 'P8a', fixture: 'P8_unfenced_directive.md', kind: 'prompt', policy: 'balanced',
    want: { category: 'prompt_injection', severity: 'high' } },
  { id: 'P8b', fixture: 'P8_unfenced_directive.md', kind: 'prompt', policy: 'strict',
    want: { category: 'prompt_injection', severity: 'high' } },
  { id: 'P9', fixture: 'P9_fenced_directive.md', kind: 'prompt', policy: 'balanced',
    want: { category: 'fenced_directive', severity: 'medium' } },
  { id: 'P10', fixture: 'P9_fenced_directive.md', kind: 'prompt', policy: 'strict',
    want: { category: 'prompt_injection', severity: 'high' } },
  { id: 'P11a', fixture: 'P11_homoglyph_fenced.md', kind: 'prompt', policy: 'balanced',
    want: { category: 'hidden_instruction', severity: 'critical' } },
  { id: 'P11b', fixture: 'P11_homoglyph_fenced.md', kind: 'prompt', policy: 'strict',
    want: { category: 'hidden_instruction', severity: 'critical' } },
  { id: 'P12', fixture: 'P12_zerowidth_word.md', kind: 'prompt',
    want: { category: 'obfuscated_text', severity: 'high' } },
  { id: 'P13', fixture: 'P13_mixed_script_word.md', kind: 'prompt',
    want: { category: 'obfuscated_text', severity: 'high' } },
  { id: 'P14', fixture: 'P14_bidi_override.md', kind: 'prompt',
    want: { category: 'obfuscated_text', severity: 'high' } },

  // Precedence: concealed characters are evaluated independently of the fence
  // policy and win. A homoglyph inside an HTML comment inside a fence must not
  // be swallowed by the downgrade path.
  { id: 'P16a', fixture: 'P16_concealed_in_fenced_comment.md', kind: 'prompt', policy: 'balanced',
    want: { category: 'hidden_instruction', severity: 'critical' } },
  { id: 'P16b', fixture: 'P16_concealed_in_fenced_comment.md', kind: 'prompt', policy: 'strict',
    want: { category: 'hidden_instruction', severity: 'critical' } },

  // The two categories that had no positive fixture until now. Both are
  // agent-facing severities, so both were shipping with no evidence they
  // detect anything. See the coverage check at the end of this file.
  { id: 'P17', fixture: 'P17_shell_metachar.json', kind: 'inventory',
    want: { category: 'command_injection_risk', severity: 'high' } },
  { id: 'P18', fixture: 'P18_literal_credential.md', kind: 'prompt',
    want: { category: 'credential_leak', severity: 'critical' } },

  // A third with no positive fixture, found only once negative fixtures
  // stopped counting toward coverage. It fired in N1 as a side effect of that
  // fixture using `npx -y`, which is not the same as anything asserting it
  // works. info severity, so it never reaches an agent, but the gap was the
  // same gap.
  { id: 'P19', fixture: 'P19_unpinned_uvx.json', kind: 'inventory',
    want: { category: 'unpinned_remote_exec', severity: 'info' } },
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

  { id: 'N6', fixture: 'N6_security_doc_fenced.md', kind: 'prompt', policy: 'balanced',
    rule: 'no high, no critical',
    check: (r) => r.counts.critical === 0 && r.counts.high === 0 },
  { id: 'N7', fixture: 'N7_soft_hyphen.md', kind: 'prompt',
    rule: 'no obfuscated_text',
    check: (r) => !r.findings.some((x) => x.category === 'obfuscated_text') },
  { id: 'N8', fixture: 'N8_bom.md', kind: 'prompt',
    rule: 'no obfuscated_text',
    check: (r) => !r.findings.some((x) => x.category === 'obfuscated_text') },
  { id: 'N9', fixture: 'N9_zwnj_scripts.md', kind: 'prompt',
    rule: 'no obfuscated_text',
    check: (r) => !r.findings.some((x) => x.category === 'obfuscated_text') },
  { id: 'N10', fixture: 'N10_emoji_zwj.md', kind: 'prompt',
    rule: 'no obfuscated_text',
    check: (r) => !r.findings.some((x) => x.category === 'obfuscated_text') },
  { id: 'N11', fixture: 'N11_russian_sentence.md', kind: 'prompt',
    rule: 'no obfuscated_text',
    check: (r) => !r.findings.some((x) => x.category === 'obfuscated_text') },
  { id: 'N12', fixture: 'N1_typical.json', kind: 'inventory', policy: 'strict',
    rule: 'clean machine under strict, still zero high',
    check: (r) => r.counts.high === 0 && r.counts.critical === 0 },

  // Pins an asymmetry found while writing P18, so it is a decision on record
  // rather than an accident nobody noticed. `secret_in_config` runs values
  // through `secretShape`, which includes a generic high-entropy fallback.
  // `credential_leak` runs free text through `findSecretsInText`, which
  // applies the vendor prefixes ONLY. So a 39-character high-entropy token in
  // prose does not fire, while the same value in an MCP env var does.
  //
  // Defensible: prose is full of hashes, UUIDs and base64 blobs, and an
  // entropy rule there would be noise. Undocumented until now, and it is why
  // the first P18 fixture written for this gap fired nothing at all.
  { id: 'N13', fixture: 'N13_high_entropy_prose.md', kind: 'prompt', policy: 'strict',
    rule: 'high-entropy token in prose is not a credential_leak (vendor shapes only)',
    check: (r) => !r.findings.some((x) => x.category === 'credential_leak') },
];

/**
 * Three real bundled skill files, verbatim, under both policies.
 *
 * Every other negative here is short, hand-written, and has its payload on one
 * line. That suite was 61 for 61 green while the scanner produced 1508
 * critical findings on an ordinary Hermes install, because none of these
 * fixtures is long enough, structured enough, or fenced enough to reach the
 * rules that were wrong. Length is the property being tested.
 *
 * See `fixtures/surfaces/real/README.md` for provenance and licence. Both
 * policies, because `strict` is what the Hermes adapter passes and it is the
 * policy under which fenced content is scanned at full severity, which is
 * where all but two of the false criticals lived.
 */
const REAL = [
  ['R1', 'real/R1_fitness_nutrition.SKILL.md', 'fenced shell block scanned as prose'],
  ['R2', 'real/R2_github_repo_management.SKILL.md', '22 identical copies, and 25 documented API calls'],
  ['R3', 'real/R3_google_workspace.SKILL.md', 'YAML frontmatter joined into one sentence'],
];

for (const [id, fixture, why] of REAL) {
  for (const policy of ['balanced', 'strict']) {
    NEGATIVE.push({
      id: id + (policy === 'strict' ? 's' : 'b'),
      fixture,
      kind: 'prompt',
      policy,
      rule: 'stock Hermes skill file: zero critical, zero high (' + why + ')',
      check: (r) => r.counts.critical === 0 && r.counts.high === 0,
    });
  }
}

async function scanCase(c) {
  const inv = c.kind === 'prompt' ? promptInv([c.fixture]) : jsonInv(c.fixture);
  const opts = Object.assign({}, OPTS);
  if (c.policy) opts.policy = c.policy;
  if (c.roots) opts.configScanRoots = c.roots;
  return scanSurfaces(inv, opts);
}

/** Label a case with the policy it ran under, so the output is unambiguous. */
function policyOf(c) {
  return c.policy || 'balanced';
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
      console.log('  ok    ' + c.id.padEnd(5) + policyOf(c).padEnd(9) +
                  c.want.category + ' ' + c.want.severity + '  [' + hit.id + ']' + loc);
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
      console.log('  ok    ' + c.id.padEnd(5) + policyOf(c).padEnd(9) + c.rule +
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

  console.log('');
  console.log('POLICY    stamping, planted config, and the absent off level');

  // P15: a config planted inside the scan target must be ignored and named.
  const plantedDir = path.join(FIX, 'P15_planted');
  const p15 = await scanSurfaces(
    { schema: 1, mcp_servers: [], prompt_files: [{ path: path.join(plantedDir, 'SKILL.md') }], code_files: [] },
    Object.assign({}, OPTS, { configScanRoots: [plantedDir] })
  );
  const warned = (p15.warnings || []).find(
    (w) => w.code === 'planted_config' && w.path && w.path.indexOf('.glance.json') !== -1
  );
  // The planted file asks for policy "off". The run must still be balanced,
  // and the skill in that directory must still be reported.
  const stillDetecting = p15.findings.some((x) => x.category === 'prompt_injection');
  if (warned && p15.policy === 'balanced' && stillDetecting) {
    pass++;
    console.log('  ok    P15  planted config ignored, warning names ' +
                path.basename(warned.path) + ', policy still ' + p15.policy +
                ', detection unaffected');
  } else {
    fail++;
    failures.push('P15');
    console.log('  FAIL  P15  warned=' + !!warned + ' policy=' + p15.policy +
                ' stillDetecting=' + stillDetecting);
  }

  // Every result must carry policy and evidence, whatever the case.
  let stampOk = true;
  for (const c of POSITIVE.concat(NEGATIVE)) {
    const r = await scanCase(c);
    if (r.policy !== policyOf(c) || typeof r.evidence !== 'boolean' ||
        !Array.isArray(r.warnings)) {
      stampOk = false;
      console.log('  FAIL  stamp missing or wrong on ' + c.id +
                  ' (policy=' + r.policy + ', evidence=' + r.evidence + ')');
    }
  }
  if (stampOk) {
    pass++;
    console.log('  ok    every result carries policy, evidence and warnings');
  } else {
    fail++;
    failures.push('policy-stamp');
  }

  // There is no off level, and asking for one is an error rather than a
  // silent fallback to something permissive.
  let refusedOff = false;
  try {
    resolvePolicy('off');
  } catch (e) {
    refusedOff = /no "off" level/.test(e.message);
  }
  const defaultsBalanced = resolvePolicy(undefined, { HOME: '/nonexistent-glance-home' }).policy === 'balanced';
  if (refusedOff && defaultsBalanced) {
    pass++;
    console.log('  ok    --policy off is refused; default resolves to balanced');
  } else {
    fail++;
    failures.push('no-off-level');
    console.log('  FAIL  refusedOff=' + refusedOff + ' defaultsBalanced=' + defaultsBalanced);
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

  // Category coverage, in BOTH directions.
  //
  //   1. every category the engine emits is declared in CATEGORIES, so the
  //      dashboard colour map cannot miss one;
  //   2. every declared category is emitted by at least one positive fixture.
  //
  // Direction 2 is the one that matters and it is the one this check did not
  // have. It reported "10 declared, 8 exercised, 0 uncovered" and passed. That
  // sentence was true and told you nothing: `command_injection_risk` (high)
  // and `credential_leak` (critical) had never been observed to fire, and both
  // are severities the Hermes adapter puts in front of an agent. A rule with
  // no positive fixture is a rule shipping on the claim that it works.
  //
  // Counting what did fire is not coverage of what could. Passing on a count
  // while two rules were unverified is the same shape as CI reporting green
  // while running no tests.
  // ---- fence extent: a structural check, not a fixture -------------------
  //
  // No fixture failed when the fence terminator regressed, because the other
  // narrowings kept the real files clean either way. The defect is still real
  // and still worth a guard, so it gets asserted directly: a fence must mask
  // every line of its body, not its opening line and one line more.
  //
  // The content is deliberately inert. A fixture that would exercise this
  // through the exfiltration rule has to carry a working payload, and writing
  // one is blocked on this machine by the guard's own D3 rule.
  {
    const { codeRanges, maskCode } = require('../dist/surfaces/text');
    const src = [
      'intro', '', '```bash', 'one', 'two', 'three', 'four', '```', '', 'after',
    ].join('\n');
    const masked = maskCode(src);
    const lines = masked.split('\n');
    const bodyBlank = lines.slice(2, 8).every((l) => /^\s*$/.test(l));
    const proseKept = lines[0] === 'intro' && lines[9] === 'after';
    // An unclosed fence must run to end of file rather than stopping at the
    // first line end, which is what the `$` alternative used to do.
    const openLines = maskCode(['a', '', '```js', 'x', 'y', 'z'].join('\n')).split('\n');
    const openBlank = openLines.slice(2).every((l) => /^\s*$/.test(l));
    if (bodyBlank && proseKept && openBlank && codeRanges(src).length >= 1) {
      pass++;
      console.log('  ok    FENCE  a fence masks its whole body, closed or not');
    } else {
      fail++;
      failures.push('FENCE');
      console.log('  FAIL  FENCE  fence masked ' +
        lines.slice(2, 8).filter((l) => /^\s*$/.test(l)).length + '/6 body lines, ' +
        'unclosed masked ' + openLines.slice(2).filter((l) => /^\s*$/.test(l)).length + '/4');
    }
  }

  const emitted = {};
  for (const c of POSITIVE) {
    const r = await scanCase(c);
    for (const x of r.findings) emitted[x.category] = true;
  }
  const negativeOnly = {};
  for (const c of NEGATIVE) {
    const r = await scanCase(c);
    for (const x of r.findings) negativeOnly[x.category] = true;
  }

  // Declared but never produced by a positive fixture. A category that only
  // ever appears incidentally in a negative fixture does not count: negative
  // fixtures assert what must NOT fire, so a category riding along in one is
  // not evidence that anything detects it on purpose.
  const unexercised = CATEGORIES.filter((k) => !emitted[k]);

  // Produced but not declared. This is what the old check tested.
  const undeclared = Object.keys(emitted)
    .concat(Object.keys(negativeOnly))
    .filter((k) => CATEGORIES.indexOf(k) === -1);

  if (unexercised.length === 0 && undeclared.length === 0) {
    pass++;
    console.log('  ok    CATEGORIES coverage: ' + CATEGORIES.length +
                ' declared, all ' + CATEGORIES.length +
                ' emitted by a positive fixture, 0 undeclared');
  } else {
    fail++;
    failures.push('categories-coverage');
    if (unexercised.length) {
      console.log('  FAIL  CATEGORIES: no positive fixture ever emits: ' +
                  unexercised.join(', ') +
                  '  (a rule with no fixture has no evidence it detects anything)');
    }
    if (undeclared.length) {
      console.log('  FAIL  CATEGORIES: emitted but not declared: ' +
                  undeclared.join(', '));
    }
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
