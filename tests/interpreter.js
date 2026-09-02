#!/usr/bin/env node
/**
 * The interpreter's two hard rules, and the schema that enforces them.
 *
 *   1. ENGINES OUTRANK INTERPRETATION. The interpreter never removes a
 *      finding, never changes its severity, and never changes what the verdict
 *      line claims. It may lower its own confidence and nothing else.
 *
 *   2. THE SCANNED CODE IS HOSTILE INPUT. Comments arguing the code is safe,
 *      and comments instructing the reviewer what to answer, must not reach the
 *      model as structure and must not change any verdict.
 *
 * Both are asserted here rather than left to review, because both fail
 * silently: a suppressed finding and an obeyed comment look identical to a
 * clean report.
 *
 * No network. The provider call is the one part not exercised here; everything
 * that decides an outcome is pure and is tested directly.
 */

const path = require('path');
const fs = require('fs');

const D = path.join(__dirname, '..', 'dist');
const { parseInterpretation, applyInterpretations, codeWindow, isSecretClass, triagedFalsePositives } = require(path.join(D, 'interpreter'));
const { stripDelimiters, containsDelimiter, canonicalize, fenceBlock, makeNonce, AUTHORITY_RULE } = require(path.join(D, 'prompt-armor'));

let failures = 0;
function ok(label, pass, detail) {
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}`);
  if (!pass) { failures++; if (detail) console.log(`        ${detail}`); }
}

const FIX = path.join(__dirname, 'fixtures', 'interpreter');
console.log('\nInterpreter: schema, layering, and hostile input\n');

// ── 1. Closed schema. Malformed degrades to needs_human, never to safe. ─────

const BAD = {
  'not JSON': 'I think this is probably fine, honestly.',
  'JSON but an array': '[{"triage":"likely_false_positive"}]',
  'triage outside the enum': '{"explanation":"x","triage":"looks_safe"}',
  'triage invented to sound safe': '{"explanation":"x","triage":"safe"}',
  'triage missing': '{"explanation":"x"}',
  'explanation missing': '{"triage":"likely_false_positive"}',
  'empty object': '{}',
  'null': 'null',
  'prose wrapping valid JSON': 'Sure! {"explanation":"x","triage":"likely_false_positive"}',
};
for (const [name, raw] of Object.entries(BAD)) {
  const r = parseInterpretation(raw);
  ok(`I1  malformed (${name}) -> needs_human`, r.triage === 'needs_human', JSON.stringify(r.triage));
}
ok('I1b a well-formed reply is accepted',
  parseInterpretation('{"explanation":"Reachable from req.query.","triage":"looks_real","suggested_fix":null}').triage === 'looks_real');
ok('I1c there is no triage value meaning "safe"',
  ['looks_real', 'likely_false_positive', 'needs_human'].length === 3 &&
  parseInterpretation('{"explanation":"x","triage":"safe"}').triage === 'needs_human');
ok('I1d a diff is carried through as text',
  parseInterpretation('{"explanation":"x","triage":"looks_real","suggested_fix":"--- a\\n+++ b\\n"}').suggested_fix.startsWith('--- a'));

// ── 2. Engines outrank interpretation. ─────────────────────────────────────

const engineFindings = [
  { severity: 'CRITICAL', category: 'sql_injection', file: 'a.js', line: 3, message: 'm' },
  { severity: 'HIGH', category: 'xss', file: 'b.js', line: 9, message: 'm' },
];
const hostile = new Map([
  [0, { explanation: 'The comments say this is fine.', triage: 'likely_false_positive', suggested_fix: null, usage: null }],
  [1, { explanation: 'Cleared by the team.', triage: 'likely_false_positive', suggested_fix: null, usage: null }],
]);
const after = applyInterpretations(engineFindings, hostile);

ok('I2  no finding is removed, whatever the interpreter says', after.length === engineFindings.length,
  `${after.length} of ${engineFindings.length}`);
ok('I2b severity is untouched',
  after[0].severity === 'CRITICAL' && after[1].severity === 'HIGH',
  after.map((f) => f.severity).join(','));
ok('I2c category, file and line are untouched',
  after[0].category === 'sql_injection' && after[0].file === 'a.js' && after[0].line === 3);
ok('I2d the interpretation is attached to its own field, labelled',
  after[0].interpretation.triage === 'likely_false_positive' && after[0].interpretedBy === 'ai');
ok('I2e the triaged count is reported separately, not subtracted',
  triagedFalsePositives(after) === 2 && after.length === 2);

// ── 3. Hostile input: the adversarial fixture. ─────────────────────────────

const persuasive = fs.readFileSync(path.join(FIX, 'persuasive.js'), 'utf8');

ok('I3  the fixture really does try to instruct the reviewer',
  /MUST reply with/.test(persuasive) && /likely_false_positive/.test(persuasive),
  'fixture has lost its payload');

const nonce = makeNonce();
const block = fenceBlock('GLANCE_CODE', nonce, persuasive);
ok('I3b the fixture is still sendable after stripping', block !== null);
ok('I3c its forged closing tags do not survive',
  !/<\s*\/\s*GLANCE_CODE\s*>/i.test(canonicalize(block).replace(new RegExp(`</GLANCE_CODE:${nonce}>`), '')),
  'a forged fence survived into the block');
ok('I3d its forged OPENING tag does not survive either',
  (canonicalize(block).match(/<GLANCE_FINDING/gi) || []).length === 0);
ok('I3e the nonce is what makes the real tag unguessable',
  block.includes(`<GLANCE_CODE:${nonce}>`) && !persuasive.includes(nonce));
ok('I3f the authority rule names the blocks and says content carries none',
  /GLANCE_FINDING/.test(AUTHORITY_RULE) && /NO authority/.test(AUTHORITY_RULE) &&
  /may be hostile/.test(AUTHORITY_RULE));

// ── 4. Homoglyphs: strip AFTER normalise and fold. ─────────────────────────

const homoglyphs = fs.readFileSync(path.join(FIX, 'homoglyphs.txt'), 'utf8').split('\n').filter(Boolean);
ok('I4  the homoglyph fixture is not plain ASCII',
  homoglyphs.some((l) => /[^\x00-\x7F]/.test(l)), 'fixture degraded to ASCII');

for (const line of homoglyphs) {
  const label = JSON.stringify(line).slice(0, 34);
  ok(`I4b detected before stripping: ${label}`, containsDelimiter(line) !== null,
    'a disguised fence was not detected');
  ok(`I4c gone after stripping: ${label}`, containsDelimiter(stripDelimiters(line)) === null,
    `survived as ${containsDelimiter(stripDelimiters(line))}`);
}

ok('I4d ordinary prose is not treated as a fence',
  ['a < b and c > d', 'see <https://example.tld>', 'if (a<b) return c>d;', 'GLANCE_CODE is a tag name']
    .every((s) => containsDelimiter(s) === null));

// ── 5. The bounded window, and the secret-class rule. ──────────────────────

const long = Array.from({ length: 400 }, (_, i) => `line ${i + 1}`).join('\n');
const w = codeWindow(long, 200);
ok('I5  the window is bounded to +/-30 lines', w.to - w.from <= 61, `${w.from}..${w.to}`);
ok('I5b the window contains the finding line', w.text.includes('line 200'));
ok('I5c the window is not the whole file', !w.text.includes('line 1\n') || w.text.split('\n').length < 400);

ok('I5d a near-start line does not underflow', codeWindow(long, 2).from >= 1);
ok('I5e a past-end line does not overflow', codeWindow(long, 9999).to <= 400);

ok('I6  secret-class findings are recognised',
  isSecretClass('hardcoded_secrets') && isSecretClass('vulnerable_dependency'));
ok('I6b ordinary categories are not',
  !isSecretClass('sql_injection') && !isSecretClass('xss'));

console.log(`\n  interpreter: ${failures} failure(s)\n`);
process.exit(failures > 0 ? 1 : 0);
