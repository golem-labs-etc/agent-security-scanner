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
const { parseInterpretation, applyInterpretations, codeWindow, isSecretClass, triagedFalsePositives, interpretationSummary, describeFailure, extractJsonObject } = require(path.join(D, 'interpreter'));
const { stripDelimiters, containsDelimiter, canonicalize, fenceBlock, makeNonce, AUTHORITY_RULE } = require(path.join(D, 'prompt-armor'));
const { FindingsDeduplicator } = require(path.join(D, 'deduplicator'));

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
  // NOT here any more: 'prose wrapping valid JSON'. That case asserted the
  // envelope had to be bare, and it was wrong -- a real run showed every reply
  // arriving inside a markdown fence. It is now an ACCEPT case in group I9.
  // The schema stayed strict; only the envelope loosened.
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

// ── 7. The invalid key. Found in a real run, not by this suite. ────────────
//
// An invalid key produced "AI analysis enabled", "Interpreting 2 finding(s)",
// then "0 calls, 0 input tokens, 0 output tokens" and a normal report. No
// error, no degradation notice. The no-key case failed loudly; the BAD-key
// case failed silently, and a bad key is the common one -- an expired key, a
// wrong environment, a copy-paste that took the placeholder.
//
// This is the silent zero again, in a third place. The rule is the same as it
// is for a skipped engine: a thing that did not happen must never render as a
// thing that happened and found nothing.

ok('I7  a 401 is described as a key problem, with the code',
  describeFailure({ response: { status: 401 } }) === 'provider rejected the key (401)',
  describeFailure({ response: { status: 401 } }));
ok('I7b a 429 is described as a rate limit', /rate-limited/.test(describeFailure({ response: { status: 429 } })));
ok('I7c a timeout is described as one', describeFailure({ code: 'ECONNABORTED' }) === 'request timed out');

const allFailed = interpretationSummary(2, { calls: 0, input: 0, output: 0 },
  [{ reason: 'provider rejected the key (401)', status: 401 }]);
ok('I7d every call failing says 0 of N, not a bare zero',
  /^0 of 2 interpreted/.test(allFailed), allFailed);
ok('I7e it names the cause', /rejected the key \(401\)/.test(allFailed), allFailed);
ok('I7f it says the findings are uninterpreted',
  /uninterpreted/.test(allFailed), allFailed);
ok('I7g it does NOT read as a completed run',
  !/^2 call/.test(allFailed) && !/0 input tokens, 0 output tokens\.$/.test(allFailed), allFailed);

const partial = interpretationSummary(3, { calls: 2, input: 100, output: 50 },
  [{ reason: 'provider rate-limited the request (429)' }]);
ok('I7h a partial run reports both halves', /2 of 3 interpreted, 1 failed/.test(partial), partial);
ok('I7i and still reports the cost', /100 input tokens, 50 output tokens/.test(partial), partial);

const clean = interpretationSummary(2, { calls: 2, input: 800, output: 120 }, []);
ok('I7j a clean run reports calls and cost', /^2 of 2 interpreted\. 2 call/.test(clean), clean);

ok('I7k nothing to interpret is its own sentence, not a zero',
  /Nothing to interpret/.test(interpretationSummary(0, { calls: 0, input: 0, output: 0 }, [])));

// ── 8. The interpretation must survive dedup. ──────────────────────────────
//
// Also found by a real run, not by this suite. Dedup builds a NEW unified
// object, so anything it does not copy is silently dropped. Interpretations
// were requested, paid for, and discarded before the report — which is
// indistinguishable from --ai doing nothing at all.

{
  const dedup = new FindingsDeduplicator();
  const withInterp = [{
    tool: 'semgrep', severity: 'HIGH', file: 'a.js', line: 3, message: 'm',
    category: 'sql_injection',
    interpretation: { explanation: 'e', triage: 'looks_real', suggested_fix: null, usage: null },
    interpretedBy: 'ai',
  }];
  const unified = dedup.deduplicate([], withInterp);
  ok('I8  the interpretation survives deduplication',
    unified[0] && unified[0].interpretation && unified[0].interpretation.triage === 'looks_real',
    JSON.stringify(unified[0] && unified[0].interpretation));
  ok('I8b the layer label survives too', unified[0] && unified[0].interpretedBy === 'ai');
  ok('I8c a run without --ai carries no interpretation field',
    dedup.deduplicate([], [{ tool: 'semgrep', severity: 'LOW', file: 'b.js', line: 1, message: 'm' }])[0].interpretation === undefined);
}

// ── 9. Extraction, separately from validation. ─────────────────────────────
//
// Found by a real run: six of six replies parsed as malformed and degraded to
// needs_human. The fail-safe was right and the happy path had never run. Every
// reply arrived inside a markdown fence, and the first version called
// JSON.parse on the whole thing.
//
// The repair is extraction, NOT a looser schema. The closed enum is what stops
// a malformed reply softening a finding; what was too strict was the envelope.

const ENVELOPES = {
  'fenced with a json tag': '```json\n{"explanation":"e","triage":"looks_real"}\n```',
  'fenced with no tag': '```\n{"explanation":"e","triage":"looks_real"}\n```',
  'prose before': 'Here is my analysis:\n{"explanation":"e","triage":"looks_real"}',
  'prose after': '{"explanation":"e","triage":"looks_real"}\nHope that helps.',
  'prose both sides': 'Sure.\n```json\n{"explanation":"e","triage":"looks_real"}\n```\nLet me know.',
  'leading whitespace and newlines': '\n\n   {"explanation":"e","triage":"looks_real"}',
};
for (const [name, raw] of Object.entries(ENVELOPES)) {
  ok(`I9  ${name} -> parsed, not degraded`, parseInterpretation(raw).triage === 'looks_real',
    JSON.stringify(parseInterpretation(raw).triage));
}

// Extraction must be string-aware or it truncates valid objects.
ok('I9b a brace inside a string does not end the object',
  extractJsonObject('noise {"a":"}","b":1} tail') === '{"a":"}","b":1}',
  String(extractJsonObject('noise {"a":"}","b":1} tail')));
ok('I9c an escaped quote inside a string is handled',
  extractJsonObject('{"a":"say \\"hi\\"","b":2}') === '{"a":"say \\"hi\\"","b":2}',
  String(extractJsonObject('{"a":"say \\"hi\\"","b":2}')));
ok('I9d a nested object is taken whole',
  extractJsonObject('x {"a":{"b":1}} y') === '{"a":{"b":1}}');
ok('I9e no JSON at all returns null', extractJsonObject('I think it is fine.') === null);
ok('I9f an unterminated object returns null', extractJsonObject('{"a":1') === null);

// THE SCHEMA IS STILL STRICT. Extraction must not have loosened it.
ok('I9g a fenced reply with a triage outside the enum still degrades',
  parseInterpretation('```json\n{"explanation":"e","triage":"safe"}\n```').triage === 'needs_human');
ok('I9h a fenced reply with no explanation still degrades',
  parseInterpretation('```json\n{"triage":"looks_real"}\n```').triage === 'needs_human');

// ── 10. The captured replies. ──────────────────────────────────────────────
//
// Real output from anthropic/claude-haiku-4-5, captured with GLANCE_AI_RAW on
// the sample project. This is the fixture that matters: the parser's job is to
// cope with what a model actually sends, and three runs were lost to a guess
// about that.
//
// Note the shape it actually arrives in — EVERY reply is fenced with a ```json
// tag. The first version of the parser called JSON.parse on the whole reply,
// so every one of these degraded to needs_human.

const RAW = path.join(FIX, 'raw-replies');
const captures = fs.readdirSync(RAW).filter((n) => n.startsWith('captured-') && n.endsWith('.txt'));
ok('I10  at least one CAPTURED reply fixture exists', captures.length > 0,
  'raw-replies/ holds no captured-*.txt; a constructed fixture is not a substitute');

for (const f of captures) {
  const body = fs.readFileSync(path.join(RAW, f), 'utf8');
  // A capture is a log: several replies separated by the marker the capture
  // writes. Split and assert each, rather than parsing the first and calling
  // the file covered.
  const replies = body.split(/^--- reply .*---$/m).map((r) => r.trim()).filter(Boolean);
  ok(`I10b ${f} holds more than one reply`, replies.length > 1, `${replies.length} found`);

  const triages = [];
  for (let i = 0; i < replies.length; i++) {
    const r = parseInterpretation(replies[i]);
    ok(`I10c ${f} reply ${i + 1} parses to a real triage`,
      r.triage === 'looks_real' || r.triage === 'likely_false_positive',
      `triage=${r.triage} :: ${r.explanation.slice(0, 90)}`);
    triages.push(r);
  }

  // Every one of these arrived fenced. If a future capture does not, the
  // envelope changed and this line is where that shows up.
  ok(`I10d ${f}: every reply is fenced`,
    replies.every((r) => r.startsWith('```')),
    'a reply arrived unfenced; the envelope assumption has changed');

  // The known shape of this run, so a parser regression that silently turns
  // real answers into needs_human cannot pass.
  const real = triages.filter((t) => t.triage === 'looks_real').length;
  const fp = triages.filter((t) => t.triage === 'likely_false_positive').length;
  const diffs = triages.filter((t) => t.suggested_fix).length;
  // 5 looks_real, 1 likely_false_positive, THREE diffs.
  //
  // The run was reported as having two. It has three, and the third is
  // invisible for a real reason: the interpreter runs BEFORE dedup, so
  // src/render.js:3 — one line carrying two semgrep rules — gets two calls and
  // two answers, and the report collapses them into one finding showing one of
  // them. The second diff was paid for and never displayed.
  //
  // Asserted at the true number so the fixture records what the run actually
  // produced, not what the rendered report showed. See M5-style note in the PR:
  // interpreting after dedup would have saved that call.
  ok(`I10e ${f}: 5 looks_real, 1 likely_false_positive, 3 diffs`,
    real === 5 && fp === 1 && diffs === 3,
    `looks_real=${real} likely_false_positive=${fp} diffs=${diffs}`);

  // The duplicate pair is the evidence for the line above: two replies about
  // the same file, from one collapsed finding.
  const renderReplies = triages.filter((t) => /render\.js/.test(t.suggested_fix || '')).length;
  ok(`I10h ${f}: two replies answer the same collapsed finding`,
    renderReplies === 2,
    `${renderReplies} replies mention render.js in a diff — pre-dedup interpretation`);

  // The false positive is the CSRF finding, reasoned from GET-only routes.
  // Asserted because it is the one reply that shows the interpreter doing the
  // thing it exists for: disagreeing with an engine, without overruling it.
  const theFp = triages.find((t) => t.triage === 'likely_false_positive');
  ok(`I10f ${f}: the false positive reasons about GET-only routes`,
    /GET/.test(theFp.explanation) && /CSRF/i.test(theFp.explanation),
    theFp.explanation.slice(0, 120));

  // A diff carries real patch structure, not prose.
  const withDiff = triages.find((t) => t.suggested_fix);
  ok(`I10g ${f}: a suggested fix is a unified diff`,
    /^---\s|\n---\s/.test(withDiff.suggested_fix) && /\n\+/.test(withDiff.suggested_fix),
    withDiff.suggested_fix.slice(0, 80));
}

console.log(`\n  interpreter: ${failures} failure(s)\n`);
process.exit(failures > 0 ? 1 : 0);
