#!/usr/bin/env node
/**
 * The verdict line, the frame, and the action sentence.
 *
 * These are the only sentences in the report that are not a direct quote of an
 * engine, so they are the only ones that can overstate. The suite exists to
 * hold one rule above all the others:
 *
 *   THE VERDICT MUST NEVER CLAIM MORE CERTAINTY THAN THE FINDINGS CARRY.
 *
 * An audit-class rule reports a construct worth a look; it has not established
 * that anything is wrong. A run that found only those must not tell anyone to
 * fix something before shipping. That is asserted directly, in both frames,
 * rather than left to a reviewer to notice.
 */

const path = require('path');
const { verdictLine, actionFor, isAuditClass, blockers } = require(path.join(__dirname, '..', 'dist', 'verdict'));

let failures = 0;
function ok(label, pass, detail) {
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}`);
  if (!pass) { failures++; if (detail) console.log(`        ${detail}`); }
}

const ENGINES = [
  { name: 'semgrep (p/default + glance rules)', ran: true },
  { name: 'npm audit', ran: true },
];

// A semgrep audit rule and a semgrep rule that asserts a defect. The `.audit.`
// segment is semgrep's own namespacing, not a convention invented here.
const AUDIT_RULE = 'javascript.express.security.audit.xss.direct-response-write.direct-response-write';
const DEFECT_RULE = 'javascript.express.security.injection.raw-html-format.raw-html-format';

const auditFinding = (sev = 'MEDIUM') => ({
  severity: sev, category: 'xss', tools: ['semgrep'], rules: [AUDIT_RULE],
  file: 'src/render.js', line: 3,
});
const defectFinding = (sev = 'HIGH') => ({
  severity: sev, category: 'sql_injection', tools: ['semgrep'], rules: ['glance-js-sql-injection'],
  file: 'src/users.js', line: 6,
});
const depFinding = () => ({
  severity: 'CRITICAL', category: 'vulnerable_dependency', tools: ['npm-audit'],
  rules: ['vulnerable_dependency'], file: 'package.json',
  details: { name: 'lodash', fixAvailable: { name: 'lodash', version: '4.18.1', isSemVerMajor: false } },
});
const secretFinding = () => ({
  severity: 'CRITICAL', category: 'hardcoded_secrets', tools: ['semgrep'],
  rules: ['generic.secrets.security.detected-jwt-token.detected-jwt-token'],
  file: 'src/config.js', line: 16,
});

console.log('\nVerdict line, frame, and action sentence\n');

// ── 1. Rule classification ─────────────────────────────────────────────────

ok('V1  a semgrep .audit. rule is audit-class', isAuditClass(auditFinding()));
ok('V1b a semgrep injection rule is not', !isAuditClass(defectFinding()));
ok('V1c an npm advisory is not audit-class', !isAuditClass(depFinding()));
ok(
  'V1d one line with an audit AND a defect rule is NOT audit-class',
  !isAuditClass({ ...auditFinding(), rules: [AUDIT_RULE, DEFECT_RULE] }),
  'a non-audit rule fired here too, so the finding must not be softened'
);
ok('V1e a HIGH audit finding is not a blocker', blockers([auditFinding('HIGH')]).length === 0);
ok('V1f a HIGH defect finding is a blocker', blockers([defectFinding('HIGH')]).length === 1);

// ── 2. The three verdict states, in both frames ────────────────────────────

for (const frame of ['author', 'adopter']) {
  const v = verdictLine([defectFinding('HIGH'), depFinding()], ENGINES, frame, 21);
  ok(`V2  blockers, ${frame}: counts them`, /1 critical and 1 high/.test(v), v);
  ok(
    `V2b blockers, ${frame}: says what to do about it`,
    frame === 'author' ? /fix before shipping/.test(v) : /not safe to adopt/.test(v),
    v
  );
}

for (const frame of ['author', 'adopter']) {
  const v = verdictLine([auditFinding(), auditFinding('HIGH')], ENGINES, frame, 21);
  ok(`V3  audit-only, ${frame}: leads with "No blockers"`, /^No blockers\./.test(v), v);
  ok(`V3b audit-only, ${frame}: counts the audit findings`, /2 audit findings/.test(v), v);
  // THE RULE THIS FILE EXISTS FOR.
  ok(
    `V3c audit-only, ${frame}: does NOT say fix before shipping`,
    !/fix before shipping/.test(v) && !/not safe to adopt/.test(v),
    v
  );
  ok(`V3d audit-only, ${frame}: frame shows in the wording`,
    frame === 'author' ? /this code handles untrusted input/.test(v) : /trusting this code/.test(v), v);
}

for (const frame of ['author', 'adopter']) {
  const v = verdictLine([], ENGINES, frame, 21);
  ok(`V4  zero findings, ${frame}: names the engines that ran`,
    v.includes('semgrep') && v.includes('npm audit'), v);
  ok(`V4b zero findings, ${frame}: names the scope`, /21 files/.test(v), v);
  ok(`V4c zero findings, ${frame}: does not say "clean"`, !/\bclean\b/i.test(v), v);
  ok(`V4d zero findings, ${frame}: states the limit`, /not the same as safe/.test(v), v);
}

{
  // The silent zero, in prose. No engine ran, nothing was found, and the
  // sentence must not read like a pass.
  const v = verdictLine([], [{ name: 'semgrep', ran: false, reason: 'not installed' }], 'author', 21);
  ok('V4e no engine ran: says so and refuses the clean reading',
    /Nothing was checked/.test(v) && /not a clean result/.test(v), v);
}

// ── 3. Action sentences, one per rule class ────────────────────────────────

ok('V5  npm advisory names the package and the fixed version',
  actionFor(depFinding()) === 'Update lodash to 4.18.1.', String(actionFor(depFinding())));

ok('V5b a major-version fix says so',
  /a major version change/.test(String(actionFor({
    ...depFinding(),
    details: { name: 'x', fixAvailable: { name: 'x', version: '2.0.0', isSemVerMajor: true } },
  }))));

ok('V5c fixAvailable:false is reported as no fix, not invented',
  /No fix is published yet/.test(String(actionFor({
    ...depFinding(), details: { name: 'x', fixAvailable: false },
  }))));

ok('V5d a secret says rotate and remove',
  actionFor(secretFinding()) === 'Rotate this credential and remove it from the file.',
  String(actionFor(secretFinding())));

ok('V5e an audit finding points at the file and line',
  actionFor(auditFinding()) === 'Open src/render.js:3 and check whether this value can come from outside the program.',
  String(actionFor(auditFinding())));

ok('V5f a rule class with no supported action gets NO sentence',
  actionFor(defectFinding()) === null,
  `got ${JSON.stringify(actionFor(defectFinding()))} — a generic "review this" would be filler, and an invented fix would be worse`);

console.log(`\n  verdict: ${failures} failure(s)\n`);
process.exit(failures > 0 ? 1 : 0);
