#!/usr/bin/env node
/**
 * Placeholder-gate precision for secret_in_config (#37) and credential_leak (#42).
 *
 * Both fixes REMOVE critical false positives that fire today, so the negatives
 * — a genuine secret must still fire — are the load-bearing half. Every
 * real-looking token or key is generated at runtime and never committed.
 *
 * #37: the generic high_entropy rule fired on
 * `ghp_FAKE_TOKEN_FOR_TESTING_ONLY_00000000` (entropy 3.759, above the old flat
 * 3.6). The gap between that FP and the worst real base62/64 token at the
 * 32-char floor is ~0.06 bits, so the entropy threshold alone cannot separate
 * them with real margin; a length-normalized threshold plus a placeholder-word
 * gate do.
 *
 * #42: private_key was `literal:true`, exempt from the filler gate, so a
 * documented `-----BEGIN ... PRIVATE KEY-----` banner always fired. The signal
 * is the BODY between the banners: a real key carries a long base64 run, docs
 * carry `...`, nothing, or a placeholder.
 */
const crypto = require('crypto');
const { secretShape, findSecretsInText } = require('../dist/surfaces/secrets');

let pass = 0, fail = 0; const failures = [];
function ok(name, cond, detail) {
  if (cond) { pass++; console.log('  ok    ' + name); }
  else { fail++; failures.push(name); console.log('  FAIL  ' + name + (detail ? '  ' + detail : '')); }
}
const rand = (alpha, n) => { let s = ''; for (let i = 0; i < n; i++) s += alpha[crypto.randomInt(alpha.length)]; return s; };
const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

console.log('\nsecret-gate precision (#37 secret_in_config, #42 credential_leak)\n');

// ── #37 positive: the exact FP must stop firing ────────────────────────────
console.log('#37 must STOP firing:');
ok('ghp_FAKE_TOKEN_FOR_TESTING_ONLY_00000000 is not a secret',
  secretShape('ghp_FAKE_TOKEN_FOR_TESTING_ONLY_00000000') === null,
  `got ${secretShape('ghp_FAKE_TOKEN_FOR_TESTING_ONLY_00000000')}`);

// ── #37 negatives: real-shaped tokens must still fire (generated at runtime) ─
console.log('\n#37 must STILL fire (generated at runtime):');
{
  // Real-shaped 40-char ghp_ base62. ghp_ + [A-Za-z0-9]{30,} is the vendor
  // shape, so this matches github_pat regardless of the generic rule.
  const realPat = 'ghp_' + rand(B62, 36);
  ok('a real-shaped ghp_ token fires', secretShape(realPat) !== null, realPat);

  // A real token that happens to end in 0000 must still fire (the issue's own
  // negative control; the run detector must not be unanchored).
  const runEnd = 'ghp_' + rand(B62, 32) + '0000';
  ok('a real ghp_ token ending 0000 fires', secretShape(runEnd) !== null, runEnd);

  // A bare 32-char base62 token with no vendor prefix, forced to carry a digit
  // and a letter, reaches the generic rule and must still fire. Retry until the
  // generated token clears the (real) entropy floor, since a rare low-entropy
  // draw is exactly what the threshold is allowed to reject.
  let bare, tries = 0, fired = false;
  do { bare = rand(B62, 32); tries++; fired = secretShape(bare) !== null; }
  while (!fired && tries < 50);
  ok('a bare 32-char base62 token fires (generic rule)', fired,
    `${bare} after ${tries} draw(s)`);
}

// ── #42 positive: documented PEM banners must stop firing ──────────────────
console.log('\n#42 must STOP firing (documentation, not a key):');
const babysitter = '"private_key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n",';
const oracleProse = 'The private key starts with `-----BEGIN RSA PRIVATE KEY-----`';
const oracleExport = 'export OCI_CLI_KEY_CONTENT="-----BEGIN RSA PRIVATE KEY-----\\n..."';
ok('babysitter `...` body is not a leak',
  !findSecretsInText(babysitter).some(h => h.shape === 'private_key'),
  JSON.stringify(findSecretsInText(babysitter)));
ok('oracle prose "starts with -----BEGIN..." is not a leak',
  !findSecretsInText(oracleProse).some(h => h.shape === 'private_key'),
  JSON.stringify(findSecretsInText(oracleProse)));
ok('oracle export with `\\n...` body is not a leak',
  !findSecretsInText(oracleExport).some(h => h.shape === 'private_key'),
  JSON.stringify(findSecretsInText(oracleExport)));

// ── #42 negatives: genuine keys must still fire, both encodings ─────────────
console.log('\n#42 must STILL fire critical (real keys, generated at runtime):');
function pemOf(type) {
  if (type === 'rsa') return crypto.generateKeyPairSync('rsa', { modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey;
  return crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey;
}
for (const type of ['rsa', 'ed25519']) {
  const pem = pemOf(type);
  ok(`${type} multiline PEM fires`,
    findSecretsInText(pem).some(h => h.shape === 'private_key'));
  // JSON-escaped single-line form: real newlines -> literal \n.
  const escaped = '"key": "' + pem.replace(/\n/g, '\\n') + '"';
  ok(`${type} JSON-escaped \\n PEM fires`,
    findSecretsInText(escaped).some(h => h.shape === 'private_key'));
}

console.log(`\n  secrets-gate: ${pass}/${pass + fail} passed`);
if (fail) { console.log('  failed: ' + failures.join(', ')); process.exit(1); }
