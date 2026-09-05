#!/usr/bin/env node
/**
 * Vendor-shape reachability and truncation-marker gating (#43).
 *
 * Two defects in one finding:
 *   1. `openai` (sk-...) is listed before `anthropic` (sk-ant-...), and the
 *      openai body `[A-Za-z0-9_-]{20,}` swallows `ant-...`, so every Anthropic
 *      key is labelled openai and the `anthropic` shape is dead code.
 *   2. The repro value `sk-ant-api03-prod-batch-...` is a truncated illustrative
 *      stand-in in an ASCII tree; the `...` marker is documentation's way of
 *      writing "not a real key", so it should not fire at all.
 *
 * The reachability block mirrors the both-directions CATEGORIES check in
 * surfaces.js: every declared shape must have a runtime-generated witness that
 * `secretShape` labels with exactly that shape's name, and every witnessed name
 * must be a declared shape. A shape shadowed into dead code fails the suite, and
 * a later reordering edit that reintroduces shadowing is caught here.
 *
 * Every real-looking token/key is generated at runtime; none is committed.
 */
const crypto = require('crypto');
const { secretShape, findSecretsInText, SECRET_SHAPE_NAMES } = require('../dist/surfaces/secrets');

let pass = 0, fail = 0; const failures = [];
function ok(name, cond, detail) {
  if (cond) { pass++; console.log('  ok    ' + name); }
  else { fail++; failures.push(name); console.log('  FAIL  ' + name + (detail ? '  ' + detail : '')); }
}
const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const B64U = B62 + '-_';
const HEXU = '0123456789ABCDEF';
const rand = (alpha, n) => { let s = ''; for (let i = 0; i < n; i++) s += alpha[crypto.randomInt(alpha.length)]; return s; };
function pem(type) {
  return crypto.generateKeyPairSync(type, {
    modulusLength: type === 'rsa' ? 2048 : undefined,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey;
}

// One canonical, full-length, real-shaped witness per declared shape. A witness
// must be long enough that its own vendor pattern matches (no truncation), so
// this doubles as the "full-length keys still fire, each with its own vendor"
// negative control.
const WITNESS = {
  openai:      () => 'sk-proj-' + rand(B62, 48),
  anthropic:   () => 'sk-ant-api03-' + rand(B62, 48),
  github_pat:  () => 'ghp_' + rand(B62, 36),
  github_fine: () => 'github_pat_' + rand(B62 + '_', 60),
  aws_akid:    () => 'AKIA' + rand(HEXU, 16),
  google:      () => 'AIza' + rand(B64U, 35),
  slack:       () => 'xoxb-' + rand(B62 + '-', 20),
  stripe:      () => 'sk_live_' + rand(B62, 28),
  gitlab:      () => 'glpat-' + rand(B64U, 24),
  npm:         () => 'npm_' + rand(B62, 36),
  hf:          () => 'hf_' + rand(B62, 34),
  jwt:         () => 'eyJ' + rand(B64U, 16) + '.eyJ' + rand(B64U, 24) + '.' + rand(B64U, 40),
  private_key: () => pem('ed25519'),
};

console.log('\nvendor-shape reachability + truncation gate (#43)\n');

// ── reachability: every declared shape has a witness, both directions ────────
console.log('every declared shape is reachable (both directions):');
const declared = SECRET_SHAPE_NAMES.slice().sort();
const witnessed = Object.keys(WITNESS).sort();
ok('WITNESS covers exactly the declared shapes',
  declared.length === witnessed.length && declared.every((n, i) => n === witnessed[i]),
  `declared=[${declared}] witnessed=[${witnessed}]`);
for (const name of SECRET_SHAPE_NAMES) {
  const w = WITNESS[name] ? WITNESS[name]() : null;
  const got = w == null ? '(no witness)' : secretShape(w);
  ok(`${name} is reachable (a witness labels ${name})`, got === name,
    `got ${got}` + (name === 'private_key' ? '' : ` for ${JSON.stringify(w)}`));
}

// ── #43 positive: sk-ant labels anthropic, sk-proj still labels openai ───────
console.log('\nvendor labels are correct:');
ok('a canonical sk-ant-api03- key labels anthropic, not openai',
  secretShape('sk-ant-api03-' + rand(B62, 40)) === 'anthropic');
ok('a canonical sk-proj- key still labels openai',
  secretShape('sk-proj-' + rand(B62, 40)) === 'openai');

// ── #43 positive: a value truncated with ... must not fire (both entry points)
console.log('\ntruncated illustrative values do not fire:');
const repro = '│   ├── API Key: sk-ant-api03-prod-batch-...';
ok('the repro ASCII-tree line produces no credential_leak',
  findSecretsInText(repro).length === 0,
  JSON.stringify(findSecretsInText(repro)));
ok('an sk-proj- prefix truncated with ... in text does not fire',
  findSecretsInText('key: sk-proj-abcd1234efgh5678ijkl-...').length === 0,
  JSON.stringify(findSecretsInText('key: sk-proj-abcd1234efgh5678ijkl-...')));
ok('a truncated value in a config field is not a secret_in_config',
  secretShape('sk-ant-api03-prod-batch-...') === null,
  `got ${secretShape('sk-ant-api03-prod-batch-...')}`);
ok('a unicode-ellipsis truncation is also filler',
  secretShape('sk-proj-abcd1234efgh5678ijklmnop…') === null,
  `got ${secretShape('sk-proj-abcd1234efgh5678ijklmnop…')}`);

// ── #43 negative: full-length real keys still fire (via text), own vendor ────
console.log('\nfull-length real keys still fire with the right vendor (in text):');
for (const name of ['openai', 'anthropic', 'stripe', 'github_pat']) {
  const w = WITNESS[name]();
  const hits = findSecretsInText('token = ' + w);
  ok(`${name} full-length key fires as ${name} in free text`,
    hits.some(h => h.shape === name), JSON.stringify(hits));
}

console.log(`\n  secret-shapes-reachability: ${pass}/${pass + fail} passed`);
if (fail) { console.log('  failed: ' + failures.join(', ')); process.exit(1); }
