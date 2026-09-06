#!/usr/bin/env node
/**
 * Synthetic-placeholder suppression for `analyze` secrets (#51, sub-class 3).
 *
 * A project that tests its own secret scanner got our worst report: ECC's three
 * `analyze` criticals were all sequential-alphabet placeholders passed to the
 * repo's own `detectSecrets`.
 *
 * This is the ONE sub-class allowed to suppress outright rather than downgrade.
 * A quoted directive is attacker-controllable text an agent might obey, so it
 * stays visible; a synthetic token in a test file is not a credential under any
 * reading. That licence is exactly why the negative controls below are the
 * load-bearing half: suppression must require BOTH a test path AND a positively
 * confirmed placeholder shape, so a real credential committed to a test file is
 * still reported.
 *
 * Runs without semgrep. Real-looking tokens are generated at runtime.
 */
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { isSyntheticTestSecret } = require('../dist/tools-orchestrator');

let pass = 0, fail = 0; const failures = [];
function ok(name, cond, detail) {
  if (cond) { pass++; console.log('  ok    ' + name); }
  else { fail++; failures.push(name); console.log('  FAIL  ' + name + (detail ? '  ' + detail : '')); }
}

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const rand = (n) => { let s = ''; for (let i = 0; i < n; i++) s += B62[crypto.randomInt(B62.length)]; return s; };
const GITHUB_RULE = 'generic.secrets.security.detected-github-token.detected-github-token';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'glance-synth-'));
function write(rel, body) {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, body);
  return p;
}

console.log('\nsynthetic test-secret suppression (#51 sub-class 3)\n');

// ── must suppress: sequential placeholders in test files ───────────────────
console.log('must SUPPRESS (synthetic placeholder in a test file):');
{
  const p = write('tests/hooks/governance-capture.test.js',
    "const findings = detectSecrets('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');\n");
  ok('sequential ghp_ token fed to a detector under test',
    isSyntheticTestSecret(GITHUB_RULE, p, 1) === true);
}
{
  const p = write('tests/hooks/pre-bash.test.js', 'aws = "AKIAABCDEFGHIJKLMNOP"\n');
  ok('sequential AKIA token in a test file',
    isSyntheticTestSecret(GITHUB_RULE, p, 1) === true);
}
{
  const p = write('spec/keys_spec.js', "const t = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';\n");
  ok('repeated-character token in a spec file',
    isSyntheticTestSecret(GITHUB_RULE, p, 1) === true);
}

// ── must NOT suppress: the controls that keep this honest ──────────────────
console.log('\nmust STILL FIRE (the negative controls):');
{
  // THE one that matters: a real credential committed to a test file.
  const real = 'ghp_' + rand(36);
  const p = write('tests/hooks/real-secret.test.js', `const token = '${real}';\n`);
  ok('a REAL random token in a test file is not suppressed',
    isSyntheticTestSecret(GITHUB_RULE, p, 1) === false, real);
}
{
  // Path gate: the same synthetic shape in shipped code still reports. A
  // placeholder in src/ is still a credential-shaped string in production code.
  const p = write('src/config.js', "const t = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';\n");
  ok('a synthetic token OUTSIDE a test path is not suppressed',
    isSyntheticTestSecret(GITHUB_RULE, p, 1) === false);
}
{
  // Category gate: only secret findings are eligible.
  const p = write('tests/other.test.js', "spawnSync(cmd, ['abcdefghijklmnop']);\n");
  ok('a non-secret rule in a test file is not suppressed',
    isSyntheticTestSecret('javascript.lang.security.detect-child-process', p, 1) === false);
}
{
  // Fail-open: an unreadable line must report, never assume.
  const p = path.join(dir, 'tests/does-not-exist.test.js');
  ok('an unreadable file is not suppressed (fail-open)',
    isSyntheticTestSecret(GITHUB_RULE, p, 1) === false);
  const q = write('tests/short.test.js', "const t = 'ghp_ABCDEFGHIJKLMNOP';\n");
  ok('a line number past end of file is not suppressed',
    isSyntheticTestSecret(GITHUB_RULE, q, 999) === false);
}

fs.rmSync(dir, { recursive: true, force: true });
console.log(`\n  synthetic-test-secrets: ${pass}/${pass + fail} passed`);
if (fail) { console.log('  failed: ' + failures.join(', ')); process.exit(1); }
