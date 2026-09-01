#!/usr/bin/env node
/**
 * Fail the build when a scanned-tree value is interpolated into output without
 * going through src/render-safe.ts.
 *
 * This is a GREP, and it is worth being honest about what that means. It reads
 * text, not types. It cannot follow a value through a rename or a helper, so a
 * path assigned to `const p` and interpolated as `${p}` slips past it. A type
 * system could catch that -- a branded `Unsafe<string>` that only render-safe
 * can unwrap -- and that is the right fix if this ever fires falsely often
 * enough to be annoying, or misses something real.
 *
 * It is here anyway because the failure it guards is not subtle misuse. Every
 * one of the four instances of this bug was the obvious shape: a template
 * literal with `${f.path}` or `${finding.file}` in it, written by someone
 * fixing one surface who did not know the other three existed. A grep catches
 * exactly that shape, and catching it is the whole point.
 *
 * To add a value: put its expression in TAINTED. To allow a line: make it call
 * a helper, or add it to ALLOW with a reason.
 */

const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'src');

// Expressions that carry a value read out of a tree we did not write.
const TAINTED = [
  'f.path', 'f.evidence', 'f.category', 'f.severity', 'f.id',
  'finding.file', 'finding.message', 'finding.tool', 'finding.severity',
  'w.message',
  // Added 1 Sep, after the check shipped and missed all three. The list is the
  // check's whole knowledge of what is hostile, so a value absent from it is
  // invisible no matter how obvious the shape. filteringReasoning is the
  // model's own text, and the model reads the scanned file.
  'finding.filteringReasoning', 'finding.line', 'finding.confidence',
  'finding.category', 'finding.rules', 'finding.tools', 'finding.categories',
];

// Calling any of these IS the fix, so a line that calls one is fine.
const HELPERS = [
  'renderPath', 'renderEvidence', 'renderField', 'escapeControls', 'fenceFor',
];

// Files that define the helpers, or that produce machine-readable output where
// escaping would corrupt the format. JSON is not a renderer: JSON.stringify
// already encodes control characters, and a consumer parses rather than reads.
const SKIP_FILES = new Set(['render-safe.ts']);

// path -> reason. A line listed here is allowed; the reason is the point.
const ALLOW = new Map();

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.ts')) out.push(full);
  }
  return out;
}

const problems = [];
let scanned = 0;

for (const file of walk(SRC)) {
  if (SKIP_FILES.has(path.basename(file))) continue;
  scanned++;
  const rel = path.relative(path.join(__dirname, '..'), file);
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    const key = `${rel}:${i + 1}`;
    if (ALLOW.has(key)) return;
    // Only interpolation matters. An assignment or a comparison is not output.
    if (!line.includes('${')) return;
    const hit = TAINTED.find((tok) => line.includes('${' + tok) || line.includes('${' + tok.split('.')[0] + '.' + tok.split('.')[1] + '}'));
    if (!hit) return;
    if (HELPERS.some((h) => line.includes(h + '('))) return;
    problems.push({ key, hit, text: line.trim() });
  });
}

console.log(`render safety: ${scanned} source file(s) checked`);

if (problems.length) {
  console.error('\nrender-safety check FAILED:');
  for (const p of problems) {
    console.error(`- ${p.key}: \`${p.hit}\` interpolated without a render-safe helper`);
    console.error(`    ${p.text}`);
  }
  console.error(
    '\nAny value derived from a scanned tree is escaped for the renderer it will\n' +
    'reach. Use src/render-safe.ts. See "The rendering invariant" in CLAUDE.md\n' +
    'for why this rule exists and what the escape does NOT cover.'
  );
  process.exit(1);
}

console.log('  every scanned-tree interpolation goes through render-safe.');
