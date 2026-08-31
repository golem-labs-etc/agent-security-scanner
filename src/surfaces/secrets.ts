/**
 * Literal-secret detection by value shape.
 *
 * The rule is deliberately shape-first rather than name-first. `API_KEY` as a
 * *name* tells you nothing -- almost every MCP config on earth has one, and
 * nearly all of them hold a reference rather than a value. What distinguishes
 * a leak is that the config carries the credential itself.
 *
 * The reference forms below are the whole reason `N5` passes: `${OPENAI_API_KEY}`
 * is a pointer, not a secret, and flagging it critical on every clean machine
 * is how a scanner earns an uninstall.
 */

import { eachMatch } from './text';

/** A value that names a variable rather than holding one. */
const REFERENCE_RE = [
  /^\$\{[^}]+\}$/,          // ${VAR}
  /^\$[A-Za-z_][A-Za-z0-9_]*$/, // $VAR
  /^\{\{[^}]+\}\}$/,        // {{VAR}}
  /^%[A-Za-z_][A-Za-z0-9_]*%$/, // %VAR% (Windows)
  /^env:[A-Za-z_]/i,        // env:VAR
  /^\$\(.*\)$/,             // $(cmd) -- a reference, though see command rules
];

/** Obvious non-secrets that happen to be long. */
const PLACEHOLDER_RE = [
  /^(your|my|the)[-_ ]/i,
  /^(x{3,}|y{3,}|z{3,}|a{4,}|0{4,}|1{4,})$/i,
  /^<.*>$/,
  /(changeme|placeholder|example|dummy|sample|redacted|replace[-_ ]?me|insert|todo|fixme|not[-_ ]?a[-_ ]?real)/i,
  /^(true|false|null|none|undefined)$/i,
  /^\d+$/,
];

/**
 * Value shapes that are credentials on sight. Vendor prefixes first, because
 * they are unambiguous; the generic high-entropy rule is last and is the one
 * that can be wrong.
 */
const SECRET_SHAPES: Array<{ name: string; re: RegExp; literal?: boolean }> = [
  { name: 'openai', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/ },
  { name: 'anthropic', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'github_pat', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b/ },
  { name: 'github_fine', re: /\bgithub_pat_[A-Za-z0-9_]{50,}\b/ },
  { name: 'aws_akid', re: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b/ },
  { name: 'google', re: /\bAIza[A-Za-z0-9_-]{35}\b/ },
  { name: 'slack', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'stripe', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/ },
  { name: 'gitlab', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'npm', re: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { name: 'hf', re: /\bhf_[A-Za-z0-9]{30,}\b/ },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: 'private_key', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, literal: true },
];

/** True when the value is a pointer to a secret rather than the secret. */
export function isReference(value: string): boolean {
  const v = value.trim();
  if (!v) return true;
  return REFERENCE_RE.some((re) => re.test(v));
}

function isPlaceholder(value: string): boolean {
  const v = value.trim();
  return PLACEHOLDER_RE.some((re) => re.test(v));
}

/** Shannon entropy in bits per character. */
function entropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  for (const k of Object.keys(freq)) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Does this *value* look like a literal credential?
 *
 * Returns the matched shape name, or null. A reference or a placeholder is
 * always null, whatever its entropy.
 */
export function secretShape(value: string): string | null {
  const v = (value || '').trim();
  if (!v || isReference(v) || isPlaceholder(v)) return null;

  for (const s of SECRET_SHAPES) {
    if (s.re.test(v)) return s.name;
  }

  // Generic fallback: a long, high-entropy, single-token opaque string with
  // no spaces, no path separators and no dots that would make it a hostname.
  if (
    v.length >= 32 &&
    /^[A-Za-z0-9_\-+/=]+$/.test(v) &&
    /[0-9]/.test(v) &&
    /[A-Za-z]/.test(v) &&
    entropy(v) >= 3.6
  ) {
    return 'high_entropy';
  }
  return null;
}

/**
 * A vendor-prefixed token whose body is filler rather than a key.
 *
 * `sk-xxxxxxxxxxxxxxxxxxxx` in a config example matches the openai shape
 * exactly and is not a credential. `secretShape` already refuses placeholders
 * before it ever reaches the shape list; `findSecretsInText` did not, and so a
 * bundled skill documenting an MCP header produced a critical `credential_leak`
 * on a clean install. It is the same asymmetry between the two entry points
 * that `N13` pins on the shape list itself.
 *
 * A run of four identical characters does not occur in a real key of this
 * length -- for a 20-character base62 token the chance is about one in twelve
 * thousand -- and the named fillers never do. `private_key` opts out, because
 * its shape is a literal banner with five dashes in it.
 */
function isFillerToken(match: string): boolean {
  if (isPlaceholder(match)) return true;
  if (/(.)\1{3,}/.test(match)) return true;
  return /(your|example|placeholder|redacted|changeme|dummy|sample|todo|fixme)/i.test(match);
}

/**
 * Find literal credentials inside free text (a prompt file), returning the
 * character offset of each. Used by `credential_leak`.
 */
export function findSecretsInText(
  text: string
): Array<{ index: number; match: string; shape: string }> {
  const out: Array<{ index: number; match: string; shape: string }> = [];
  for (const s of SECRET_SHAPES) {
    eachMatch(new RegExp(s.re.source, 'g'), text, (m) => {
      if (!s.literal && isFillerToken(m[0])) return;
      out.push({ index: m.index, match: m[0], shape: s.name });
    });
  }
  return out.sort((a, b) => a.index - b.index);
}
