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
    if (s.name === 'private_key') {
      // The BEGIN banner is documentation's shape as much as a key's; the
      // signal is the body between the banners (see privateKeyBodyIsReal).
      const m = new RegExp(s.re.source).exec(v);
      if (m && privateKeyBodyIsReal(v.slice(m.index))) return s.name;
      continue;
    }
    if (s.re.test(v)) return s.name;
  }

  // Generic fallback: a long, high-entropy, single-token opaque string with
  // no spaces, no path separators and no dots that would make it a hostname.
  if (
    v.length >= 32 &&
    /^[A-Za-z0-9_\-+/=]+$/.test(v) &&
    /[0-9]/.test(v) &&
    /[A-Za-z]/.test(v) &&
    !GENERIC_PLACEHOLDER_WORD.test(v) &&
    entropy(v) >= ENTROPY_FLOOR * Math.log2(v.length)
  ) {
    return 'high_entropy';
  }
  return null;
}

/**
 * The generic high-entropy rule's threshold, set by measurement (#37).
 *
 * It is LENGTH-NORMALIZED — `entropy >= K * log2(len)` — because Shannon
 * entropy is capped by `log2(len)`, so a flat bits threshold punishes short
 * tokens: a real 32-char base62 key floors near 3.82 bits while a 52-char one
 * clears 4.5, and a flat cut that spares the short key barely clears the false
 * positive.
 *
 * Measured across the real 366-file MCP-config corpus (417 env values, 5 that
 * reach this rule): the only value below ~4.85 was the reported false positive
 * `ghp_FAKE_TOKEN_FOR_TESTING_ONLY_00000000` at 3.759 bits (normalized 0.706).
 * Synthetic real-shaped tokens (n=3000 per length, base62/base64url/base64,
 * run-ending variants) floor at normalized 0.764 (base62, 32 chars). So K=0.72
 * sits between: the FP is below by 0.014 normalized, the worst real token above
 * by 0.044. That lower margin is thin — which is why the word gate below is a
 * second, independent gate on this exact class, per the issue.
 *
 * Hex-charset tokens normalize to ~0.59 and are already below any workable
 * threshold; they were missed before this change too, and closing that
 * false negative is a separate question this change does not touch.
 */
const ENTROPY_FLOOR = 0.72;

/**
 * A placeholder word inside an otherwise credential-shaped token. The reported
 * FP carries FAKE and TESTING; a real random token effectively never contains
 * these as substrings. Independent of entropy, so the thin normalized margin
 * on the FP side cannot let it through.
 */
const GENERIC_PLACEHOLDER_WORD = /(fake|testing|mock|dummy|sample|example|placeholder|not[-_]?real)/i;

/**
 * A PEM private-key banner is real only when a credential-shaped body sits
 * between BEGIN and END (#42). A real key carries a long base64 run; docs
 * carry `...`, `\n...\n`, nothing, or a placeholder word. Both encodings are
 * handled: a literal multiline PEM and the JSON-escaped single-line form where
 * newlines are the two characters backslash-n.
 *
 * Floor set by measuring the smallest real key: an Ed25519 PKCS#8 body is 64
 * base64 characters; the documentation bodies strip to 0-11. `>= 40` with an
 * entropy floor sits between with margin, and admits Ed25519, EC and RSA alike.
 */
function privateKeyBodyIsReal(fromBegin: string): boolean {
  // A real key has a MATCHING END banner. A prose mention of the BEGIN banner
  // ("the private key starts with -----BEGIN...-----") has none, and without
  // this guard the body would sweep the rest of the document, whose ordinary
  // words survive the base64 filter and pass the length floor (#42 regression
  // found on oraclecloud-install-auth: 128 chars of markdown table text).
  const end = fromBegin.slice(0, 8000).search(/-----\s*END[^-]*-----/i);
  if (end === -1) return false;

  const between = fromBegin.slice(0, end).replace(/^-----BEGIN[^-]*-----/i, '');
  // The body between the banners is base64 lines and nothing else. Require it
  // to be PREDOMINANTLY base64 once whitespace (real `\n` or the escaped `\n`)
  // is removed: a real PEM is ~100%, `...` and prose are far below.
  const nonSpace = between.replace(/\s/g, '').replace(/\\n/g, '');
  const body = nonSpace.replace(/[^A-Za-z0-9+/=]/g, '');
  if (!nonSpace.length) return false;
  const base64Ratio = body.length / nonSpace.length;
  return body.length >= 40 && base64Ratio >= 0.9 && entropy(body) >= 3.5;
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
 * thousand -- and the named fillers never do.
 *
 * `private_key` no longer routes through here at all. It used to be exempt
 * (its shape is a banner with five dashes, which the run detector would have
 * suppressed), and that blanket exemption is exactly why every documented
 * `-----BEGIN ... PRIVATE KEY-----` fired (#42). It is now gated on its BODY
 * instead -- see privateKeyBodyIsReal -- in both entry points, so the banner
 * alone is not a leak and a real key still is.
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
      if (s.name === 'private_key') {
        // Gate on the body between the banners, not the banner alone (#42).
        if (!privateKeyBodyIsReal(text.slice(m.index))) return;
      } else if (!s.literal && isFillerToken(m[0])) {
        return;
      }
      out.push({ index: m.index, match: m[0], shape: s.name });
    });
  }
  return out.sort((a, b) => a.index - b.index);
}
