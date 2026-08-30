/**
 * Text primitives for prompt-surface detection.
 *
 * Two things here carry the weight of the whole prompt ruleset:
 *
 * 1. `maskCode` — fenced and inline code is blanked before the *instruction*
 *    rules run. Without it a scanner cannot read its own threat documentation
 *    without alarming on it, and a security tool that screams at the security
 *    docs gets uninstalled. Blanking preserves length and newlines so every
 *    reported line number still points at the real line.
 *
 * 2. `foldConfusables` — NFKC does NOT fold Cyrillic and Greek homoglyphs.
 *    They are distinct characters, not compatibility forms, so `'о'`
 *    (Cyrillic o) survives `.normalize('NFKC')` unchanged. Detection therefore
 *    needs an explicit mapping. Note this is a *detection* aid only. A
 *    confusable table is a fair thing to fold for "does this look like the
 *    word ignore"; it is never a safe thing to put on a security boundary,
 *    because folding is lossy and two distinct inputs collapse to one.
 */

/**
 * Iterate every match of a global regex.
 *
 * `String.prototype.matchAll` needs ES2020 and this package targets ES2018,
 * so the exec loop is written out. The `lastIndex` guard is not optional:
 * a pattern that can match empty spins forever without it.
 */
export function eachMatch(
  re: RegExp,
  s: string,
  fn: (m: RegExpExecArray) => void
): void {
  const rx = re.global ? re : new RegExp(re.source, re.flags + 'g');
  rx.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(s)) !== null) {
    fn(m);
    if (m.index === rx.lastIndex) rx.lastIndex++;
  }
}

/** Characters that are present to the parser and absent to the reader. */
export const ZERO_WIDTH = [
  '​', // zero width space
  '‌', // zero width non-joiner
  '‍', // zero width joiner
  '⁠', // word joiner
  '﻿', // zero width no-break space / BOM
  '­', // soft hyphen
  '᠎', // mongolian vowel separator
  '‎', // left-to-right mark
  '‏', // right-to-left mark
  '‪', '‫', '‬', '‭', '‮', // bidi embedding/override
  '⁦', '⁧', '⁨', '⁩', // bidi isolates
];

export const ZERO_WIDTH_RE = new RegExp('[' + ZERO_WIDTH.join('') + ']', 'g');

/**
 * Cyrillic and Greek characters that render as Latin letters.
 *
 * Deliberately explicit rather than derived from a Unicode confusables file:
 * the set that matters for hiding an English directive word is small, and a
 * table we can read is a table we can audit.
 */
export const CONFUSABLES: Record<string, string> = {
  // Cyrillic lowercase
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
  'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's', 'ј': 'j',
  'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w',
  'ѵ': 'v', 'ɡ': 'g',
  // Cyrillic uppercase
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
  'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
  'У': 'Y', 'Х': 'X', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
  // Greek lowercase
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i',
  'ν': 'v', 'υ': 'u', 'κ': 'k', 'τ': 't', 'ϲ': 'c',
  'ϳ': 'j', 'η': 'n',
  // Greek uppercase
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H',
  'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
  'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
};

const CONFUSABLE_RE = new RegExp(
  '[' + Object.keys(CONFUSABLES).join('') + ']',
  'g'
);

/** True when the string contains at least one Cyrillic or Greek homoglyph. */
export function hasConfusable(s: string): boolean {
  CONFUSABLE_RE.lastIndex = 0;
  return CONFUSABLE_RE.test(s);
}

/** Map Cyrillic/Greek homoglyphs onto the Latin letters they imitate. */
export function foldConfusables(s: string): string {
  return s.replace(CONFUSABLE_RE, (c) => CONFUSABLES[c] || c);
}

/** Strip zero-width and bidi controls. */
export function stripInvisible(s: string): string {
  ZERO_WIDTH_RE.lastIndex = 0;
  return s.replace(ZERO_WIDTH_RE, '');
}

/**
 * What a directive word looks like once the hiding is undone.
 * NFKC first (real compatibility forms), then the explicit homoglyph map,
 * then invisibles, then case.
 */
export function canonical(s: string): string {
  return foldConfusables(stripInvisible(s.normalize('NFKC'))).toLowerCase();
}

/** Replace a run with spaces, preserving newlines so line numbers survive. */
function blank(s: string): string {
  return s.replace(/[^\n]/g, ' ');
}

/**
 * Blank out fenced blocks, indented code blocks and inline code spans.
 *
 * Fenced content is visible verbatim to a human reader in every markdown
 * renderer, so by definition it is not "hidden", and quoting an attack in a
 * fence is what documentation is for. Offsets and line numbers are preserved
 * exactly, so a finding outside a fence still reports its true line.
 */
export function maskCode(src: string): string {
  let out = src;
  // Fenced blocks: ``` or ~~~ , optional info string, to the closing fence
  // or to end of file if the author never closed it.
  out = out.replace(/^([ \t]*)(`{3,}|~{3,})[^\n]*\n([\s\S]*?)(^[ \t]*\2[^\n]*$|$)/gm,
    (m) => blank(m));
  // Inline code spans, single or multiple backticks, not spanning a blank line.
  out = out.replace(/(`+)(?:(?!\1)[\s\S])*?\1/g, (m) => blank(m));
  // Indented code blocks: four leading spaces or a tab, on a line that is not
  // inside a list continuation we can cheaply tell apart. Conservative: only
  // when the previous line is blank.
  out = out.replace(/(^|\n)[ \t]*\n((?:(?: {4}|\t)[^\n]*\n?)+)/g,
    (m, pre, body) => pre + '\n' + blank(body));
  return out;
}

/** 1-based line number of a character offset. */
export function lineAt(src: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < src.length; i++) {
    if (src.charCodeAt(i) === 10) line++;
  }
  return line;
}
