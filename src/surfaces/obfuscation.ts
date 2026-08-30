/**
 * `obfuscated_text`: text is deliberately concealed.
 *
 * Deliberately separate from `hidden_instruction`, because they make two
 * different claims. `hidden_instruction` says *the hidden text says something
 * bad* -- it reads the payload, so its recall is bounded by a phrase list.
 * This says *text is hidden*, and depends on no phrase list at all. Keeping
 * them apart means the false-positive data says which signal is noisy, rather
 * than averaging the two together.
 *
 * All three signals are fence-immune. A code fence renders content visible to
 * a human, which is why it defeats the rules that turn on visibility -- but it
 * does nothing whatever to a homoglyph or a zero-width split. Documentation
 * quotes attack text; it never needs to reproduce the hiding. A real security
 * page describes the homoglyph technique in prose rather than smuggling a live
 * U+200B into its example.
 */

import { eachMatch, lineAt } from './text';

export interface ObfuscationHit {
  index: number;
  line: number;
  /** Names the signal, never the concealed text. */
  evidence: string;
}

/**
 * Signal 1: a zero-width character wedged between two ASCII letters.
 *
 * The "between two ASCII letters" framing is what makes this safe, and it is
 * load-bearing rather than incidental:
 *
 *   - ZWNJ (U+200C) is a real letter-joining control in Persian and Hindi, but
 *     it sits between Arabic or Devanagari letters, never between two ASCII
 *     ones.
 *   - ZWJ (U+200D) builds emoji sequences, and it sits between emoji.
 *   - U+FEFF as a byte-order mark sits at offset 0, where by definition it has
 *     no preceding letter.
 *
 * U+00AD (soft hyphen) is excluded outright. It legitimately turns up inside
 * words in text pasted out of Word and out of some PDF extractors, which is
 * exactly the "one false critical on an ordinary document" case that gets a
 * scanner uninstalled. It stays in the reveal test, where it is harmless.
 */
const ZW_BETWEEN_LETTERS = /[A-Za-z][​‌‍﻿][A-Za-z]/g;

/**
 * Signal 3: bidirectional control characters, anywhere in a prompt file.
 *
 * This is Trojan Source, CVE-2021-42574. The characters reorder how text is
 * displayed without changing what the parser reads, so what a reviewer sees
 * and what the agent consumes can be made to differ arbitrarily. Published,
 * named, and with no benign use in a prompt file.
 */
const BIDI_CONTROLS = /[‪-‮⁦-⁩]/g;

/** Cyrillic and Greek letter blocks, for the mixed-script signal. */
function isCyrillicOrGreek(ch: string): boolean {
  const c = ch.charCodeAt(0);
  return (
    (c >= 0x0370 && c <= 0x03ff) || // Greek and Coptic
    (c >= 0x1f00 && c <= 0x1fff) || // Greek Extended
    (c >= 0x0400 && c <= 0x04ff) || // Cyrillic
    (c >= 0x0500 && c <= 0x052f)    // Cyrillic Supplement
  );
}

function isAsciiLetter(ch: string): boolean {
  return /[A-Za-z]/.test(ch);
}

/**
 * Signal 2: a Cyrillic or Greek character inside an otherwise Latin word.
 *
 * A whole Russian sentence has words that are entirely Cyrillic, so its Latin
 * count is zero and nothing fires. What fires is `Ignоre` -- five Latin
 * letters and one Cyrillic `о` -- which no keyboard produces by accident.
 *
 * The word must be at least three characters and the Latin letters must
 * outnumber the foreign ones, so a genuinely mixed-script token is not
 * mistaken for a disguised Latin one.
 */
function mixedScriptWords(text: string): ObfuscationHit[] {
  const out: ObfuscationHit[] = [];
  let start = -1;

  const flush = (end: number) => {
    if (start < 0) return;
    const word = text.slice(start, end);
    if (word.length >= 3) {
      let latin = 0;
      let foreign = 0;
      for (const ch of word) {
        if (isAsciiLetter(ch)) latin++;
        else if (isCyrillicOrGreek(ch)) foreign++;
      }
      if (foreign >= 1 && latin >= 2 && latin > foreign) {
        out.push({
          index: start,
          line: lineAt(text, start),
          evidence:
            'mixed-script word: ' + latin + ' latin, ' + foreign +
            ' cyrillic/greek, length ' + word.length,
        });
      }
    }
    start = -1;
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const isWordChar = isAsciiLetter(ch) || isCyrillicOrGreek(ch);
    if (isWordChar) {
      if (start < 0) start = i;
    } else {
      flush(i);
    }
  }
  flush(text.length);
  return out;
}

/**
 * Every obfuscation signal over a whole prompt file.
 *
 * Evidence names the signal and counts characters. It never reproduces the
 * concealed text, so passing this to `--evidence` still cannot deliver a
 * payload into anyone's context.
 */
export function findObfuscation(raw: string): ObfuscationHit[] {
  const out: ObfuscationHit[] = [];

  eachMatch(ZW_BETWEEN_LETTERS, raw, (m) => {
    // A byte-order mark at offset 0 cannot be between two letters, but assert
    // it rather than relying on the regex to imply it.
    if (m.index === 0) return;
    out.push({
      index: m.index,
      line: lineAt(raw, m.index),
      evidence: 'zero-width character between two ascii letters',
    });
  });

  eachMatch(BIDI_CONTROLS, raw, (m) => {
    out.push({
      index: m.index,
      line: lineAt(raw, m.index),
      evidence:
        'bidirectional control character U+' +
        m[0].charCodeAt(0).toString(16).toUpperCase() +
        ' (trojan source, CVE-2021-42574)',
    });
  });

  out.push(...mixedScriptWords(raw));

  return out.sort((a, b) => a.index - b.index);
}
