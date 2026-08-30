/**
 * Rules for prompt files (SKILL.md and friends).
 *
 * These are prompt rules, not code rules. semgrep is never run on them.
 *
 * Two decisions shape everything below.
 *
 * **Instruction rules read prose only.** Fenced and inline code is blanked
 * first (`maskCode`). Fenced content is rendered verbatim to a human in every
 * markdown viewer, so quoting an attack in a fence is documentation, not an
 * attack. Without this a security skill cannot describe the thing it defends
 * against without tripping its own scanner, and that is not shippable.
 *
 * **`hidden_instruction` is a reveal test, not a character blacklist.** It
 * fires when undoing the obfuscation exposes a directive that the raw bytes
 * did not contain. Blacklisting zero-width characters outright would fire on
 * every emoji ZWJ sequence and every BOM; asking "did hiding change the
 * meaning" fires on exactly the attack and nothing else.
 */

import { Finding, Category, Severity, Policy } from './types';
import { RawFinding } from './mcp-rules';
import {
  eachMatch, lineAt, stripInvisible, foldConfusables, hasConfusable,
  codeRanges, maskRanges, inRanges, Range,
} from './text';
import { findObfuscation } from './obfuscation';
import { findSecretsInText } from './secrets';

// ── directive vocabulary ───────────────────────────────────────────────────

/** Instruction-override phrasing aimed at the agent. */
const DIRECTIVE_RE: RegExp[] = [
  /\b(?:ignore|disregard|forget|discard|override)\b[^.\n]{0,40}\b(?:all\s+)?(?:previous|prior|above|earlier|preceding|foregoing|former|initial|original|system)\b[^.\n]{0,40}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|message|messages|context|guideline|guidelines)\b/i,
  /\b(?:ignore|disregard|bypass|override|circumvent)\b[^.\n]{0,30}\b(?:your|the)\b[^.\n]{0,30}\b(?:system\s+prompt|safety|guardrail|guardrails|restriction|restrictions|policy|policies|guideline|guidelines|constraint|constraints)\b/i,
  /\byou\s+are\s+(?:now|no\s+longer)\b[^.\n]{0,60}/i,
  /\b(?:new|updated|revised|real|true|actual|secret)\s+(?:instruction|instructions|directive|directives|task|objective|system\s+prompt)\s*(?::|are|is)\b/i,
  /\b(?:do\s*not|don't|never)\b[^.\n]{0,30}\b(?:tell|inform|mention|reveal|disclose|show|report)\b[^.\n]{0,30}\b(?:the\s+)?(?:user|human|operator|owner)\b/i,
  /\bwithout\s+(?:telling|informing|notifying|asking|alerting)\b[^.\n]{0,20}\b(?:the\s+)?(?:user|human|operator|owner)\b/i,
  /\b(?:enter|enable|activate|switch\s+to)\b[^.\n]{0,20}\b(?:developer|dev|debug|god|unrestricted|jailbreak|dan)\s+mode\b/i,
  /\bend\s+of\s+(?:prompt|instructions)\b[^.\n]{0,40}\b(?:new|begin|start)\b/i,
];

/** Verbs that move data off the machine. */
const EXFIL_VERB =
  /\b(?:send|post|upload|transmit|forward|exfiltrate|leak|report|email|mail|submit|push|sync|copy|deliver|curl|wget|fetch|POST)\b/i;

/** Things on this machine worth stealing. */
const LOCAL_DATA =
  /(?:~\/\.[A-Za-z0-9_.-]+|\$HOME|\$\{?[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*\}?|\bdotfile|\bdot-file|\.env\b|\.ssh\b|id_rsa|id_ed25519|\.aws\b|\.npmrc\b|\.netrc\b|\/etc\/passwd|\bcredential|\bapi[\s_-]?key|\benv(?:ironment)?\s+variable|\baccess\s+token|\bsecret|\bpassword|\bprivate\s+key|\bsession\s+token|\bcookie)/i;

/** Somewhere off this machine to put it. */
const NETWORK_DEST =
  /(?:https?:\/\/[^\s)\]"'<>]+|\bwebhook\b|\bendpoint\b|\bremote\s+server\b|\bmy\s+server\b|\battacker\b|\bexternal\s+(?:url|server|service|api)\b|\b[A-Za-z0-9-]+\.(?:com|net|org|io|dev|sh|xyz|ru|cn|co|me|app|site|link)\b(?:\/[^\s]*)?)/i;

/** Imperative verbs, for the HTML-comment rule. */
const IMPERATIVE_VERB =
  /\b(?:ignore|disregard|forget|send|post|upload|run|execute|exec|fetch|curl|wget|delete|remove|read|output|print|reply|respond|append|include|add|install|download|must|always|never|do\s+not|don't)\b/i;

/** Something that indicates the text is addressed to the model. */
const AGENT_REF =
  /\b(?:you|your|yourself|assistant|agent|claude|gpt|chatgpt|llm|model|ai|system)\b/i;

// ── helpers ────────────────────────────────────────────────────────────────

/**
 * De-obfuscate while keeping a map back to raw offsets, so a finding can still
 * name the line it came from after the string has changed length.
 */
function canonicalWithMap(raw: string): { text: string; map: number[] } {
  let text = '';
  const map: number[] = [];
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    const stripped = stripInvisible(ch);
    if (!stripped) continue; // invisible: dropped, contributes no output char
    const folded = foldConfusables(stripped.normalize('NFKC')).toLowerCase();
    for (let j = 0; j < folded.length; j++) {
      text += folded[j];
      map.push(i);
    }
  }
  return { text, map };
}

function firstMatch(res: RegExp[], s: string): RegExpExecArray | null {
  for (const re of res) {
    const rx = new RegExp(re.source, re.flags.replace('g', ''));
    const m = rx.exec(s);
    if (m) return m as RegExpExecArray;
  }
  return null;
}

/** Normalize a CSS colour to a comparable token. */
function normColour(v: string): string {
  let c = v.trim().toLowerCase().replace(/\s+/g, '');
  const named: Record<string, string> = {
    white: '#ffffff', black: '#000000', transparent: 'transparent',
  };
  if (named[c]) c = named[c];
  const short = /^#([0-9a-f])([0-9a-f])([0-9a-f])$/.exec(c);
  if (short) c = '#' + short[1] + short[1] + short[2] + short[2] + short[3] + short[3];
  const rgb = /^rgba?\((\d+),(\d+),(\d+)(?:,([\d.]+))?\)$/.exec(c);
  if (rgb) {
    if (rgb[4] !== undefined && parseFloat(rgb[4]) === 0) return 'transparent';
    const hex = (n: string) => ('0' + parseInt(n, 10).toString(16)).slice(-2);
    c = '#' + hex(rgb[1]) + hex(rgb[2]) + hex(rgb[3]);
  }
  return c;
}

/** Does this style declaration render its text invisible to a human? */
function styleHides(style: string): boolean {
  const s = style.toLowerCase().replace(/\s+/g, '');
  if (/display:none/.test(s)) return true;
  if (/visibility:hidden/.test(s)) return true;
  if (/opacity:0(?:\.0+)?(?:;|$|[^.\d])/.test(s)) return true;
  if (/font-size:0(?:px|em|rem|pt)?(?:;|$)/.test(s)) return true;
  if (/(?:^|;)(?:height|width):0(?:px)?(?:;|$)/.test(s)) return true;
  if (/color:transparent/.test(s)) return true;
  if (/text-indent:-\d{4,}/.test(s)) return true;

  const fg = /(?:^|;)color:([^;]+)/.exec(s);
  const bg = /(?:^|;)background(?:-color)?:([^;]+)/.exec(s);
  if (fg && bg) {
    const a = normColour(fg[1]);
    const b = normColour(bg[1]);
    // A background shorthand may carry more than a colour; take the first token.
    const bFirst = normColour(bg[1].split(/[,)]/)[0]);
    if (a === b || a === bFirst) return true;
  }
  return false;
}

// ── the ruleset ────────────────────────────────────────────────────────────

/**
 * Does this span carry concealment that a code fence does not defeat?
 *
 * Precedence rule, and the reason it is a separate check rather than a side
 * effect of rule ordering: concealed characters are evaluated independently of
 * the fence policy, and they win. A homoglyph inside an HTML comment inside a
 * fence is still concealed -- the fence made the *comment* visible, and did
 * nothing at all to the homoglyph. So the downgrade path must not be able to
 * swallow it.
 *
 * Soft hyphen is excluded for the same reason it is excluded from
 * `obfuscated_text`: it turns up inside ordinary words pasted out of a word
 * processor.
 */
function concealedInSpan(s: string): boolean {
  return hasConfusable(s) || /[\u200B\u200C\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/.test(s);
}

/**
 * How a directive found inside a code fence is reported.
 *
 * `balanced` downgrades it to `fenced_directive` at medium. Not info: info is
 * where `unpinned_remote_exec` lives, and that is genuinely benign. A directive
 * in a fence is not benign, it is unproven, and the severity should say so.
 *
 * `strict` reports it as what it is. Part B passes strict, because an agent
 * consuming raw markdown never sees the fence.
 */
function fenceVerdict(
  policy: Policy,
  original: Category,
  originalSeverity: Severity
): { category: Category; severity: Severity } {
  if (policy === 'strict') {
    return { category: original, severity: originalSeverity };
  }
  return { category: 'fenced_directive', severity: 'medium' };
}

export function scanPromptFile(
  filePath: string,
  raw: string,
  policy: Policy = 'balanced'
): RawFinding[] {
  const out: RawFinding[] = [];

  // One range set, two exact complements. A directive cannot fall through the
  // gap between "prose" and "the fenced part" because there is no gap.
  const ranges: Range[] = codeRanges(raw);
  const prose = maskRanges(raw, ranges, false);
  const fenced = maskRanges(raw, ranges, true);

  const push = (
    category: Category,
    severity: Severity,
    line: number,
    evidence: string
  ) => {
    out.push({ category, severity, surface: 'prompt', path: filePath, line, evidence });
  };

  // ── prompt_injection ─────────────────────────────────────────────────────
  for (const re of DIRECTIVE_RE) {
    const rx = new RegExp(re.source, re.flags.indexOf('g') === -1 ? re.flags + 'g' : re.flags);
    eachMatch(rx, prose, (m) => {
      push('prompt_injection', 'high', lineAt(raw, m.index), m[0].trim());
    });
  }

  // The same patterns over fenced regions only, reported under the policy.
  for (const re of DIRECTIVE_RE) {
    const rx = new RegExp(re.source, re.flags.indexOf('g') === -1 ? re.flags + 'g' : re.flags);
    eachMatch(rx, fenced, (m) => {
      const v = fenceVerdict(policy, 'prompt_injection', 'high');
      push(v.category, v.severity, lineAt(raw, m.index),
           'in fenced block: ' + m[0].trim());
    });
  }

  // ── hidden_instruction: the reveal test ──────────────────────────────────
  // Runs over the whole file, fences included, and is fence-immune under every
  // policy. A fence renders content visible, which is why it defeats the rules
  // that turn on visibility. It does nothing at all to a homoglyph.
  const canon = canonicalWithMap(raw);
  const seenHidden: Record<string, true> = {};
  for (const re of DIRECTIVE_RE) {
    const rx = new RegExp(re.source, re.flags.indexOf('g') === -1 ? re.flags + 'g' : re.flags);
    eachMatch(rx, canon.text, (m) => {
      const from = canon.map[m.index];
      const toIdx = m.index + m[0].length - 1;
      const to = canon.map[Math.min(toIdx, canon.map.length - 1)];
      if (from === undefined || to === undefined) return;
      const rawSpan = raw.slice(from, to + 1);
      const plain = new RegExp(re.source, re.flags.replace('g', ''));
      if (plain.test(rawSpan)) return; // visible as written; not hidden

      const line = lineAt(raw, from);
      const key = String(line) + ':' + m[0];
      if (seenHidden[key]) return;
      seenHidden[key] = true;
      push('hidden_instruction', 'critical', line,
           'obfuscated directive: ' + m[0].trim());
    });
  }

  // ── hidden_instruction: HTML comments carrying agent-directed imperatives ─
  //
  // This shape and the CSS one below conceal by *rendering*, and a code fence
  // defeats that concealment: a comment quoted in a fence is displayed to the
  // reader like any other line. So these two follow the fence policy, while the
  // reveal test above does not. That split is deliberate. Without it a security
  // page cannot show what a hidden-comment payload looks like, which is the
  // single most likely thing such a page contains, and N3/N6 fail.
  eachMatch(/<!--([\s\S]*?)-->/g, raw, (m) => {
    const body = m[1];
    const directive = firstMatch(DIRECTIVE_RE, body);
    const exfil = EXFIL_VERB.test(body) && NETWORK_DEST.test(body);
    const addressed = AGENT_REF.test(body) && IMPERATIVE_VERB.test(body);
    if (!(directive || exfil || addressed)) return;

    const evidence = 'html comment: ' + body.trim().slice(0, 120);
    // Concealed characters win. A fence renders the comment visible; it does
    // not render a homoglyph or a zero-width split visible, so that part of the
    // concealment survives and the finding stays critical under every policy.
    if (inRanges(ranges, m.index) && !concealedInSpan(m[0])) {
      const v = fenceVerdict(policy, 'hidden_instruction', 'critical');
      push(v.category, v.severity, lineAt(raw, m.index), 'in fenced block: ' + evidence);
    } else {
      push('hidden_instruction', 'critical', lineAt(raw, m.index), evidence);
    }
  });

  // ── hidden_instruction: HTML styled to be unreadable ─────────────────────
  eachMatch(/<([a-z][a-z0-9]*)\b[^>]*\bstyle\s*=\s*("([^"]*)"|'([^']*)')[^>]*>/gi, raw, (m) => {
    const style = m[3] !== undefined ? m[3] : (m[4] || '');
    if (!styleHides(style)) return;

    const evidence = 'hidden html <' + m[1] + ' style="' + style.trim().slice(0, 80) + '">';
    if (inRanges(ranges, m.index) && !concealedInSpan(m[0])) {
      const v = fenceVerdict(policy, 'hidden_instruction', 'critical');
      push(v.category, v.severity, lineAt(raw, m.index), 'in fenced block: ' + evidence);
    } else {
      push('hidden_instruction', 'critical', lineAt(raw, m.index), evidence);
    }
  });

  // ── obfuscated_text ──────────────────────────────────────────────────────
  // Independent of the phrase list, and fence-immune under every policy.
  for (const hit of findObfuscation(raw)) {
    push('obfuscated_text', 'high', hit.line, hit.evidence);
  }

  // ── exfiltration_instruction ─────────────────────────────────────────────
  // Verb, local data and destination must co-occur inside one sentence. Any
  // two of the three are ordinary technical writing.
  //
  // A wrapped markdown paragraph is one sentence, not four. Single newlines
  // become spaces first -- one character for one character, so every offset
  // still points where it did. A full stop only ends a sentence when
  // whitespace follows it, or the split lands inside `~/.env` and inside every
  // hostname, which is exactly where verb and destination get separated.
  const flow = (t: string) => t.replace(/([^\n])\n(?![ \t]*\n)/g, '$1 ');
  const SENTENCE = /(?:[^\n.!?]|[.!?](?!\s|$))+[.!?]?/g;

  eachMatch(SENTENCE, flow(prose), (m) => {
    const sent = m[0];
    if (sent.trim().length < 12) return;
    if (EXFIL_VERB.test(sent) && LOCAL_DATA.test(sent) && NETWORK_DEST.test(sent)) {
      push('exfiltration_instruction', 'critical', lineAt(raw, m.index),
           sent.trim().slice(0, 160));
    }
  });

  eachMatch(SENTENCE, flow(fenced), (m) => {
    const sent = m[0];
    if (sent.trim().length < 12) return;
    if (EXFIL_VERB.test(sent) && LOCAL_DATA.test(sent) && NETWORK_DEST.test(sent)) {
      const v = fenceVerdict(policy, 'exfiltration_instruction', 'critical');
      push(v.category, v.severity, lineAt(raw, m.index),
           'in fenced block: ' + sent.trim().slice(0, 160));
    }
  });

  // ── credential_leak (whole file) ─────────────────────────────────────────
  // A live key inside a fence is still a live key.
  for (const hit of findSecretsInText(raw)) {
    push('credential_leak', 'critical', lineAt(raw, hit.index), hit.shape + ' credential');
  }

  return out;
}
