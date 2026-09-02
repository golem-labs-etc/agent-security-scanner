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

/**
 * Instruction override: aimed at prior instructions, at the agent's identity,
 * or at its mode.
 *
 * This is the list `prompt_injection` reads visible prose with, and it is
 * deliberately narrower than the list the concealment rules read. Everything
 * here makes a claim about the instructions themselves.
 */
const OVERRIDE_RE: RegExp[] = [
  /\b(?:ignore|disregard|forget|discard|override)\b[^.\n]{0,40}\b(?:all\s+)?(?:previous|prior|above|earlier|preceding|foregoing|former|initial|original|system)\b[^.\n]{0,40}\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions|message|messages|context|guideline|guidelines)\b/i,
  /\b(?:ignore|disregard|bypass|override|circumvent)\b[^.\n]{0,30}\b(?:your|the)\b[^.\n]{0,30}\b(?:system\s+prompt|safety|guardrail|guardrails|restriction|restrictions|policy|policies|guideline|guidelines|constraint|constraints)\b/i,
  /\byou\s+are\s+(?:now|no\s+longer)\b[^.\n]{0,60}/i,
  // `task` and `objective` were in this alternation and came out. "The new task
  // is assigned to the original implementer" is how a work-queue skill is
  // written; it is not an attempt to replace anyone's instructions.
  /\b(?:new|updated|revised|real|true|actual|secret)\s+(?:instruction|instructions|directive|directives|system\s+prompt)\s*(?::|are|is)\b/i,
  /\b(?:enter|enable|activate|switch\s+to)\b[^.\n]{0,20}\b(?:developer|dev|debug|god|unrestricted|jailbreak|dan)\s+mode\b/i,
  /\bend\s+of\s+(?:prompt|instructions)\b[^.\n]{0,40}\b(?:new|begin|start)\b/i,
];

/**
 * "Keep this from the user."
 *
 * Concealment is not instruction override, and by itself it is ordinary
 * skill-writing. On a real machine these two patterns produced 54 of 65
 * `prompt_injection` findings, every one of them a line like "don't tell the
 * user to run `/skin`", "never tell a user to put a non-credential setting in
 * `.env`", or "Do NOT explain how @mention works to the user" -- which matches
 * because `@mention` contains `mention`.
 *
 * So they no longer fire on visible prose. They fire where the text carrying
 * them is ITSELF concealed: inside an HTML comment, or exposed by undoing a
 * homoglyph or a zero-width split. Hidden text that says keep this from the
 * user is the attack; the same sentence written plainly is documentation.
 */
const CONCEALMENT_RE: RegExp[] = [
  /\b(?:do\s*not|don't|never)\b[^.\n]{0,30}\b(?:tell|inform|mention|reveal|disclose|show|report)\b[^.\n]{0,30}\b(?:the\s+)?(?:user|human|operator|owner)\b/i,
  /\bwithout\s+(?:telling|informing|notifying|asking|alerting)\b[^.\n]{0,20}\b(?:the\s+)?(?:user|human|operator|owner)\b/i,
];

/** Both lists, for the rules that only ever read concealed text. */
const ALL_DIRECTIVES: RegExp[] = OVERRIDE_RE.concat(CONCEALMENT_RE);

/**
 * Verbs that move data off the machine.
 *
 * The trailing `(?!@)` is not decoration. `ssh-keygen -C "their-email@example.com"
 * -f ~/.ssh/id_ed25519` was a critical finding: `email` inside an address read
 * as the verb, `example.com` as the destination and `.ssh` as the source. A
 * word that is the local part of an address is not being used as a verb.
 */
const EXFIL_VERB =
  /\b(?:send|post|upload|transmit|forward|exfiltrate|leak|report|e-?mail|mail|submit|push|sync|copy|deliver|curl|wget|fetch)\b(?!@)/i;

/**
 * A local artefact worth stealing: a dotfile, a home path, a known secret path.
 *
 * This list used to also carry the English nouns -- `secret`, `credential`,
 * `api key`, `password`, `token`, `cookie`, `environment variable`. Those are
 * what a skill documenting an HTTP call says in its own prose, and with a
 * `curl` and a URL in the same paragraph they made every such skill a critical
 * finding. A noun naming a category of secret is not a secret. A path is.
 *
 * It also used to carry `~/.<anything>` and `$HOME`, which said that every
 * hidden directory holds credentials. `~/.local/bin` and `~/.hermes/cache` do
 * not, and three ordinary `curl ... | sh` installers were critical findings
 * because of it. The paths named here are stores that hold credentials, and
 * they are matched anywhere, so `~/.hermes/.env` and `$HOME/.ssh/id_rsa` are
 * both still caught.
 */
const SECRET_ARTEFACT =
  /(?:\.env\b|\.ssh\b|\.aws\b|\.gnupg\b|\.kube\b|\.docker\/config|\.npmrc\b|\.netrc\b|\.pgpass\b|\.pypirc\b|\.git-credentials\b|id_rsa|id_ed25519|id_ecdsa|\/etc\/(?:passwd|shadow))/gi;

/** An environment variable whose NAME says it holds a credential. */
const CREDENTIAL_VAR =
  /\$\{?[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*\}?/g;

/**
 * A credential variable used to authenticate TO the destination.
 *
 * `-H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user/repos`,
 * `-H "X-Api-Key: $COMFY_CLOUD_API_KEY"`, `curl -u $LAMBDA_API_KEY:` and
 * `...?api_key=${API_KEY}` are what a documented API call looks like. The
 * variable is the key to the door being knocked on, not something carried out
 * of the building. On a stock install this one shape was 25 of 30 criticals.
 *
 * The exclusion is for credential VARIABLES, and only in those positions:
 * inside the destination URL, after a credential-named header, or as the
 * argument to `curl -u`. A dotfile interpolated into a URL is still
 * exfiltration and still fires, because `id_rsa` is not an authentication
 * parameter.
 *
 * The cost, stated here rather than discovered later: a stolen token sent to an
 * attacker's endpoint in an Authorization header looks exactly like this and is
 * missed. Nothing in the text distinguishes them, and the alternative -- ruling
 * that every documented API call is critical -- is the thing this replaces.
 */
const AUTH_PRECEDES = [
  // Any header whose NAME says it carries a credential: Authorization,
  // X-Api-Key, X-Shopify-Access-Token, Private-Token, apikey. Naming them one
  // at a time is a list that is always one vendor short; naming the property
  // they share is not.
  /\b[A-Za-z0-9-]*?(?:key|token|auth|secret|credential)[A-Za-z0-9-]*\s*:\s*(?:bearer|basic|token)?\s*["']?\s*$/i,
  // HTTP basic auth on the command line: `curl -u $LAMBDA_API_KEY: ...`
  /(?:^|\s)(?:-u|--user)\s+["']?$/,
];

/**
 * A credential variable being copied into another shell variable.
 *
 * `API_KEY="${USDA_API_KEY:-DEMO_KEY}"` moves a credential from one name to
 * another. Nothing leaves the machine, and the later use of `$API_KEY` is
 * judged on its own by the two tests above.
 *
 * The name must be uppercase and must start a word, so this is a shell
 * assignment statement and not a query parameter or a form field:
 * `curl -d "token=$SECRET" ...` and `curl -d "DATA=$API_KEY" ...` are both
 * preceded by a quote rather than by whitespace, and both still fire.
 */
const ASSIGN_PRECEDES = /(?:^|\s)[A-Z][A-Z0-9_]*=["']?$/;

/**
 * How far apart the three signals may be and still be one instruction.
 *
 * Explicit, because the window used to be "one sentence" and `flow` below had
 * quietly made a sentence as long as a paragraph. On a real skill file that
 * paragraph was twenty lines of YAML frontmatter: a `curl` on one key, an
 * "API key" on another and a URL on a third, none of them related, reported as
 * one critical finding at line 1.
 */
const EXFIL_WINDOW = 240;

/**
 * Somewhere off this machine to put it.
 *
 * Loopback is excluded, the same way `unencrypted_transport` excludes it for
 * MCP entries: `curl http://localhost:8644/health` crosses no network and
 * cannot exfiltrate anything. The two rules disagreeing about what "off this
 * machine" means was how a skill's own health check became a critical finding.
 */
const NETWORK_DEST =
  /(?:https?:\/\/(?!(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[?::1\]?)(?:[:\/]|$))[^\s)\]"'<>]+|\bwebhook\b|\bendpoint\b|\bremote\s+server\b|\bmy\s+server\b|\battacker\b|\bexternal\s+(?:url|server|service|api)\b|\b[A-Za-z0-9-]+\.(?:com|net|org|io|dev|sh|xyz|ru|cn|co|me|app|site|link)\b(?:\/[^\s]*)?)/i;

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

/**
 * The full raw source line containing `index`, for evidence that shows a
 * reviewer the surrounding context (a table cell, a quote, a heading) rather
 * than the bare regex match. `m[0]` alone strips exactly the context that
 * marks a documented example as an example -- a skill teaching eval-writing
 * reported `high prompt_injection` on a row reading
 * `| **Adversarial** | "Ignore previous instructions ..." |`, and the evidence
 * recorded only the sentence, so the finding could not be adjudicated without
 * opening the file. Length-capped the same way every other evidence string in
 * this file is.
 *
 * Read from `raw`, not from the masked `prose`/`fenced` copies: those blank
 * code spans out, and blanked context is the thing this exists to restore.
 * Offsets are shared across all three, one character out for one in.
 */
function rawLineAt(src: string, index: number): string {
  const start = src.lastIndexOf('\n', Math.max(0, index - 1)) + 1;
  let end = src.indexOf('\n', index);
  if (end === -1) end = src.length;
  return src.slice(start, end).trim().slice(0, 200);
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
    evidence: string,
    endLine?: number
  ) => {
    const f: RawFinding = {
      category, severity, surface: 'prompt', path: filePath, line, evidence,
    };
    if (endLine !== undefined && endLine !== line) f.endLine = endLine;
    out.push(f);
  };

  // ── prompt_injection ─────────────────────────────────────────────────────
  // Override phrasing only. Concealment phrasing on visible prose is ordinary
  // skill-writing, and it fires below only where the text is itself hidden.
  for (const re of OVERRIDE_RE) {
    const rx = new RegExp(re.source, re.flags.indexOf('g') === -1 ? re.flags + 'g' : re.flags);
    eachMatch(rx, prose, (m) => {
      push('prompt_injection', 'high', lineAt(raw, m.index), rawLineAt(raw, m.index));
    });
  }

  // The same patterns over fenced regions only, reported under the policy.
  for (const re of OVERRIDE_RE) {
    const rx = new RegExp(re.source, re.flags.indexOf('g') === -1 ? re.flags + 'g' : re.flags);
    eachMatch(rx, fenced, (m) => {
      const v = fenceVerdict(policy, 'prompt_injection', 'high');
      push(v.category, v.severity, lineAt(raw, m.index),
           'in fenced block: ' + rawLineAt(raw, m.index));
    });
  }

  // ── hidden_instruction: the reveal test ──────────────────────────────────
  // Runs over the whole file, fences included, and is fence-immune under every
  // policy. A fence renders content visible, which is why it defeats the rules
  // that turn on visibility. It does nothing at all to a homoglyph.
  const canon = canonicalWithMap(raw);
  const seenHidden: Record<string, true> = {};
  for (const re of ALL_DIRECTIVES) {
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
    const directive = firstMatch(ALL_DIRECTIVES, body);
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
  // A verb, a sensitive source and a destination must co-occur inside one
  // window. Any two of the three are ordinary technical writing.
  //
  // `flow` joins a wrapped paragraph into one line, so a sentence split across
  // two lines is still one sentence. One character out for one character in, so
  // every offset still points where it did.
  //
  // It joins a line to the next ONLY when the next line continues running
  // prose. A line that opens a list item, a heading, a table row, a block
  // quote, a fence or a YAML key starts something new. Joining those was how a
  // scan of a stock skill file turned twenty lines of frontmatter into a single
  // "sentence" and reported it as one critical finding at line 1.
  //
  // The test is positive rather than a blacklist of markers: after any indent
  // and an optional opening quote, a continuation line starts with a letter or
  // a digit, and is neither a YAML key nor a numbered item. A blacklist grows
  // one character at a time, and the character it was missing was the tick in a
  // checklist -- three unrelated lines of one, joined, put an "Email" on the
  // first and a `.env` on the third inside the same window.
  const CONTINUES =
    /^[ \t]*(?![A-Za-z_][A-Za-z0-9_.-]*[ \t]*:(?=[ \t]|$)|\d+[.)][ \t])["'(]?[A-Za-z0-9]/;

  // Inside a fence there is no wrapped paragraph. A newline in a shell script
  // ends a statement, and joining across it put the `curl` from one line in the
  // same window as the credential path from the next. The one join a shell does
  // make is a trailing backslash, and that one is honoured, because a malicious
  // multi-line `curl` must not fall between its own arguments.
  const CONTINUES_CODE = /\\$/;

  const flow = (t: string, code: boolean): string => {
    const lines = t.split('\n');
    let out = '';
    for (let k = 0; k < lines.length; k++) {
      out += lines[k];
      if (k === lines.length - 1) continue;
      const join = code
        ? CONTINUES_CODE.test(lines[k])
        : lines[k].length > 0 && CONTINUES.test(lines[k + 1]);
      out += join ? ' ' : '\n';
    }
    return out;
  };
  // A full stop only ends a sentence when whitespace follows it, or the split
  // lands inside `~/.env` and inside every hostname, which is exactly where
  // verb and destination get separated.
  const SENTENCE = /(?:[^\n.!?]|[.!?](?!\s|$))+[.!?]?/g;

  const spansOf = (re: RegExp, s2: string): Range[] => {
    const out2: Range[] = [];
    eachMatch(re, s2, (m) => out2.push([m.index, m.index + m[0].length]));
    return out2;
  };

  /**
   * The narrowest span in which a verb, a sensitive source and a destination
   * all occur, or null.
   *
   * It returns the span rather than a boolean so the finding can name the lines
   * it actually covers. The old rule reported the line the containing sentence
   * began on, which after `flow` was the line the containing paragraph began
   * on, which sent every reader to the wrong place in the file.
   */
  const exfilSpan = (sent: string): Range | null => {
    const verbs = spansOf(EXFIL_VERB, sent);
    if (!verbs.length) return null;
    const dests = spansOf(NETWORK_DEST, sent);
    if (!dests.length) return null;

    const sources: Range[] = spansOf(SECRET_ARTEFACT, sent);
    for (const c of spansOf(CREDENTIAL_VAR, sent)) {
      let auth = false;
      for (const d of dests) if (c[0] >= d[0] && c[1] <= d[1]) auth = true;
      if (auth) continue;
      const before = sent.slice(Math.max(0, c[0] - 60), c[0]);
      let auth2 = false;
      for (const re of AUTH_PRECEDES) if (re.test(before)) auth2 = true;
      if (auth2) continue;
      if (ASSIGN_PRECEDES.test(before)) continue;
      sources.push(c);
    }
    if (!sources.length) return null;

    let best: Range | null = null;
    for (const v of verbs) {
      for (const src of sources) {
        for (const d of dests) {
          const lo = Math.min(v[0], src[0], d[0]);
          const hi = Math.max(v[1], src[1], d[1]);
          if (hi - lo > EXFIL_WINDOW) continue;
          if (!best || hi - lo < best[1] - best[0]) best = [lo, hi];
        }
      }
    }
    return best;
  };

  const scanExfil = (region: string, insideFence: boolean) => {
    eachMatch(SENTENCE, flow(region, insideFence), (m) => {
      const sent = m[0];
      if (sent.trim().length < 12) return;
      const span = exfilSpan(sent);
      if (!span) return;
      const from = m.index + span[0];
      const to = m.index + span[1];
      const text = raw.slice(from, to).replace(/\s+/g, ' ').trim().slice(0, 160);
      const line = lineAt(raw, from);
      const endLine = lineAt(raw, Math.max(from, to - 1));
      if (insideFence) {
        const v = fenceVerdict(policy, 'exfiltration_instruction', 'critical');
        push(v.category, v.severity, line, 'in fenced block: ' + text, endLine);
      } else {
        push('exfiltration_instruction', 'critical', line, text, endLine);
      }
    });
  };

  scanExfil(prose, false);
  scanExfil(fenced, true);

  // ── credential_leak (whole file) ─────────────────────────────────────────
  // A live key inside a fence is still a live key.
  for (const hit of findSecretsInText(raw)) {
    push('credential_leak', 'critical', lineAt(raw, hit.index), hit.shape + ' credential');
  }

  return out;
}
