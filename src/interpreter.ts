/**
 * The interpreter: per-finding interpretation on the user's own key.
 *
 * `--ai` used to run a generic semantic pass. This asks one bounded question
 * about one finding an engine already produced, and its answer is commentary
 * beside that finding, never a replacement for it.
 *
 * THE RULE THAT GOVERNS EVERY LINE HERE:
 *
 *   ENGINES OUTRANK INTERPRETATION. The interpreter can lower its own
 *   confidence. It can never remove a finding, change its severity, or change
 *   the verdict line's claims. A deterministic engine matched a pattern in the
 *   user's code; a model's opinion about that match is a second opinion, and
 *   the report says which layer said what.
 *
 * That is not deference for its own sake. The model is reading attacker-authored
 * code, so an interpreter that could suppress findings would be a suppression
 * channel reachable from the scanned repository. `applyInterpretations` is
 * where this is enforced, and tests/interpreter.js asserts it directly.
 */

import axios from 'axios';
import * as fs from 'fs';
import { resolveProvider, resolveApiKey } from './env-key';
import { fenceBlock, makeNonce, AUTHORITY_RULE } from './prompt-armor';
import { renderField, renderPath, escapeControls } from './render-safe';

export type Triage = 'looks_real' | 'likely_false_positive' | 'needs_human';

export type Interpretation = {
  explanation: string;
  triage: Triage;
  /** A unified diff, rendered and never applied. Null when none was offered. */
  suggested_fix: string | null;
  /** Provider-reported token usage. Never estimated. Null when unreported. */
  usage: { input: number; output: number } | null;
  /** Why this finding was not sent, when it was not. */
  skipped?: string;
};

const TRIAGE_VALUES: Triage[] = ['looks_real', 'likely_false_positive', 'needs_human'];

/**
 * Categories where the snippet IS the secret.
 *
 * For these, metadata goes to the provider and the code window does not. The
 * finding says a credential is on line 16; sending line 16 would send the
 * credential to a third party in order to ask whether sending credentials to
 * third parties is a problem.
 */
const SECRET_CLASS = new Set(['hardcoded_secrets', 'vulnerable_dependency']);

export function isSecretClass(category: unknown): boolean {
  return SECRET_CLASS.has(String(category ?? ''));
}

const WINDOW_LINES = 30;

/**
 * The bounded code window: the enclosing function, or ±30 lines, whichever is
 * SMALLER. Never the whole file, never the repository.
 *
 * The enclosing block is found by scanning outward for a line at a lower
 * indent that opens a block. It is a heuristic and it is allowed to be wrong,
 * because the ±30 bound is the guarantee: a wrong guess is still clamped.
 */
export function codeWindow(fileText: string, line: number): { text: string; from: number; to: number } {
  const lines = fileText.split('\n');
  const idx = Math.max(0, Math.min(lines.length - 1, (line || 1) - 1));

  const hardFrom = Math.max(0, idx - WINDOW_LINES);
  const hardTo = Math.min(lines.length - 1, idx + WINDOW_LINES);

  // Walk up to a plausible block opener at a lower indent than the finding.
  const indentOf = (s: string) => s.search(/\S/);
  const own = indentOf(lines[idx]);
  let from = hardFrom;
  if (own > 0) {
    for (let i = idx - 1; i >= hardFrom; i--) {
      const ind = indentOf(lines[i]);
      if (ind === -1) continue;
      if (ind < own && /[({:]\s*$|\b(function|def|class|=>)\b/.test(lines[i])) { from = i; break; }
    }
  }

  return { text: lines.slice(from, hardTo + 1).join('\n'), from: from + 1, to: hardTo + 1 };
}

/**
 * Pull the first complete JSON object out of a reply.
 *
 * Extraction is separate from validation ON PURPOSE, and the split is the
 * whole fix. The first version called JSON.parse on the raw reply, so a model
 * that wrapped its object in a markdown fence — which is what actually
 * happened, six times out of six — failed the schema check and degraded to
 * needs_human. The fail-safe behaved correctly and the happy path never ran.
 *
 * Loosening the SCHEMA would have been the wrong repair: the closed enum is
 * what stops a malformed reply softening a finding. What was too strict was the
 * envelope, not the contract. So this finds the object and hands it, unchanged,
 * to exactly the same strict check as before.
 *
 * Brace counting is string-aware. A brace inside a JSON string literal, and an
 * escaped quote inside that string, must not end the object — `{"a":"}"}` is
 * one object, and a naive scan truncates it into invalid JSON and reports a
 * parse failure that is really an extraction failure.
 */
export function extractJsonObject(raw: string): string | null {
  const s = String(raw ?? '');
  const start = s.indexOf('{');
  if (start === -1) return null;

  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = start; i < s.length; i++) {
    const ch = s[i];

    if (inString) {
      if (escaped) { escaped = false; continue; }
      if (ch === '\\') { escaped = true; continue; }
      if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') { inString = true; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return s.slice(start, i + 1);
    }
  }
  return null;
}

/**
 * Parse the model's reply against a CLOSED schema.
 *
 * Anything that is not exactly the schema becomes `needs_human`. Never
 * `likely_false_positive`, and there is deliberately no value meaning "safe":
 * a malformed reply must not be able to soften a finding, and the failure
 * direction is the whole point of a closed enum.
 */
export function parseInterpretation(raw: string): Omit<Interpretation, 'usage'> {
  const fallback = (why: string): Omit<Interpretation, 'usage'> => ({
    explanation: `The reviewer's reply could not be read (${why}). The finding stands as the engine reported it.`,
    triage: 'needs_human',
    suggested_fix: null,
  });

  // Extract first, then validate. See extractJsonObject.
  const candidate = extractJsonObject(raw);
  if (candidate === null) return fallback('no JSON object in the reply');

  let obj: any;
  try {
    obj = JSON.parse(candidate);
  } catch {
    return fallback('not valid JSON');
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return fallback('not an object');

  const triage = obj.triage;
  if (typeof triage !== 'string' || !TRIAGE_VALUES.includes(triage as Triage)) {
    return fallback(`triage was not one of ${TRIAGE_VALUES.join(', ')}`);
  }
  if (typeof obj.explanation !== 'string' || !obj.explanation.trim()) {
    return fallback('explanation missing');
  }

  const fix = obj.suggested_fix;
  return {
    explanation: obj.explanation.trim().slice(0, 1200),
    triage: triage as Triage,
    suggested_fix: typeof fix === 'string' && fix.trim() ? fix.trim().slice(0, 4000) : null,
  };
}

/**
 * Fold interpretations into findings WITHOUT letting them change anything the
 * engines established.
 *
 * The only fields written are `interpretation` and `interpretedBy`. Severity,
 * category, file, line and the finding's presence are copied through
 * untouched. This function is the enforcement point for the rule at the top of
 * the file, and it is written so that enforcement is visible rather than
 * distributed across call sites.
 */
export function applyInterpretations<T extends Record<string, any>>(
  findings: T[],
  byIndex: Map<number, Interpretation>
): T[] {
  return findings.map((f, i) => {
    const interp = byIndex.get(i);
    if (!interp) return f;
    return { ...f, interpretation: interp, interpretedBy: 'ai' };
  });
}

/** How many findings the interpreter thinks are probably not real. Best effort. */
export function triagedFalsePositives(findings: Array<{ interpretation?: Interpretation }>): number {
  return findings.filter((f) => f.interpretation?.triage === 'likely_false_positive').length;
}

/**
 * Why a call failed, in the words a reader can act on.
 *
 * The status code is the useful part and it is stated: a 401 is a key problem
 * and a 429 is a rate limit, and telling someone "the reviewer could not be
 * reached" for both wastes the one piece of information the provider gave.
 */
export function describeFailure(err: any): string {
  const status = err?.response?.status;
  if (status === 401 || status === 403) return `provider rejected the key (${status})`;
  if (status === 429) return `provider rate-limited the request (429)`;
  if (status && status >= 500) return `provider error (${status})`;
  if (status) return `provider returned ${status}`;
  if (err?.code === 'ECONNABORTED') return 'request timed out';
  return String(err?.message || 'unknown error').slice(0, 120);
}

/**
 * The one-line account of what interpretation actually did.
 *
 * NEVER a bare zero. A run where every call failed must say so and why; a run
 * with nothing to interpret is a different sentence. Pure, so the invalid-key
 * case is testable without a network.
 */
export function interpretationSummary(
  total: number,
  totals: { calls: number; input: number; output: number },
  failures: Array<{ reason: string; status?: number }>
): string {
  if (total === 0) return 'Nothing to interpret: the engines produced no findings.';

  if (totals.calls === 0) {
    const why = failures.length ? failures[0].reason : 'no call completed';
    return `0 of ${total} interpreted — ${why}. Every finding below is the engine's, uninterpreted.`;
  }

  const cost = `${totals.calls} call(s), ${totals.input} input tokens, ${totals.output} output tokens`;
  if (failures.length) {
    return `${totals.calls} of ${total} interpreted, ${failures.length} failed — ${failures[0].reason}. ${cost}.`;
  }
  return `${totals.calls} of ${total} interpreted. ${cost}.`;
}

const PROVIDERS: Record<string, { url: string; model: string; header: string }> = {
  anthropic: { url: 'https://api.anthropic.com/v1/messages', model: 'claude-haiku-4-5-20251001', header: 'x-api-key' },
  openai: { url: 'https://api.openai.com/v1/chat/completions', model: 'gpt-4o-mini', header: 'authorization' },
  openrouter: { url: 'https://openrouter.ai/api/v1/chat/completions', model: 'anthropic/claude-haiku-4.5', header: 'authorization' },
};

export class Interpreter {
  private key: string;
  private provider: { url: string; model: string; header: string };
  private name: string;
  /** Every call's reported usage, in order. Never estimated. */
  public readonly usage: Array<{ input: number; output: number }> = [];
  /**
   * Every call that did not produce an interpretation, with why.
   *
   * Tracked separately from `usage` because a run where every call failed and
   * a run with nothing to interpret both leave `usage` empty, and they are not
   * the same event. Reported by an invalid key: the first version of this class
   * printed "0 calls, 0 input tokens, 0 output tokens" and a normal report,
   * which is the silent-zero failure wearing different clothes.
   */
  public readonly failures: Array<{ reason: string; status?: number }> = [];

  constructor() {
    this.name = resolveProvider();
    const cfg = PROVIDERS[this.name];
    if (!cfg) throw new Error(`Unknown AI provider '${this.name}'. Available: ${Object.keys(PROVIDERS).join(', ')}`);
    this.provider = cfg;
    this.key = resolveApiKey(this.name).key || '';
    if (!this.key) throw new Error('AI_API_KEY not set. Required for --ai');
  }

  buildPrompt(finding: any, window: string | null, nonce: string): string | null {
    const meta = [
      `tool: ${renderField(finding.tools ? finding.tools.join(', ') : finding.tool)}`,
      `severity: ${renderField(finding.severity)}`,
      `category: ${renderField(finding.category)}`,
      `location: ${renderPath(finding.file, finding.line)}`,
      `rule: ${renderField((finding.rules || []).join(', '), 120)}`,
      `message: ${escapeControls(String(finding.message || '')).slice(0, 600)}`,
    ].join('\n');

    const findingBlock = fenceBlock('GLANCE_FINDING', nonce, meta);
    if (!findingBlock) return null;

    let codeBlock = '';
    if (window !== null) {
      const b = fenceBlock('GLANCE_CODE', nonce, window);
      // A snippet that still reads as a fence after stripping is not sent. The
      // finding keeps its engine verdict and is reported as not interpreted.
      if (!b) return null;
      codeBlock = `\n\n${b}`;
    }

    return [
      'You are reviewing one security finding produced by a static analysis engine.',
      '',
      AUTHORITY_RULE,
      '',
      window === null
        ? 'No code is included for this finding: the snippet would itself be the credential. Judge from the metadata alone, and say so if that is not enough.'
        : 'The code block is a bounded window around the finding, not the whole file.',
      '',
      findingBlock + codeBlock,
      '',
      'Reply with ONE JSON object and nothing else:',
      '{"explanation": "<two sentences at most>",',
      ' "triage": "looks_real" | "likely_false_positive" | "needs_human",',
      ' "suggested_fix": "<unified diff>" | null}',
      '',
      'Use needs_human when the window does not settle it. There is no value',
      'meaning "safe": you are explaining a finding, not clearing it.',
    ].join('\n');
  }

  async interpret(finding: any, fileText: string | null): Promise<Interpretation> {
    const nonce = makeNonce();
    const secret = isSecretClass(finding.category);

    let window: string | null = null;
    if (!secret && fileText && finding.line) {
      window = codeWindow(fileText, finding.line).text;
    }

    const prompt = this.buildPrompt(finding, window, nonce);
    if (!prompt) {
      return {
        explanation: 'Not sent for interpretation: the surrounding text reads as a prompt delimiter even after normalisation.',
        triage: 'needs_human',
        suggested_fix: null,
        usage: null,
        skipped: 'delimiter-residue',
      };
    }

    try {
      const isAnthropic = this.provider.header === 'x-api-key';
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (isAnthropic) {
        headers['x-api-key'] = this.key;
        headers['anthropic-version'] = '2023-06-01';
      } else {
        headers['authorization'] = `Bearer ${this.key}`;
      }

      const res = await axios.post(
        this.provider.url,
        { model: this.provider.model, max_tokens: 700, messages: [{ role: 'user', content: prompt }] },
        { headers, timeout: 30000 }
      );

      let text = '';
      let usage: { input: number; output: number } | null = null;
      if (isAnthropic) {
        const block = (res.data.content || []).find((b: any) => b.type === 'text');
        text = (block ? block.text : '') || '';
        // Provider-reported, never derived from string length.
        const u = res.data.usage;
        if (u) usage = { input: Number(u.input_tokens) || 0, output: Number(u.output_tokens) || 0 };
      } else {
        text = res.data.choices?.[0]?.message?.content || '';
        const u = res.data.usage;
        if (u) usage = { input: Number(u.prompt_tokens) || 0, output: Number(u.completion_tokens) || 0 };
      }

      if (usage) this.usage.push(usage);
      // Opt-in capture of the raw reply, for building a parser fixture out of
      // what a model ACTUALLY sends rather than what we imagine it sends. Off
      // unless GLANCE_AI_RAW names a file. The reply can quote the scanned
      // code, so this is never on by default and never goes anywhere but the
      // path the user chose.
      const rawPath = process.env.GLANCE_AI_RAW;
      if (rawPath) {
        try {
          fs.appendFileSync(rawPath, `--- reply ${new Date().toISOString()} ---\n${text}\n`);
        } catch {
          /* capture is a convenience; never break a scan for it */
        }
      }
      return { ...parseInterpretation(text), usage };
    } catch (err: any) {
      const status = err?.response?.status;
      const reason = describeFailure(err);
      this.failures.push({ reason, status });
      return {
        explanation: `Not interpreted: ${reason}. The finding stands exactly as the engine reported it.`,
        triage: 'needs_human',
        suggested_fix: null,
        usage: null,
        skipped: reason,
      };
    }
  }

  /** Totals for the cost line. Sum of what the provider reported, nothing else. */
  totals(): { input: number; output: number; calls: number } {
    return {
      calls: this.usage.length,
      input: this.usage.reduce((a, u) => a + u.input, 0),
      output: this.usage.reduce((a, u) => a + u.output, 0),
    };
  }
}

/** Read a file for the code window, or null if it cannot be read. */
export function readFileForWindow(file: string): string | null {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}
