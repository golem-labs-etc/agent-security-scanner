/**
 * The verdict line, the invocation frame, and the per-finding action sentence.
 *
 * The report used to print evidence and stop. It said what was found and left
 * the reader to work out what it meant, which is the wrong half of the job: a
 * scanner's output is read by someone deciding whether to do something.
 *
 * EVERY SENTENCE HERE IS DERIVED, NEVER COMPOSED. The verdict comes from the
 * severity mix and the rule classes, the action comes from the rule class
 * alone. Nothing in this file writes a claim the findings do not support, and
 * nothing guesses at a fix. That is the same rule the rest of the tool follows
 * about line numbers, applied to prose.
 *
 * The load-bearing constraint is the last one in the brief: the verdict must
 * never claim more certainty than the findings carry. An audit-only run must
 * not say "fix before shipping", because an audit rule has not established
 * that anything is wrong — see `isAuditClass`.
 */

/**
 * Who is reading, decided by how the scan was invoked.
 *
 *   `--repo <url>`  adopter: someone evaluating code they did not write.
 *                   Their question is "should I trust this?"
 *   `--path`/`--file`  author: someone scanning their own tree.
 *                   Their question is "should I ship?"
 *
 * Same findings, same severities, different verdict wording. The frame is
 * stored once at invocation and reaches only two places, the verdict line and
 * the action sentences. It must never influence what is FOUND or how it is
 * ranked: a frame that changed severities would be telling two different
 * stories about one repository.
 */
export type Frame = 'adopter' | 'author';

export type VerdictFinding = {
  severity?: string;
  category?: string;
  tool?: string;
  tools?: string[];
  file?: string;
  line?: number;
  rules?: string[];
  details?: any;
};

/**
 * Is this finding from semgrep's `audit` rule class?
 *
 * Semgrep namespaces rules by intent. An `.audit.` rule reports a construct
 * that is worth a human look and is NOT an assertion that a vulnerability
 * exists: `express.security.audit.xss.direct-response-write` fires on every
 * `res.send()` of a variable, including ones whose value never leaves the
 * program. The non-audit rules are the ones that assert a defect.
 *
 * A finding counts as audit-class only when EVERY rule that produced it is
 * audit-class. Findings collapse by file and line, so one line can carry two
 * rules; if a non-audit rule fired there too, the finding is not merely an
 * audit observation and must not be softened into one.
 */
export function isAuditClass(f: VerdictFinding): boolean {
  const rules = f.rules && f.rules.length ? f.rules : [String(f.details?.check_id || '')];
  const named = rules.filter(Boolean);
  return named.length > 0 && named.every((r) => r.includes('.audit.'));
}

const BLOCKING = new Set(['CRITICAL', 'HIGH']);

/** Severities that stop a release, from rules that assert a defect. */
export function blockers(findings: VerdictFinding[]): VerdictFinding[] {
  return findings.filter((f) => BLOCKING.has(String(f.severity)) && !isAuditClass(f));
}

function plural(n: number, one: string, many = one + 's'): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** "1 critical", "2 critical and 1 high". Counts, not adjectives. */
function severityPhrase(findings: VerdictFinding[]): string {
  const crit = findings.filter((f) => f.severity === 'CRITICAL').length;
  const high = findings.filter((f) => f.severity === 'HIGH').length;
  const parts: string[] = [];
  if (crit) parts.push(`${crit} critical`);
  if (high) parts.push(`${high} high`);
  return parts.join(' and ');
}

export type EngineSummary = { name: string; ran: boolean; reason?: string };

/**
 * The verdict, in one line, before any counts.
 *
 * Three states, and the third is the one that needs the most care.
 *
 * The zero-findings case must say WHAT WAS CHECKED. "No issues found" is the
 * silent-zero failure in prose: it reads as a clean bill of health when it may
 * mean an engine did not run, or that the engines that ran do not look for the
 * thing the reader is worried about. The same rule the scan output already
 * follows for a skipped engine applies to the sentence a human actually reads.
 */
export function verdictLine(
  findings: VerdictFinding[],
  engines: EngineSummary[],
  frame: Frame,
  fileCount: number
): string {
  const ran = engines.filter((e) => e.ran).map((e) => e.name);

  if (findings.length === 0) {
    if (ran.length === 0) {
      return 'Nothing was checked: no analysis engine was available. This is not a clean result.';
    }
    const what = ran.join(' and ');
    const scope = fileCount > 0 ? ` across ${plural(fileCount, 'file')}` : '';
    return (
      `Nothing found by ${what}${scope}. That is not the same as safe: ` +
      `these engines match known patterns and do not reason about intent.`
    );
  }

  const blocking = blockers(findings);

  if (blocking.length > 0) {
    const phrase = severityPhrase(blocking);
    return frame === 'author'
      ? `${phrase}: fix before shipping. Details below.`
      : `${phrase}: not safe to adopt as-is. Details below.`;
  }

  // Nothing blocking. Everything that remains is either audit-class or below
  // the blocking severities, and neither asserts a defect.
  const audits = findings.filter(isAuditClass).length;
  const rest = findings.length - audits;

  if (audits > 0 && rest === 0) {
    const tail = frame === 'author'
      ? 'worth a look before this code handles untrusted input.'
      : 'worth a look before trusting this code with untrusted input.';
    return `No blockers. ${plural(audits, 'audit finding')} ${tail}`;
  }

  const tail = frame === 'author'
    ? 'worth reading before shipping.'
    : 'worth reading before trusting this code.';
  return `No blockers. ${plural(findings.length, 'finding')} ${tail}`;
}

/**
 * One sentence saying what to do about a finding, derived from its rule class.
 *
 * Three classes have an action the rule itself supports. Everything else gets
 * NOTHING, deliberately: a generic "review this finding" is filler, and
 * inventing a remediation for an arbitrary semgrep rule would be the prose
 * equivalent of an invented line number. A missing sentence is honest; a
 * guessed one is not.
 */
export function actionFor(f: VerdictFinding): string | null {
  const tools = f.tools && f.tools.length ? f.tools : [String(f.tool || '')];

  if (tools.includes('npm-audit')) {
    const fix = f.details?.fixAvailable;
    const pkg = String(f.details?.name || '').trim();
    if (fix && typeof fix === 'object' && fix.version) {
      const major = fix.isSemVerMajor ? ' (a major version change)' : '';
      return `Update ${fix.name || pkg} to ${fix.version}${major}.`;
    }
    // npm reports `true` when a fix exists but not which version, and `false`
    // when none is published. Both are stated as npm states them.
    if (fix === true) return `A fix is published. Run \`npm audit fix\` to take it.`;
    if (fix === false) return `No fix is published yet. The options are to pin, patch or drop this dependency.`;
    return null;
  }

  if (f.category === 'hardcoded_secrets') {
    return 'Rotate this credential and remove it from the file.';
  }

  if (isAuditClass(f) && f.file) {
    const where = f.line ? `${f.file}:${f.line}` : f.file;
    return `Open ${where} and check whether this value can come from outside the program.`;
  }

  return null;
}
