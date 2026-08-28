import { ToolsOrchestrator, ToolFinding, EngineRun } from './tools-orchestrator';

/**
 * The no-API-key path.
 *
 * This replaces `MockAnalyzer`, which matched substrings and then returned
 * canned findings with hardcoded line numbers — `sql_injection` always claimed
 * line 7, `command_injection` always line 5 — and, being an if/else chain,
 * reported at most one problem per file. Those numbers were fed straight into
 * `--verbose` code context, so the tool printed the wrong lines of the user's
 * own file with complete confidence.
 *
 * Everything here comes from a real engine:
 *
 *   Tier 0  npm audit   dependency advisories, no line numbers (there are none)
 *   Tier 1  semgrep     1074 rules from p/default, real line numbers
 *
 * THE RULES THIS FILE EXISTS TO KEEP:
 *
 *   1. No invented line numbers. If an engine does not report one, the field is
 *      omitted. It is never guessed, defaulted, or carried over.
 *   2. Every engine that ran is named in the output, and every engine that did
 *      not run says why.
 *   3. If nothing is available, say so and return nothing. There is no
 *      fallback to fabricated output, and adding one would undo the whole point.
 */
export class StaticAnalyzer {
  private orchestrator: ToolsOrchestrator;

  constructor(orchestrator?: ToolsOrchestrator) {
    this.orchestrator = orchestrator || new ToolsOrchestrator();
  }

  /** True on the very first semgrep run, when rules still have to be fetched. */
  needsRuleDownload(): boolean {
    return !this.orchestrator.semgrepRulesCached();
  }

  /**
   * Run every available engine once over the whole scan.
   *
   * Deliberately not per-file: semgrep costs ~2.5s of startup per invocation
   * and npm audit is a property of a directory, not of a file. The old
   * per-file analyzer loop made sense for an API call per file and makes none
   * here.
   */
  async scan(files: string[], scanDir: string): Promise<{ findings: ToolFinding[]; engines: EngineRun[] }> {
    const [semgrep, npmAudit] = await Promise.all([
      this.orchestrator.runSemgrep(files),
      this.orchestrator.runNpmAudit(scanDir),
    ]);

    return {
      findings: [...semgrep.findings, ...npmAudit.findings],
      engines: [semgrep.run, npmAudit.run],
    };
  }

  /** One line per engine, for the report header. Names names, states skips. */
  static describe(engines: EngineRun[]): string[] {
    return engines.map((e) =>
      e.ran
        ? `  ${e.name}: ${e.findings} finding${e.findings === 1 ? '' : 's'}${e.ms ? ` in ${(e.ms / 1000).toFixed(1)}s` : ''}`
        : `  ${e.name}: did not run — ${e.reason}`
    );
  }
}
