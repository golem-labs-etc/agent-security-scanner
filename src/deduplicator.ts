import { Finding } from './taxonomy';
import { ToolFinding } from './tools-orchestrator';

export interface UnifiedFinding {
  id: string;
  file: string;
  line?: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  message: string;
  tools: string[];
  /** Every rule that fired at this file and line, most specific name available. */
  rules: string[];
  /** Every taxonomy id contributed here. More than one means genuinely distinct problems. */
  categories: string[];
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW'; // Semantic filter confidence
  isFalsePositive?: boolean; // Marked by semantic filter
  filteringReasoning?: string; // Why semantic filter marked it as FP or real
  details?: any;
}

export class FindingsDeduplicator {
  /**
   * Deduplicate findings from all sources (semantic + tools)
   * Group by file+line+category to avoid reporting the same issue twice
   */
  deduplicate(
    semanticFindings: Finding[],
    toolFindings: ToolFinding[]
  ): UnifiedFinding[] {
    const unified: Map<string, UnifiedFinding> = new Map();

    // Add semantic findings
    for (const finding of semanticFindings) {
      const file = (finding as any).file || 'unknown';
      const key = this.generateKey(file, finding.pattern, finding.line);
      if (!unified.has(key)) {
        unified.set(key, {
          id: key,
          file,
          line: finding.line,
          severity: this.mapSeverity(finding.severity),
          category: finding.pattern,
          message: finding.description || '',
          tools: ['semantic-analysis'],
          rules: [finding.pattern].filter(Boolean),
          categories: [finding.pattern].filter(Boolean),
          details: finding,
        });
      } else {
        this.fold(unified.get(key)!, {
          tool: 'semantic-analysis',
          rule: finding.pattern,
          category: finding.pattern,
          severity: this.mapSeverity(finding.severity),
          message: finding.description || '',
        });
      }
    }

    // Add tool findings
    for (const finding of toolFindings) {
      const key = this.generateKey(finding.file, finding.message, finding.line);
      if (!unified.has(key)) {
        unified.set(key, {
          id: key,
          file: finding.file,
          line: finding.line,
          severity: this.mapSeverity(finding.severity),
          // Engines that classify (semgrep, npm audit) supply a taxonomy id.
          // The Python tools do not, and fall back to the tool name as before.
          category: finding.category || finding.tool,
          message: finding.message,
          tools: [finding.tool],
          rules: [this.ruleName(finding)].filter(Boolean),
          categories: [finding.category || finding.tool].filter(Boolean),
          details: finding.details,
        });
      } else {
        this.fold(unified.get(key)!, {
          tool: finding.tool,
          rule: this.ruleName(finding),
          category: finding.category || finding.tool,
          severity: this.mapSeverity(finding.severity),
          message: finding.message,
        });
      }
    }

    // Sort by severity (critical first) then by line number
    return Array.from(unified.values()).sort((a, b) => {
      const severityOrder: Record<string, number> = {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 2,
        LOW: 3,
      };
      if (severityOrder[a.severity] !== severityOrder[b.severity]) {
        return severityOrder[a.severity] - severityOrder[b.severity];
      }
      return (a.line || 0) - (b.line || 0);
    });
  }

  /**
   * Identity of a finding: file + what it says + line.
   *
   * The file path is load-bearing and was missing. Without it, two files hit by
   * the same rule at the same line collide and one is silently dropped — the
   * deduplicator reports a lower total and never says it discarded anything.
   * With the old mock analyzer that was nearly invisible, because it emitted at
   * most one finding per file from a fixed set of canned line numbers. A real
   * static engine run across a directory hits it constantly: the same rule
   * firing at line 12 of four different files became one finding.
   *
   * The doc comment on deduplicate() already claimed "group by file+line+
   * category". This makes that true rather than aspirational.
   */
  private generateKey(file: string, discriminator: string, line?: number): string {
    const filePart = (file || 'unknown').replace(/[^a-zA-Z0-9]/g, '_');

    // A place in a file is one finding. Two semgrep rules firing on the same
    // `res.send('<h1>' + req.query.q + '</h1>')` are two descriptions of one
    // problem, and counting them twice inflates every total on a real repo.
    if (line) return `${filePart}:${line}`;

    // No line means a dependency advisory, where the file is always
    // package.json. Collapsing on file alone would merge every advisory in a
    // project into a single finding, so these keep the message as their
    // discriminator.
    return `${filePart}::${discriminator.substring(0, 50).replace(/[^a-zA-Z0-9]/g, '_')}`;
  }

  private static readonly SEVERITY_RANK: Record<string, number> = {
    CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3,
  };

  /**
   * Fold a second finding into one already held at this file and line.
   *
   * The most severe contributor supplies the headline: its severity, its
   * category and its message. Everything else is preserved as a name in
   * `rules` and `categories`, so a collapse never makes a distinct problem
   * invisible. Two rules on one line CAN be genuinely different problems, and
   * `categories` is what says so.
   */
  private fold(
    existing: UnifiedFinding,
    incoming: { tool: string; rule: string; category: string; severity: UnifiedFinding['severity']; message: string }
  ): void {
    if (!existing.tools.includes(incoming.tool)) existing.tools.push(incoming.tool);
    if (incoming.rule && !existing.rules.includes(incoming.rule)) existing.rules.push(incoming.rule);
    if (incoming.category && !existing.categories.includes(incoming.category)) {
      existing.categories.push(incoming.category);
    }

    const rank = FindingsDeduplicator.SEVERITY_RANK;
    if (rank[incoming.severity] < rank[existing.severity]) {
      existing.severity = incoming.severity;
      existing.category = incoming.category || existing.category;
      existing.message = incoming.message || existing.message;
    }
  }

  /** The rule that produced a finding, by the most specific name available. */
  private ruleName(f: { details?: any; category?: string; tool?: string }): string {
    return String(f.details?.check_id || f.category || f.tool || '').trim();
  }

  private mapSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
    if (!severity) return 'MEDIUM';
    const map: Record<string, 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'> = {
      CRITICAL: 'CRITICAL',
      HIGH: 'HIGH',
      MEDIUM: 'MEDIUM',
      LOW: 'LOW',
      ERROR: 'HIGH',
      WARNING: 'MEDIUM',
      NOTICE: 'LOW',
    };
    return map[severity.toUpperCase()] || 'MEDIUM';
  }

  generateReport(unifiedFindings: UnifiedFinding[]): {
    summary: {
      total: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      toolsCovered: string[];
    };
    findings: UnifiedFinding[];
  } {
    const toolsCovered = new Set<string>();
    const summary = {
      total: unifiedFindings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      toolsCovered: [] as string[],
    };

    for (const finding of unifiedFindings) {
      summary[finding.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low']++;
      finding.tools.forEach((t) => toolsCovered.add(t));
    }

    summary.toolsCovered = Array.from(toolsCovered).sort();

    return { summary, findings: unifiedFindings };
  }

  generateJSON(report: any): string {
    return JSON.stringify(report, null, 2);
  }
}
