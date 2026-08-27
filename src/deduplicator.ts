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
      const key = this.generateKey(finding.pattern, finding.line);
      if (!unified.has(key)) {
        unified.set(key, {
          id: key,
          file: (finding as any).file || 'unknown',
          line: finding.line,
          severity: this.mapSeverity(finding.severity),
          category: finding.pattern,
          message: finding.description || '',
          tools: ['semantic-analysis'],
          details: finding,
        });
      } else {
        const existing = unified.get(key)!;
        if (!existing.tools.includes('semantic-analysis')) {
          existing.tools.push('semantic-analysis');
        }
      }
    }

    // Add tool findings
    for (const finding of toolFindings) {
      const key = this.generateKey(finding.message, finding.line);
      if (!unified.has(key)) {
        unified.set(key, {
          id: key,
          file: finding.file,
          line: finding.line,
          severity: this.mapSeverity(finding.severity),
          category: finding.tool,
          message: finding.message,
          tools: [finding.tool],
          details: finding.details,
        });
      } else {
        const existing = unified.get(key)!;
        if (!existing.tools.includes(finding.tool)) {
          existing.tools.push(finding.tool);
        }
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

  private generateKey(message: string, line?: number): string {
    const linePart = line ? `:${line}` : '';
    // Hash the message to create a unique key
    return `${message.substring(0, 50).replace(/[^a-zA-Z0-9]/g, '_')}${linePart}`;
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
