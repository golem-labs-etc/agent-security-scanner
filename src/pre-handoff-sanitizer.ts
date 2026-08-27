/**
 * Pre-Handoff Trigger: Redact secrets before agent responds
 * 
 * Flow:
 * 1. Agent has response text ready to send
 * 2. Scan response for API keys, passwords, tokens
 * 3. If secrets found: Redact them, log what was redacted
 * 4. Send sanitized response to user
 * 
 * Use Case: Prevent accidental credential leaks in agent responses
 */

import * as crypto from 'crypto';

export interface RedactionResult {
  original: string;
  sanitized: string;
  redactionsFound: number;
  redactions: {
    type: string;
    pattern: string;
    occurrences: number;
    context: string[];
  }[];
}

export class PreHandoffSanitizer {
  // Pattern definitions for secrets
  private patterns = {
    apiKey: /(?:api[_-]?key|api[_-]?secret|api[_-]?token)\s*[:=]\s*([a-zA-Z0-9\-_.]{20,})/gi,
    bearerToken: /bearer\s+([a-zA-Z0-9\-_.]{20,})/gi,
    awsKey: /AKIA[0-9A-Z]{16}/g,
    privateKey: /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/g,
    password: /(?:password|passwd|pwd)\s*[:=]\s*(\S+)/gi,
    gitHubToken: /ghp_[a-zA-Z0-9]{36}/g,
    jwtToken: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_.+/-]*$/gm,
    slackToken: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/g,
    databaseUrl: /(?:postgres|mysql|mongodb):\/\/[^\s]+/gi,
    simpleApiKey: /sk_(?:live|test)_[a-zA-Z0-9]{20,}/g,
  };

  async sanitizeResponse(text: string): Promise<RedactionResult> {
    let sanitized = text;
    const redactions: RedactionResult['redactions'] = [];
    let totalRedactions = 0;

    for (const [type, pattern] of Object.entries(this.patterns)) {
      const matches = text.match(pattern) || [];
      if (matches.length > 0) {
        const contexts = matches.slice(0, 3).map((m) => this.extractContext(text, m, 50));

        redactions.push({
          type,
          pattern: pattern.source,
          occurrences: matches.length,
          context: contexts,
        });

        // Redact all matches of this pattern
        sanitized = sanitized.replace(pattern, `[REDACTED_${type.toUpperCase()}]`);
        totalRedactions += matches.length;
      }
    }

    return {
      original: text,
      sanitized,
      redactionsFound: totalRedactions,
      redactions,
    };
  }

  private extractContext(text: string, match: string, contextLength: number): string {
    const index = text.indexOf(match);
    const start = Math.max(0, index - contextLength);
    const end = Math.min(text.length, index + match.length + contextLength);
    const context = text.substring(start, end).replace(/\n/g, ' ');
    return context.length > contextLength * 2 ? context.substring(0, contextLength * 2) + '...' : context;
  }

  logRedaction(result: RedactionResult, agentName: string): void {
    if (result.redactionsFound > 0) {
      console.warn(
        `[SECURITY] Agent '${agentName}' attempted to leak ${result.redactionsFound} secret(s) in response:`
      );
      for (const redaction of result.redactions) {
        console.warn(`  - ${redaction.type}: ${redaction.occurrences} occurrence(s)`);
        redaction.context.forEach((ctx, i) => {
          console.warn(`    Example ${i + 1}: ...${ctx}...`);
        });
      }
      console.warn('[SECURITY] Secrets redacted before sending response to user');
    }
  }
}
