import axios from 'axios';
import { renderPath, renderField, renderEvidence, escapeControls, fenceFor } from './render-safe';
import { ToolFinding } from './tools-orchestrator';
import { resolveProvider, resolveApiKey } from './env-key';

export interface FilteredFinding {
  original: ToolFinding;
  isRealVulnerability: boolean;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  reasoning: string;
  aiAnalysis: string;
}

const FILTER_PROVIDERS: Record<string, { apiUrl: string; model: string; authHeader: string }> = {
  anthropic: {
    apiUrl: 'https://api.anthropic.com/v1/messages',
    model: 'claude-haiku-4-5-20251001',
    authHeader: 'x-api-key',
  },
  openai: {
    apiUrl: 'https://api.openai.com/v1/chat/completions',
    model: 'gpt-4o-mini',
    authHeader: 'Authorization',
  },
  openrouter: {
    apiUrl: 'https://openrouter.ai/api/v1/chat/completions',
    model: 'anthropic/claude-haiku-4.5',
    authHeader: 'Authorization',
  },
};

export class SemanticFilter {
  private apiKey: string;
  private provider: { apiUrl: string; model: string; authHeader: string };

  constructor() {
    const providerName = resolveProvider();
    const config = FILTER_PROVIDERS[providerName];

    this.apiKey = resolveApiKey(providerName).key;
    if (!this.apiKey) {
      throw new Error('AI_API_KEY not set. Required for --filter-fp');
    }

    if (!config) {
      throw new Error(`Unknown AI provider '${providerName}'. Available: ${Object.keys(FILTER_PROVIDERS).join(', ')}`);
    }

    this.provider = config;
  }

  async filterFinding(finding: ToolFinding, codeContext: string): Promise<FilteredFinding> {
    try {
      const prompt = this.buildPrompt(finding, codeContext);
      let responseText = '';

      if (this.provider.authHeader === 'x-api-key') {
        // Anthropic-style
        const response = await axios.post(
          this.provider.apiUrl,
          {
            model: this.provider.model,
            max_tokens: 500,
            messages: [{ role: 'user', content: prompt }],
          },
          {
            headers: {
              [this.provider.authHeader]: this.apiKey,
              'anthropic-version': '2023-06-01',
              'content-type': 'application/json',
            },
          }
        );
        // Anthropic responses can lead with a thinking block before the
        // text block, so find the text block rather than assume index 0.
        const textBlock = response.data.content.find((b: any) => b.type === 'text');
        responseText = (textBlock ? textBlock.text : '') || '';
      } else {
        // OpenAI-compatible
        const response = await axios.post(
          this.provider.apiUrl,
          {
            model: this.provider.model,
            max_tokens: 500,
            messages: [{ role: 'user', content: prompt }],
          },
          {
            headers: {
              [this.provider.authHeader]: `Bearer ${this.apiKey}`,
              'content-type': 'application/json',
            },
          }
        );
        responseText = response.data.choices[0].message.content || '';
      }

      const analysis = this.parseResponse(responseText);

      return {
        original: finding,
        isRealVulnerability: analysis.isReal,
        confidence: analysis.confidence,
        reasoning: analysis.reasoning,
        aiAnalysis: responseText,
      };
    } catch (error) {
      console.warn('Filter error, defaulting to report finding');
      return {
        original: finding,
        isRealVulnerability: true,
        confidence: 'MEDIUM',
        reasoning: 'Filter analysis unavailable',
        aiAnalysis: '',
      };
    }
  }

  private buildPrompt(finding: ToolFinding, codeContext: string): string {
    // This prompt is assembled from a scanned tree and sent to a model. The
    // file path is a filename an attacker wrote; the message is a tool's
    // rendering of attacker code. Both are escaped, so neither can close a
    // line and forge a section header.
    //
    // The code context cannot be escaped the same way: newlines are what make
    // it readable, and it is the thing the model is being asked to judge. The
    // problem there was the fence, which the content could close. Fixed by
    // sizing the fence to the content rather than by altering the content --
    // see fenceFor. Stripping backticks would have edited the code under
    // review, and the construct removed could be the one that makes the
    // finding real.
    const body = codeContext.substring(0, 2000);
    const fence = fenceFor(body);
    return `You are a security code reviewer evaluating whether a vulnerability finding is real or a false positive.

FINDING TO ANALYZE:
Tool: ${renderField(finding.tool)}
Severity: ${renderField(finding.severity)}
File: ${renderPath(finding.file)}
Line: ${finding.line || 'unknown'}
Message: ${escapeControls(finding.message)}

CODE CONTEXT (surrounding the finding):
${fence}
${body}
${fence}

YOUR TASK:
1. Read the code context carefully
2. Determine if this is a REAL vulnerability or a FALSE POSITIVE
3. Explain your reasoning with reference to the code

RESPONSE FORMAT (EXACTLY as shown):
VERDICT: [REAL VULNERABILITY | FALSE POSITIVE]
CONFIDENCE: [HIGH | MEDIUM | LOW]
REASONING: [1-2 sentences explaining why, with code reference]

Examples:
- FALSE POSITIVE with HIGH confidence: "The query uses parameterized prepared statements (?) which safely escapes user input. This is the correct safe pattern."
- REAL VULNERABILITY with HIGH confidence: "User input is concatenated directly into SQL string without parameterization or escaping."

Respond only in the format above.`;
  }

  private parseResponse(
    response: string
  ): { isReal: boolean; confidence: 'HIGH' | 'MEDIUM' | 'LOW'; reasoning: string } {
    const verdictMatch = response.match(/VERDICT:\s*([A-Z\s]+)/);
    const confidenceMatch = response.match(/CONFIDENCE:\s*(HIGH|MEDIUM|LOW)/);
    const reasoningMatch = response.match(/REASONING:\s*(.+?)(?=\n|$)/s);

    const verdict = verdictMatch ? verdictMatch[1].trim() : 'UNKNOWN';
    const isReal = verdict.includes('REAL');
    const confidence = (confidenceMatch ? confidenceMatch[1] : 'MEDIUM') as 'HIGH' | 'MEDIUM' | 'LOW';
    const reasoning = reasoningMatch ? reasoningMatch[1].trim() : 'Unable to parse reasoning';

    return { isReal, confidence, reasoning };
  }

  async filterFindings(
    findings: ToolFinding[],
    codeContext: string
  ): Promise<FilteredFinding[]> {
    const filtered: FilteredFinding[] = [];

    for (const finding of findings) {
      console.log(`  Filtering: ${renderField(finding.tool)} - ${escapeControls(finding.message).substring(0, 50)}...`);
      const result = await this.filterFinding(finding, codeContext);
      filtered.push(result);
      await this.delay(200);
    }

    return filtered;
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}