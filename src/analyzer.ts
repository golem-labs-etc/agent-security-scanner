import axios from 'axios';
import { SYSTEM_PROMPT, Finding, AnalysisResult } from './taxonomy';
import { resolveProvider, resolveApiKey } from './env-key';

export interface AIProviderConfig {
  name: string;
  apiUrl: string;
  model: string;
  authHeader: string;
}

const PROVIDERS: Record<string, AIProviderConfig> = {
  anthropic: {
    name: 'anthropic',
    apiUrl: 'https://api.anthropic.com/v1/messages',
    model: 'claude-sonnet-5',
    authHeader: 'x-api-key',
  },
  openai: {
    name: 'openai',
    apiUrl: 'https://api.openai.com/v1/chat/completions',
    model: 'gpt-4o',
    authHeader: 'Authorization',
  },
  openrouter: {
    name: 'openrouter',
    apiUrl: 'https://openrouter.ai/api/v1/chat/completions',
    model: 'anthropic/claude-sonnet-5',
    authHeader: 'Authorization',
  },
};

export class AIAnalyzer {
  private provider: AIProviderConfig;
  private apiKey: string;

  constructor() {
    const providerName = resolveProvider();
    const config = PROVIDERS[providerName];

    if (!config) {
      const available = Object.keys(PROVIDERS).join(', ');
      throw new Error(`Unknown AI provider '${providerName}'. Available: ${available}. Set AI_PROVIDER env var.`);
    }

    const resolved = resolveApiKey(providerName);
    this.apiKey = resolved.key;
    if (!this.apiKey) {
      throw new Error(`AI_API_KEY environment variable is not set. Required for provider: ${providerName}`);
    }

    this.provider = config;
  }

  async analyze(code: string, filename?: string): Promise<AnalysisResult> {
    try {
      const userPrompt = `Analyze this code for security vulnerabilities:\n\n\`\`\`\n${code}\n\`\`\``;
      let findings: Finding[] = [];

      if (this.provider.name === 'anthropic') {
        const response = await axios.post(
          this.provider.apiUrl,
          {
            model: this.provider.model,
            max_tokens: 2048,
            system: SYSTEM_PROMPT,
            messages: [{ role: 'user', content: userPrompt }],
          },
          {
            headers: {
              [this.provider.authHeader]: this.apiKey,
              'anthropic-version': '2023-06-01',
              'content-type': 'application/json',
            },
            timeout: 30000,
          }
        );
        // Anthropic responses can lead with a thinking block before the
        // text block, so find the text block rather than assume index 0.
        const textBlock = response.data.content.find((b: any) => b.type === 'text');
        const content = textBlock ? textBlock.text : '';
        const jsonMatch = content.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
          findings = JSON.parse(jsonMatch[0]);
        }
      } else {
        // OpenAI-compatible endpoint (openai, openrouter)
        const response = await axios.post(
          this.provider.apiUrl,
          {
            model: this.provider.model,
            max_tokens: 2048,
            messages: [
              { role: 'system', content: SYSTEM_PROMPT },
              { role: 'user', content: userPrompt },
            ],
          },
          {
            headers: {
              [this.provider.authHeader]: `Bearer ${this.apiKey}`,
              'content-type': 'application/json',
            },
            timeout: 30000,
          }
        );
        const content = response.data.choices[0].message.content;
        const jsonMatch = content.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
          findings = JSON.parse(jsonMatch[0]);
        }
      }

      const riskScore = this.calculateRiskScore(findings);

      return {
        file: filename,
        findings,
        riskScore,
        timestamp: Date.now(),
      };
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 429) {
          throw new Error(`${this.provider.name} API rate limit exceeded. Retry later.`);
        }
        if (error.response?.status === 401) {
          throw new Error(`Invalid ${this.provider.name} API key. Check AI_API_KEY.`);
        }
        if (error.code === 'ECONNABORTED') {
          throw new Error(`${this.provider.name} API request timeout.`);
        }
        throw new Error(`${this.provider.name} API error: ${error.response?.data?.error?.message || error.message}`);
      }
      throw error;
    }
  }

  private calculateRiskScore(findings: Finding[]): number {
    const weights: Record<string, number> = {
      CRITICAL: 10,
      HIGH: 5,
      MEDIUM: 2,
      LOW: 1,
    };
    const totalScore = findings.reduce((sum, f) => sum + (weights[f.severity] || 0), 0);
    return Math.min(100, Math.round((totalScore / (findings.length * 10)) * 100) || 0);
  }
}