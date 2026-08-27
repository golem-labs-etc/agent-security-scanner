// Resolves which AI provider key to use, and how it got there.
// AI_API_KEY is the documented variable. ANTHROPIC_API_KEY is accepted as a
// fallback only when the provider is anthropic, since that variable is
// already set in most Claude Code environments.
export function resolveProvider(): string {
  return (process.env.AI_PROVIDER || 'anthropic').toLowerCase();
}

export function resolveApiKey(providerName: string): { key: string; source: string | null } {
  if (process.env.AI_API_KEY) {
    return { key: process.env.AI_API_KEY, source: 'AI_API_KEY' };
  }
  if (providerName === 'anthropic' && process.env.ANTHROPIC_API_KEY) {
    return { key: process.env.ANTHROPIC_API_KEY, source: 'ANTHROPIC_API_KEY' };
  }
  return { key: '', source: null };
}
