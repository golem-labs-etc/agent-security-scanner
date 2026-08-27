export const RISK_TAXONOMY = [
  {
    id: 'sql_injection',
    name: 'SQL Injection',
    description: 'Unsanitized user input in SQL queries',
  },
  {
    id: 'command_injection',
    name: 'Command Injection',
    description: 'Unsanitized input passed to shell commands',
  },
  {
    id: 'path_traversal',
    name: 'Path Traversal',
    description: 'Unsafe file path handling without validation',
  },
  {
    id: 'hardcoded_secrets',
    name: 'Hardcoded Secrets',
    description: 'API keys, passwords, tokens visible in code',
  },
  {
    id: 'xxe_attack',
    name: 'XXE Attack',
    description: 'XML External Entity vulnerabilities',
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    description: 'Unescaped user input rendered in HTML',
  },
  {
    id: 'csrf',
    name: 'CSRF',
    description: 'Missing CSRF token validation',
  },
  {
    id: 'insecure_deserialization',
    name: 'Insecure Deserialization',
    description: 'Unsafe deserialization of untrusted data',
  },
  {
    id: 'weak_crypto',
    name: 'Weak Cryptography',
    description: 'Use of weak or deprecated crypto algorithms',
  },
  {
    id: 'missing_auth',
    name: 'Missing Authentication',
    description: 'Sensitive endpoints without auth checks',
  },
  {
    id: 'hardcoded_config',
    name: 'Hardcoded Configuration',
    description: 'Database credentials or config hardcoded',
  },
  {
    id: 'unvalidated_redirect',
    name: 'Unvalidated Redirect',
    description: 'Open redirects using user-supplied URLs',
  },
  {
    id: 'information_disclosure',
    name: 'Information Disclosure',
    description: 'Sensitive data exposed in error messages or logs',
  },
  {
    id: 'insecure_random',
    name: 'Insecure Random',
    description: 'Weak random number generation for security purposes',
  },
  {
    id: 'unsafe_pickle',
    name: 'Unsafe Pickle/Marshalling',
    description: 'Deserialization of pickle/marshal with untrusted input',
  },
];

export interface Finding {
  pattern: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  line?: number;
  file?: string;
  description: string;
  recommendation?: string;
}

export interface AnalysisResult {
  file?: string;
  findings: Finding[];
  riskScore: number;
  timestamp: number;
}

export const SYSTEM_PROMPT = `You are a security code analyzer using semantic analysis patterns.
Your job is to identify security vulnerabilities in code snippets.

Risk Taxonomy:
${RISK_TAXONOMY.map((r) => `- ${r.id}: ${r.name} - ${r.description}`).join('\n')}

Rules:
1. Analyze code for the patterns listed above
2. For each finding, provide:
   - pattern: one of the risk IDs above
   - severity: CRITICAL, HIGH, MEDIUM, or LOW
   - line: approximate line number if detectable
   - description: detailed explanation of the issue
   - recommendation: how to fix it

3. Be precise and minimize false positives. Only flag real issues.
4. Return results as a JSON array of findings objects
5. If no vulnerabilities found, return empty array []

Output format (VALID JSON ONLY):
[
  {
    "pattern": "sql_injection",
    "severity": "HIGH",
    "line": 5,
    "description": "User input used in SQL query without parameterization",
    "recommendation": "Use parameterized queries or prepared statements"
  }
]
`;
