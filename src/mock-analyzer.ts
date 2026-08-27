import { Finding, AnalysisResult } from './taxonomy';

// Mock Claude response patterns for testing (before real API key available)
const MOCK_FINDINGS: Record<string, Finding[]> = {
  sql_injection: [
    {
      pattern: 'sql_injection',
      severity: 'CRITICAL',
      line: 7,
      description: 'User input used in SQL query without parameterization',
      recommendation: 'Use parameterized queries or prepared statements',
    },
  ],
  hardcoded_secrets: [
    {
      pattern: 'hardcoded_secrets',
      severity: 'CRITICAL',
      line: 5,
      description: 'Stripe API key hardcoded in source code',
      recommendation: 'Move to environment variables using dotenv',
    },
    {
      pattern: 'hardcoded_config',
      severity: 'HIGH',
      line: 6,
      description: 'Database password hardcoded in connection string',
      recommendation: 'Use environment variables for all credentials',
    },
  ],
  path_traversal: [
    {
      pattern: 'path_traversal',
      severity: 'HIGH',
      line: 8,
      description: 'User input directly used in file path without validation',
      recommendation: 'Validate input, use path.resolve() and ensure it stays within expected directory',
    },
  ],
  xss: [
    {
      pattern: 'xss',
      severity: 'HIGH',
      line: 6,
      description: 'User input rendered without escaping in EJS template',
      recommendation: 'Use <%- ... %> for HTML escaping or sanitize input',
    },
  ],
  xss_innerhtml: [
    {
      pattern: 'xss',
      severity: 'HIGH',
      line: 6,
      description: 'User input assigned to innerHTML without sanitization',
      recommendation: 'Use textContent instead of innerHTML, or sanitize with DOMPurify',
    },
  ],
  command_injection: [
    {
      pattern: 'command_injection',
      severity: 'CRITICAL',
      line: 5,
      description: 'User input passed to shell command without sanitization',
      recommendation: 'Use execFile() with argument arrays instead of exec(); validate and whitelist input',
    },
  ],
  safe: [],
};

export class MockAnalyzer {
  async analyze(code: string, filename?: string): Promise<AnalysisResult> {
    // Detect which vulnerability type based on keywords in code
    let findings: Finding[] = [];

    // SQL injection: String concatenation in SELECT (not parameterized queries)
    // Checks for + concatenation with quotes, excludes $1/$2 parameterized form
    // Also excludes variable names containing "SELECT" (e.g. PROFILE_SELECTABLE)
    const hasSQLSelect = /\bSELECT\b/i.test(code);
    if (
      hasSQLSelect &&
      code.includes('+') &&
      code.includes("'") &&
      !code.includes('$1') &&
      !code.includes('prepare(') &&
      !code.includes('.query(')
    ) {
      findings = MOCK_FINDINGS.sql_injection;
    }
    // Hardcoded secrets: explicit key/password strings
    else if (code.includes('SK_LIVE_') || code.includes('SuperSecret') || (code.includes('STRIPE_API_KEY =') && code.includes("'"))) {
      findings = MOCK_FINDINGS.hardcoded_secrets;
    }
    // Path traversal: path.join + req.query.file pattern
    else if (code.includes('path.join') && code.includes('req.query.file')) {
      findings = MOCK_FINDINGS.path_traversal;
    }
    // Command injection: exec/execSync/spawn with user input concatenation
    else if (
      (code.includes('exec(') || code.includes('execSync(') || code.includes('spawn(')) &&
      (code.includes('req.body') || code.includes('req.query') || code.includes('req.params') ||
       code.includes('user_input') || code.includes('userInput') || code.includes('input +') ||
       code.includes('+ input') || code.includes('${'))
    ) {
      findings = MOCK_FINDINGS.command_injection;
    }
    // XSS innerHTML: direct innerHTML assignment with user data
    else if (
      code.includes('innerHTML') &&
      (code.includes('req.') || code.includes('user') || code.includes('input') || code.includes('query') || code.includes('param'))
    ) {
      findings = MOCK_FINDINGS.xss_innerhtml;
    }
    // XSS: EJS template or render with searchTerm
    else if (code.includes('<%= searchTerm') || (code.includes('render') && code.includes('searchTerm'))) {
      findings = MOCK_FINDINGS.xss;
    }
    // Safe code: uses prepare/parameterized queries or process.env
    else {
      findings = MOCK_FINDINGS.safe;
    }

    const riskScore = this.calculateRiskScore(findings);

    return {
      file: filename,
      findings,
      riskScore,
      timestamp: Date.now(),
    };
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
