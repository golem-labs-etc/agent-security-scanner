import { spawn, execSync } from 'child_process';
import { readFileSync } from 'fs';

export interface ToolFinding {
  tool: string;
  severity: string;
  file: string;
  line?: number;
  message: string;
  details?: any;
}

export interface ToolAvailability {
  name: string;
  binName: string;
  pythonModule: string;
  installed: boolean;
  method: 'bin' | 'python' | null;
}

const TOOL_DEFS = [
  { name: 'detect-secrets', binName: 'detect-secrets', pythonModule: 'detect_secrets' },
  { name: 'bandit', binName: 'bandit', pythonModule: 'bandit' },
  { name: 'pylint', binName: 'pylint', pythonModule: 'pylint' },
  { name: 'pip-audit', binName: 'pip-audit', pythonModule: 'pip_audit' },
];

export class ToolsOrchestrator {
  private pythonBin: string;

  constructor() {
    // Find a usable python3 (platform-aware, no hardcoded user path)
    this.pythonBin = this.locatePython();
  }

  private locatePython(): string {
    // Order: python3 in PATH > 'python3' as-is (macOS/Linux/Windows fallback)
    try {
      execSync('command -v python3', { stdio: 'pipe' });
      return 'python3';
    } catch {
      try {
        execSync('command -v python', { stdio: 'pipe' });
        return 'python';
      } catch {
        return 'python3'; // last resort, will fail with clear error
      }
    }
  }

  /**
   * Check which tools are installed. Returns availability + how to invoke each.
   */
  checkToolAvailability(): ToolAvailability[] {
    const results: ToolAvailability[] = [];

    for (const def of TOOL_DEFS) {
      const av: ToolAvailability = {
        name: def.name,
        binName: def.binName,
        pythonModule: def.pythonModule,
        installed: false,
        method: null,
      };

      // Method 1: binary on PATH
      try {
        execSync(`command -v ${def.binName}`, { stdio: 'pipe', env: { ...process.env } });
        av.installed = true;
        av.method = 'bin';
        results.push(av);
        continue;
      } catch {}

      // Method 2: python module importable
      try {
        execSync(`${this.pythonBin} -c "import ${def.pythonModule}"`, { stdio: 'pipe' });
        av.installed = true;
        av.method = 'python';
        results.push(av);
        continue;
      } catch {}

      results.push(av);
    }

    return results;
  }

  /**
   * Install Python tools via pip (user scope). Skips ones already available.
   * Returns the list of tools that were installed or already present.
   */
  installTools(tools?: string[]): { installed: string[]; alreadyPresent: string[]; failed: string[] } {
    const availability = this.checkToolAvailability();
    const wanted = (tools && tools.length > 0)
      ? tools.map((t) => t.toLowerCase())
      : TOOL_DEFS.map((def) => def.name);

    const installed: string[] = [];
    const alreadyPresent: string[] = [];
    const failed: string[] = [];

    const pipPkgs: Record<string, string> = {
      'detect-secrets': 'detect-secrets',
      'bandit': 'bandit',
      'pylint': 'pylint',
      'pip-audit': 'pip-audit',
    };

    for (const name of wanted) {
      const av = availability.find((a) => a.name === name);
      if (av && av.installed) {
        alreadyPresent.push(name);
        continue;
      }

      const pkg = pipPkgs[name];
      if (!pkg) {
        failed.push(name);
        continue;
      }

      try {
        console.log(`  Installing ${name}...`);
        execSync(`${this.pythonBin} -m pip install --user --quiet ${pkg}`, { stdio: 'pipe' });
        installed.push(name);
      } catch {
        try {
          // Retry without --user (some envs disallow user installs)
          console.log(`  Retry without --user for ${name}...`);
          execSync(`${this.pythonBin} -m pip install --quiet ${pkg}`, { stdio: 'pipe' });
          installed.push(name);
        } catch {
          failed.push(name);
        }
      }
    }

    return { installed, alreadyPresent, failed };
  }

  /**
   * Resolve the invocation for a tool. Returns null if not installed.
   */
  private toolInvocation(binName: string, pythonModule: string): { cmd: string; argsPrefix: string[] } | null {
    try {
      execSync(`command -v ${binName}`, { stdio: 'pipe' });
      return { cmd: binName, argsPrefix: [] };
    } catch {}

    try {
      execSync(`${this.pythonBin} -c "import ${pythonModule}"`, { stdio: 'pipe' });
      return { cmd: this.pythonBin, argsPrefix: ['-m', pythonModule] };
    } catch {}

    return null;
  }

  private runToolCmd(
    binName: string,
    pythonModule: string,
    args: string[],
    cwd?: string,
    timeoutMs?: number
  ): Promise<{ output: string; error: string }> {
    return new Promise((resolve) => {
      const inv = this.toolInvocation(binName, pythonModule);
      if (!inv) {
        resolve({ output: '', error: '[' + binName + ' not installed - run `glance-scanner install-tools`' });
        return;
      }

      const proc = spawn(inv.cmd, [...inv.argsPrefix, ...args], {
        cwd,
        env: { ...process.env },
      });

      let output = '';
      let error = '';
      let settled = false;

      const timeout = timeoutMs
        ? setTimeout(() => {
            if (!settled) {
              settled = true;
              proc.kill();
              resolve({ output, error: `${binName} timeout (${timeoutMs}ms)` });
            }
          }, timeoutMs)
        : null;

      proc.stdout.on('data', (data) => {
        output += data.toString();
      });
      proc.stderr.on('data', (data) => {
        error += data.toString();
      });
      proc.on('close', () => {
        if (timeout) clearTimeout(timeout);
        if (!settled) {
          settled = true;
          resolve({ output, error });
        }
      });
    });
  }

  async runDetectSecrets(filePath: string): Promise<ToolFinding[]> {
    const { output } = await this.runToolCmd('detect-secrets', 'detect_secrets', ['scan', filePath]);

    try {
      const data = JSON.parse(output);
      const findings: ToolFinding[] = [];

      if (data.results && Object.keys(data.results).length > 0) {
        for (const [file, secrets] of Object.entries(data.results)) {
          for (const secret of secrets as any[]) {
            findings.push({
              tool: 'detect-secrets',
              severity: 'HIGH',
              file,
              line: secret.line_number || undefined,
              message: `Secret detected (${secret.type || 'unknown'})`,
              details: secret,
            });
          }
        }
      }

      return findings;
    } catch {
      return [];
    }
  }

  async runBandit(filePath: string): Promise<ToolFinding[]> {
    const { output } = await this.runToolCmd('bandit', 'bandit', ['-r', filePath, '-f', 'json']);

    try {
      const data = JSON.parse(output);
      const findings: ToolFinding[] = [];

      if (data.results && data.results.length > 0) {
        for (const issue of data.results) {
          findings.push({
            tool: 'bandit',
            severity: issue.severity,
            file: issue.filename,
            line: issue.line_number,
            message: issue.issue_text,
            details: issue,
          });
        }
      }

      return findings;
    } catch {
      return [];
    }
  }

  async runPylint(filePath: string): Promise<ToolFinding[]> {
    const { output } = await this.runToolCmd('pylint', 'pylint', [filePath, '--output-format=json', '--exit-zero']);

    try {
      const data = JSON.parse(output);
      const findings: ToolFinding[] = [];

      const criticalTypes = ['error', 'fatal', 'undefined-variable'];

      if (Array.isArray(data)) {
        for (const issue of data) {
          if (criticalTypes.includes(issue.type)) {
            findings.push({
              tool: 'pylint',
              severity: issue.type === 'error' || issue.type === 'fatal' ? 'HIGH' : 'MEDIUM',
              file: issue.path,
              line: issue.line,
              message: issue.message,
              details: issue,
            });
          }
        }
      }

      return findings;
    } catch {
      return [];
    }
  }

  async runPipAudit(dirPath: string): Promise<ToolFinding[]> {
    const { output } = await this.runToolCmd('pip-audit', 'pip_audit', ['-f', 'json'], dirPath, 30000);

    try {
      const data = JSON.parse(output);
      const findings: ToolFinding[] = [];

      if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        for (const vuln of data.vulnerabilities) {
          findings.push({
            tool: 'pip-audit',
            severity: 'HIGH',
            file: 'requirements.txt (or pyproject.toml)',
            message: `${vuln.name} ${vuln.version} has vulnerability: ${vuln.description}`,
            details: vuln,
          });
        }
      }

      return findings;
    } catch {
      return [];
    }
  }

  async runAllTools(
    filePath: string,
    dirPath: string,
    options: {
      semanticOnly?: boolean;
      withSecrets?: boolean;
      withBandit?: boolean;
      withLinting?: boolean;
      withDependencies?: boolean;
      withAll?: boolean;
    }
  ): Promise<ToolFinding[]> {
    const findings: ToolFinding[] = [];

    if (!options.semanticOnly) {
      if (options.withSecrets || options.withAll) {
        findings.push(...await this.runDetectSecrets(filePath || dirPath));
      }

      if (options.withBandit || options.withAll) {
        findings.push(...await this.runBandit(filePath || dirPath));
      }

      if (options.withLinting || options.withAll) {
        if (filePath?.endsWith('.py') || !filePath) {
          findings.push(...await this.runPylint(filePath || dirPath));
        }
      }

      if (options.withDependencies || options.withAll) {
        findings.push(...await this.runPipAudit(dirPath || filePath));
      }
    }

    return findings;
  }
}