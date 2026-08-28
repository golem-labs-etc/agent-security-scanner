import { spawn, execSync } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

function chunkArray<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/** npm audit severities, as emitted in `.vulnerabilities[pkg].severity`. */
const NPM_SEVERITY: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
  info: 'LOW',
};

export interface ToolFinding {
  tool: string;
  severity: string;
  file: string;
  line?: number;
  message: string;
  /**
   * Risk-taxonomy id, when the engine's own rule id maps onto one. Optional:
   * the four Python tools do not classify, so their findings fall back to the
   * tool name, which is what the report showed before this field existed.
   */
  category?: string;
  details?: any;
}

/** What an engine did on this run, so the CLI can say so by name. */
export interface EngineRun {
  name: string;
  ran: boolean;
  /** Present when `ran` is false. Stated to the user verbatim. */
  reason?: string;
  findings: number;
  ms?: number;
}

export interface ToolAvailability {
  name: string;
  binName: string;
  pythonModule: string;
  installed: boolean;
  method: 'bin' | 'python' | null;
}

const TOOL_DEFS = [
  { name: 'semgrep', binName: 'semgrep', pythonModule: 'semgrep' },
  { name: 'detect-secrets', binName: 'detect-secrets', pythonModule: 'detect_secrets' },
  { name: 'bandit', binName: 'bandit', pythonModule: 'bandit' },
  { name: 'pylint', binName: 'pylint', pythonModule: 'pylint' },
  { name: 'pip-audit', binName: 'pip-audit', pythonModule: 'pip_audit' },
];

/**
 * semgrep `check_id` substring -> risk-taxonomy id.
 *
 * Order matters: the first match wins, so narrower ids come first. Anything
 * unmatched keeps its own check_id as the category rather than being forced
 * into a bucket it does not fit.
 */
const SEMGREP_TAXONOMY: Array<[string, string]> = [
  ['detect-child-process', 'command_injection'],
  ['subprocess-shell-true', 'command_injection'],
  ['dangerous-system-call', 'command_injection'],
  ['command-injection', 'command_injection'],
  ['path-traversal', 'path_traversal'],
  ['path-join-resolve-traversal', 'path_traversal'],
  ['sendfile', 'path_traversal'],
  ['raw-html', 'xss'],
  ['xss', 'xss'],
  ['pickle', 'unsafe_pickle'],
  ['deserialization', 'insecure_deserialization'],
  ['sql-query', 'sql_injection'],
  ['sql-injection', 'sql_injection'],
  ['sqlalchemy-execute-raw-query', 'sql_injection'],
  ['detected-', 'hardcoded_secrets'],
  ['secret', 'hardcoded_secrets'],
  ['hardcoded', 'hardcoded_secrets'],
  ['csurf', 'csrf'],
  ['csrf', 'csrf'],
  ['insecure-random', 'insecure_random'],
  ['weak-', 'weak_crypto'],
  ['open-redirect', 'unvalidated_redirect'],
];

function semgrepCategory(checkId: string): string {
  const id = checkId.toLowerCase();
  for (const [needle, taxonomy] of SEMGREP_TAXONOMY) {
    if (id.includes(needle)) return taxonomy;
  }
  return checkId;
}

/**
 * ERROR -> HIGH, or CRITICAL when the rule is about a leaked credential.
 * WARNING -> MEDIUM, INFO -> LOW.
 */
function semgrepSeverity(checkId: string, severity: string): string {
  const s = String(severity || '').toUpperCase();
  if (s === 'ERROR') {
    const id = checkId.toLowerCase();
    return id.includes('secret') || id.includes('-key') || id.includes('key-') ? 'CRITICAL' : 'HIGH';
  }
  if (s === 'WARNING') return 'MEDIUM';
  if (s === 'INFO') return 'LOW';
  return 'MEDIUM';
}

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
      'semgrep': 'semgrep',
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

  /**
   * Tier 0 — `npm audit`. Zero install, no Python, no prompt.
   *
   * Runs whenever the scanned directory has a package.json AND a lockfile.
   *
   * A missing lockfile is SKIPPED with a stated reason rather than repaired.
   * `npm install --package-lock-only` would fix it, but it writes a
   * package-lock.json into the directory being scanned and needs the network to
   * do it. A security scanner that silently mutates the tree it was pointed at
   * is a worse trade than one advisory line telling the owner the command.
   *
   * Findings carry NO line number. A dependency advisory does not have one, and
   * inventing a `package.json:1` would be exactly the lie this work removes.
   */
  async runNpmAudit(dirPath: string): Promise<{ findings: ToolFinding[]; run: EngineRun }> {
    const started = Date.now();
    const skip = (reason: string): { findings: ToolFinding[]; run: EngineRun } => ({
      findings: [],
      run: { name: 'npm audit', ran: false, reason, findings: 0 },
    });

    if (!dirPath || !existsSync(join(dirPath, 'package.json'))) {
      return skip('no package.json in the scanned directory');
    }
    const hasLock = ['package-lock.json', 'npm-shrinkwrap.json'].some((f) => existsSync(join(dirPath, f)));
    if (!hasLock) {
      return skip('no package-lock.json (run `npm install --package-lock-only` in that directory to enable it)');
    }

    const { output, error } = await this.runCmd('npm', ['audit', '--json'], dirPath, 60000);

    let data: any;
    try {
      // npm audit exits non-zero when it FINDS vulnerabilities, so a non-zero
      // exit is the normal case and only unparseable output is a real failure.
      data = JSON.parse(output);
    } catch {
      const detail = (error || 'no output').trim().split('\n')[0].slice(0, 160);
      return skip(`npm audit produced no parseable JSON (${detail})`);
    }
    if (data?.error) {
      return skip(`npm audit failed: ${String(data.error.summary || data.error.code || 'unknown').slice(0, 160)}`);
    }

    const findings: ToolFinding[] = [];
    const vulns = data?.vulnerabilities;
    if (vulns && typeof vulns === 'object') {
      for (const name of Object.keys(vulns)) {
        const v = vulns[name];
        // `via` holds advisory objects for a direct hit, or plain package-name
        // strings when the package is only affected through a dependency.
        const advisories = Array.isArray(v?.via) ? v.via.filter((x: any) => x && typeof x === 'object') : [];
        const title = advisories[0]?.title || `Vulnerable via ${Array.isArray(v?.via) ? v.via.join(', ') : 'a dependency'}`;
        const url = advisories[0]?.url;
        const range = v?.range ? ` (affected: ${v.range})` : '';

        findings.push({
          tool: 'npm-audit',
          severity: NPM_SEVERITY[String(v?.severity || '').toLowerCase()] || 'MEDIUM',
          file: join(dirPath, 'package.json'),
          // No line: an advisory is about a dependency, not a source location.
          message: `${name}: ${title}${range}${url ? ` — ${url}` : ''}`,
          category: 'vulnerable_dependency',
          details: v,
        });
      }
    }

    return {
      findings,
      run: { name: 'npm audit', ran: true, findings: findings.length, ms: Date.now() - started },
    };
  }

  /**
   * Tier 1 — semgrep. One auto-installable dependency, real line numbers.
   *
   * Invocation is the spec's, with one addition that is not cosmetic:
   *
   *   semgrep --config=p/default --metrics=off --json --quiet <explicit files>
   *
   * EXPLICIT FILE PATHS, never a directory. Measured on this repo: pointing
   * semgrep at `tests/` scanned ZERO files and reported "Findings: 0", because
   * its built-in `.semgrepignore` excludes test directories and it limits
   * itself to files tracked by git. A security tool that reports a confident
   * zero after silently skipping everything is the same class of lie as the
   * canned line numbers this work removes. `--no-git-ignore` alone did not fix
   * it; naming the files does, and the CLI already knows which files are in
   * scope.
   *
   * `--metrics=off` is on every invocation and is non-negotiable for the
   * "uploads nothing" claim.
   */
  async runSemgrep(files: string[]): Promise<{ findings: ToolFinding[]; run: EngineRun }> {
    const started = Date.now();
    if (!files.length) {
      return { findings: [], run: { name: 'semgrep', ran: false, reason: 'no scannable files', findings: 0 } };
    }
    if (!this.toolInvocation('semgrep', 'semgrep')) {
      return {
        findings: [],
        run: {
          name: 'semgrep',
          ran: false,
          reason: 'not installed (run `glance-scanner install-tools --semgrep`, or `pipx install semgrep`)',
          findings: 0,
        },
      };
    }

    const findings: ToolFinding[] = [];
    let failure: string | null = null;

    // Chunked so a large repo cannot overflow the OS argument limit. semgrep's
    // ~2.5s startup dominates, so chunks are kept large rather than per-file.
    for (const chunk of chunkArray(files, 400)) {
      const { output, error } = await this.runToolCmd(
        'semgrep',
        'semgrep',
        ['--config=p/default', '--metrics=off', '--json', '--quiet', ...chunk],
        undefined,
        300000
      );

      let data: any;
      try {
        data = JSON.parse(output);
      } catch {
        failure = (error || 'no output').trim().split('\n').slice(-1)[0].slice(0, 160);
        continue;
      }

      for (const r of data?.results || []) {
        const checkId = String(r?.check_id || '');
        const meta = r?.extra?.metadata || {};
        const refs = Array.isArray(meta.references) ? meta.references[0] : undefined;
        findings.push({
          tool: 'semgrep',
          severity: semgrepSeverity(checkId, r?.extra?.severity),
          file: String(r?.path || 'unknown'),
          // Semgrep's own line number. Never recomputed, never invented.
          line: typeof r?.start?.line === 'number' ? r.start.line : undefined,
          message: `${String(r?.extra?.message || checkId).trim().split('\n')[0]}${meta.cwe ? ` [${[].concat(meta.cwe)[0]}]` : ''}${refs ? ` — ${refs}` : ''}`,
          category: semgrepCategory(checkId),
          details: { check_id: checkId, cwe: meta.cwe, owasp: meta.owasp, references: meta.references },
        });
      }
    }

    if (failure && findings.length === 0) {
      return { findings: [], run: { name: 'semgrep', ran: false, reason: `semgrep failed: ${failure}`, findings: 0 } };
    }
    return {
      findings,
      run: { name: 'semgrep (p/default)', ran: true, findings: findings.length, ms: Date.now() - started },
    };
  }

  /** Has semgrep ever been run on this machine? Governs the first-run notice. */
  semgrepRulesCached(): boolean {
    return existsSync(join(homedir(), '.semgrep'));
  }

  /** Run a plain binary (not a Python module). Used by npm audit and semgrep. */
  private runCmd(
    cmd: string,
    args: string[],
    cwd?: string,
    timeoutMs?: number
  ): Promise<{ output: string; error: string; code: number | null }> {
    return new Promise((resolve) => {
      let proc;
      try {
        proc = spawn(cmd, args, { cwd, env: { ...process.env } });
      } catch (err) {
        resolve({ output: '', error: err instanceof Error ? err.message : String(err), code: null });
        return;
      }

      let output = '';
      let error = '';
      let settled = false;
      const done = (r: { output: string; error: string; code: number | null }) => {
        if (!settled) { settled = true; resolve(r); }
      };

      const timeout = timeoutMs
        ? setTimeout(() => { proc.kill(); done({ output, error: `${cmd} timeout (${timeoutMs}ms)`, code: null }); }, timeoutMs)
        : null;

      proc.stdout.on('data', (d) => { output += d.toString(); });
      proc.stderr.on('data', (d) => { error += d.toString(); });
      proc.on('error', (err) => {
        if (timeout) clearTimeout(timeout);
        done({ output, error: err.message, code: null });
      });
      proc.on('close', (code) => {
        if (timeout) clearTimeout(timeout);
        done({ output, error, code });
      });
    });
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