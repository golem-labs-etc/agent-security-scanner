import { spawn, execSync } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { join, resolve as resolvePath } from 'path';
import { homedir } from 'os';

function chunkArray<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * The rules this repo ships itself, alongside `p/default`.
 *
 * `__dirname` is `<pkg>/dist` when installed and `<pkg>/src` in development,
 * so one level up finds `rules/` in both. `rules/` is in package.json `files`;
 * if it ever falls out, this resolves to a missing directory and semgrep is
 * run with p/default alone rather than failing.
 */
export const LOCAL_RULES_DIR = resolvePath(__dirname, '..', 'rules');

/**
 * Did semgrep actually look at this path?
 *
 * Covered means the exact file appears in `paths.scanned`, or — for a directory
 * argument — at least one scanned file lives under it. The directory case
 * matters: `paths.scanned` lists files, so a directory that was scanned in full
 * would otherwise be reported as skipped.
 */
function isCovered(requested: string, scanned: Set<string>): boolean {
  const abs = resolvePath(requested);
  if (scanned.has(abs)) return true;
  const prefix = abs.endsWith('/') ? abs : `${abs}/`;
  for (const s of scanned) {
    if (s.startsWith(prefix)) return true;
  }
  return false;
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
  /**
   * Things that happened during a run that ran. Printed with the engine line
   * and never swallowed: a partial scan reported as a clean one is the failure
   * this field exists to prevent.
   */
  warnings?: string[];
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

/**
 * Strip the directory path semgrep bakes into the id of a local rule.
 *
 * Rules loaded from `--config=<dir>` are named after the path they came from,
 * so ours arrived as
 * `Users.dev.agent-security-scanner.rules.glance-js-sql-injection` — the
 * scanner's own install location, printed in the user's report. From npm it
 * would be their node_modules path instead. Neither is information about their
 * code.
 *
 * Anchored on our own `glance-` prefix rather than on `.rules.`, so a registry
 * rule that happens to contain that word is left exactly as semgrep named it.
 */
function normalizeCheckId(checkId: string): string {
  const m = checkId.match(/(?:^|\.)(glance-[a-z0-9-]+)$/);
  return m ? m[1] : checkId;
}

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
   * Install the Python tools. Skips ones already available.
   *
   * `advice` carries the reason a tool failed, in the user's words rather than
   * pip's. It exists because of a real failure on this machine: `pip install
   * semgrep` died with an `externally-managed-environment` error, PEP 668, and
   * the message the CLI printed was `Try: python3 -m pip install --user
   * semgrep` — the exact command that had just failed, and would fail again.
   * Silence about the cause sends people to a Tier 2 tool instead.
   */
  installTools(tools?: string[]): {
    installed: string[];
    alreadyPresent: string[];
    failed: string[];
    advice: string[];
  } {
    const availability = this.checkToolAvailability();
    const wanted = (tools && tools.length > 0)
      ? tools.map((t) => t.toLowerCase())
      : TOOL_DEFS.map((def) => def.name);

    const installed: string[] = [];
    const alreadyPresent: string[] = [];
    const failed: string[] = [];
    const advice: string[] = [];

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
        advice.push(`${name}: not a tool this command knows how to install.`);
        continue;
      }

      console.log(`  Installing ${name}...`);
      const outcome = this.installOne(pkg);
      if (outcome.ok) {
        installed.push(name);
      } else {
        failed.push(name);
        advice.push(...outcome.advice.map((line) => `${name}: ${line}`));
      }
    }

    return { installed, alreadyPresent, failed, advice: [...new Set(advice)] };
  }

  /**
   * pip, then pipx, and a stated reason when neither works.
   *
   * PEP 668 marks a distro- or Homebrew-managed interpreter as
   * "externally managed" and pip refuses to write into it at all. That is not a
   * fixable pip invocation: `--user` fails the same way. pipx is the answer
   * because it puts the tool in its own virtualenv, which PEP 668 permits.
   */
  private installOne(pkg: string): { ok: boolean; advice: string[] } {
    const attempt = (cmd: string): { ok: boolean; err: string } => {
      try {
        execSync(cmd, { stdio: 'pipe' });
        return { ok: true, err: '' };
      } catch (e: any) {
        return { ok: false, err: `${e?.stderr?.toString() || ''}${e?.stdout?.toString() || ''}${e?.message || ''}` };
      }
    };
    const have = (bin: string): boolean => {
      try { execSync(`command -v ${bin}`, { stdio: 'pipe' }); return true; } catch { return false; }
    };

    const pip = attempt(`${this.pythonBin} -m pip install --user --quiet ${pkg}`);
    if (pip.ok) return { ok: true, advice: [] };

    const pep668 = /externally[- ]managed|PEP 668/i.test(pip.err);
    if (!pep668) {
      // Some environments disallow user installs but allow the plain form.
      // Only worth trying when PEP 668 is NOT the cause; under PEP 668 it fails
      // identically and just wastes the user's time.
      const plain = attempt(`${this.pythonBin} -m pip install --quiet ${pkg}`);
      if (plain.ok) return { ok: true, advice: [] };
    }

    const why = pep668
      ? 'pip cannot install here: this Python is marked externally managed (PEP 668), '
        + 'so pip refuses to write into it and --user fails the same way. '
        + 'pipx installs the tool into its own virtualenv, which PEP 668 allows.'
      : 'pip install failed.';

    if (!have('pipx')) {
      return {
        ok: false,
        advice: [
          why,
          'pipx is not installed. Install it, then re-run this command:',
          '  brew install pipx        (macOS)',
          '  sudo apt install pipx    (Debian/Ubuntu)',
        ],
      };
    }

    console.log(`  pip is blocked (PEP 668). Retrying ${pkg} with pipx...`);
    const viaPipx = attempt(`pipx install ${pkg}`);
    if (viaPipx.ok) return { ok: true, advice: [] };

    // Last resort: an older interpreter. Not a version guess — the default one
    // has already been tried and rejected the package for some reason of its
    // own, so pin pipx to one that is known to have wheels.
    const alternates = ['python3.13', 'python3.12', 'python3.11'];
    const present = alternates.filter(have);
    for (const interp of present) {
      console.log(`  Retrying ${pkg} with pipx --python ${interp}...`);
      if (attempt(`pipx install ${pkg} --python ${interp}`).ok) return { ok: true, advice: [] };
    }

    const detail = viaPipx.err.trim().split('\n').filter(Boolean).slice(-1)[0]?.slice(0, 200) || 'no output';
    if (present.length === 0) {
      return {
        ok: false,
        advice: [
          why,
          `pipx also failed on the default interpreter (${detail.replace(/\s+/g, ' ')}), and no older`,
          'interpreter is installed to fall back to. Install one and re-run:',
          '  brew install python@3.12          (macOS)',
          '  sudo apt install python3.12       (Debian/Ubuntu)',
          `Then: pipx install ${pkg} --python python3.12`,
        ],
      };
    }
    return {
      ok: false,
      advice: [
        why,
        `pipx failed on the default interpreter and on ${present.join(', ')}.`,
        `Last error: ${detail.replace(/\s+/g, ' ')}`,
      ],
    };
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
   * A missing lockfile is SKIPPED with a stated reason rather than repaired,
   * with one exception. `npm install --package-lock-only` would fix it, but it
   * writes a package-lock.json into the directory being scanned. A security
   * scanner that silently mutates the tree it was pointed at is a worse trade
   * than one advisory line telling the owner the command.
   *
   * The exception is `--repo`, where the tree is a shallow clone this process
   * made in /tmp and deletes when it is done. Nothing there is the user's, so
   * generating a lockfile costs them nothing and buys the whole dependency
   * tier. `mayGenerateLockfile` is passed ONLY on that path — never for
   * `--path` or `--file`, which point at a directory the user owns.
   *
   * Findings carry NO line number. A dependency advisory does not have one, and
   * inventing a `package.json:1` would be exactly the lie this work removes.
   */
  async runNpmAudit(
    dirPath: string,
    opts: { mayGenerateLockfile?: boolean } = {}
  ): Promise<{ findings: ToolFinding[]; run: EngineRun }> {
    const started = Date.now();
    const warnings: string[] = [];
    const skip = (reason: string): { findings: ToolFinding[]; run: EngineRun } => ({
      findings: [],
      run: { name: 'npm audit', ran: false, reason, findings: 0 },
    });

    if (!dirPath || !existsSync(join(dirPath, 'package.json'))) {
      return skip('no package.json in the scanned directory');
    }
    const lockNames = ['package-lock.json', 'npm-shrinkwrap.json'];
    let hasLock = lockNames.some((f) => existsSync(join(dirPath, f)));

    if (!hasLock && opts.mayGenerateLockfile) {
      // Disposable clone only. `--ignore-scripts` because the clone is a
      // repository off the internet and npm must not be allowed to run any of
      // its code, `--package-lock-only` because nothing is installed.
      const { error } = await this.runCmd(
        'npm',
        ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund'],
        dirPath,
        180000
      );
      hasLock = lockNames.some((f) => existsSync(join(dirPath, f)));
      if (!hasLock) {
        const detail = (error || 'no output').trim().split('\n').filter(Boolean).slice(-1)[0]?.slice(0, 160) || 'unknown';
        return skip(`no lockfile, and generating one in the clone failed (${detail})`);
      }
      warnings.push('no lockfile in the repository; one was generated inside the temporary clone to enable this engine');
    }

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

        // The MATCHED advisory's own affected range, not `v.range`.
        //
        // `v.range` is npm's aggregate across every advisory for the package.
        // On lodash 4.17.11 it reads `<=4.17.23`, spanning seven advisories,
        // while the advisory named on the same line — GHSA-35jh-r3h4-6jhm,
        // Command Injection — is `<4.17.21`. Printing the aggregate beside one
        // advisory's title states something that advisory does not say. It
        // also overstates: it implies 4.17.22 is vulnerable to the named issue
        // when it is not.
        //
        // The aggregate is still worth having when there is no advisory object
        // to read, which is what happens when a package is only affected
        // transitively; it is labelled differently so the two cannot be
        // confused.
        const advisoryRange = advisories[0]?.range;
        const range = advisoryRange
          ? ` (affected: ${advisoryRange})`
          : v?.range ? ` (package affected overall: ${v.range})` : '';
        const alsoCount = advisories.length > 1 ? ` [+${advisories.length - 1} more advisor${advisories.length === 2 ? 'y' : 'ies'} for this package]` : '';

        findings.push({
          tool: 'npm-audit',
          severity: NPM_SEVERITY[String(v?.severity || '').toLowerCase()] || 'MEDIUM',
          file: join(dirPath, 'package.json'),
          // No line: an advisory is about a dependency, not a source location.
          message: `${name}: ${title}${range}${url ? ` — ${url}` : ''}${alsoCount}`,
          category: 'vulnerable_dependency',
          details: v,
        });
      }
    }

    return {
      findings,
      run: {
        name: 'npm audit',
        ran: true,
        findings: findings.length,
        ms: Date.now() - started,
        warnings: warnings.length ? warnings : undefined,
      },
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
    const scanned = new Set<string>();
    let sawScannedField = false;

    const config = ['--config=p/default'];
    if (existsSync(LOCAL_RULES_DIR)) config.push(`--config=${LOCAL_RULES_DIR}`);

    // Chunked so a large repo cannot overflow the OS argument limit. semgrep's
    // ~2.5s startup dominates, so chunks are kept large rather than per-file.
    for (const chunk of chunkArray(files, 400)) {
      const { output, error } = await this.runToolCmd(
        'semgrep',
        'semgrep',
        [...config, '--metrics=off', '--json', '--quiet', ...chunk],
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

      // What semgrep says it actually looked at. Checked against what it was
      // handed, below.
      if (Array.isArray(data?.paths?.scanned)) {
        sawScannedField = true;
        for (const p of data.paths.scanned) scanned.add(resolvePath(String(p)));
      }

      for (const r of data?.results || []) {
        const checkId = normalizeCheckId(String(r?.check_id || ''));
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

    // THE SILENT ZERO.
    //
    // Pointed at `tests/`, semgrep scanned nothing and reported "Findings: 0"
    // with exit status 0. Nothing in that output distinguishes "looked and
    // found nothing" from "looked at nothing". The scanner passes explicit file
    // paths now, which is what fixed it — but a clean scan that was never
    // performed is the single most dangerous output this tool can produce, so
    // it is checked rather than assumed.
    const skipped = sawScannedField ? files.filter((f) => !isCovered(f, scanned)) : [];
    const name = `semgrep (p/default${config.length > 1 ? ' + glance rules' : ''})`;

    if (sawScannedField && skipped.length === files.length) {
      return {
        findings,
        run: {
          name: 'semgrep',
          ran: false,
          reason:
            `scanned 0 of ${files.length} path(s) — semgrep skipped everything it was given. ` +
            `This is NOT a clean result. First skipped: ${skipped.slice(0, 3).join(', ')}`,
          findings: findings.length,
          ms: Date.now() - started,
        },
      };
    }

    const warnings = skipped.length
      ? [
          `scanned ${files.length - skipped.length} of ${files.length} files; semgrep skipped ` +
            `${skipped.length}: ${skipped.slice(0, 5).join(', ')}${skipped.length > 5 ? `, and ${skipped.length - 5} more` : ''}`,
        ]
      : undefined;

    return {
      findings,
      run: { name, ran: true, findings: findings.length, ms: Date.now() - started, warnings },
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