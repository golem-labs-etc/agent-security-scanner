#!/usr/bin/env node

import { Command } from 'commander';
import { renderPath, renderField, renderEvidence, escapeControls } from './render-safe';
import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import { AIAnalyzer } from './analyzer';
import { StaticAnalyzer } from './static-analyzer';
import { CacheManager } from './cache';
import { ToolsOrchestrator, EngineRun } from './tools-orchestrator';
import { FindingsDeduplicator } from './deduplicator';
import { SemanticFilter } from './semantic-filter';
import { resolveProvider, resolveApiKey } from './env-key';
import { MARK } from './brand';
import { verdictLine, actionFor, isAuditClass, Frame } from './verdict';
import { relativiseFindings } from './finding-paths';
import { Interpreter, applyInterpretations, triagedFalsePositives, readFileForWindow, interpretationSummary, Interpretation } from './interpreter';

// `quiet` suppresses dotenvx's "injected env (1) from .env" banner, which it
// writes to STDOUT at import time. That banner was the first line of every
// `--json` report and made the output unparseable before anything else ran.
dotenv.config({ quiet: true });

const program = new Command();

/**
 * Human-facing progress output.
 *
 * Silenced by `--json`, because it was previously interleaved with the report
 * on stdout and made `--json` unparseable — the first line of the "JSON" was
 * `Mock mode (pattern-based detection).`. Anything a machine consumes goes to
 * stdout alone; anything a person reads goes through here.
 */
let quietHumanOutput = false;
function say(msg = ''): void {
  if (!quietHumanOutput) console.log(msg);
}

program
  .name('glance-scanner')
  .description('Security scanner for AI agents. Static analysis by default (semgrep + npm audit), no API key needed.')
  .version(require('../package.json').version);

/**
 * Exit with a status without discarding output already written.
 *
 * `process.exit()` terminates immediately and drops anything still queued on
 * stdout. Writes to a terminal are synchronous, so this is invisible by hand;
 * writes to a pipe are not, so any output past the pipe buffer is lost at
 * exactly 65536 bytes. That shipped in 1.3.0 and truncated the `surfaces`
 * report mid-JSON for every consumer that read it as a program.
 *
 * The rule this establishes: no `process.exit()` anywhere in this file. Either
 * set `process.exitCode` and return, which is best, or call this. The unref'd
 * timer is the backstop for a reader that goes away without an error, so a
 * flush that never completes cannot hang a CI job.
 */
function exitAfterFlush(code: number): never {
  process.exitCode = code;
  const out = process.stdout as any;
  if (out.writableLength) {
    out.write('', () => process.exit(code));
    setTimeout(() => process.exit(code), 2000).unref();
  } else {
    process.exit(code);
  }
  return undefined as never;
}



// ── surfaces command ───────────────────────────────────────────
//
// Agent surfaces are a distinct scan target from code. An MCP server entry and
// a skill file are read by the agent as configuration and as instruction, and
// neither `npm audit` nor semgrep reads either one. They are also identical on
// every host, so this lives in the shipped CLI and every platform adapter gets
// it for free.
program
  .command('surfaces')
  .description('Scan agent surfaces: MCP server configs and prompt/skill files')
  .option('--inventory <path>', 'Inventory JSON produced by a platform adapter')
  .option('--root <dir>', 'Discover surfaces under a directory instead')
  .option('--json', 'Emit the report as JSON')
  .option(
    '--evidence',
    'Include matched text on each finding. Off by default: the caller is sometimes an LLM prompt.'
  )
  .option(
    '--list-categories',
    'Print the categories this engine can emit, as JSON, and exit. Consumers build their maps from this rather than keeping a copy that drifts.'
  )
  .option(
    '--policy <level>',
    'balanced (default) downgrades a directive quoted inside a code fence to fenced_directive/medium; strict reports it as written. There is no "off" level.'
  )
  .action(async (options) => {
    try {
      const { scanSurfaces, discoverInventory, discoverDefaultInventory, resolvePolicy, CATEGORIES } = require('./surfaces');

      // Answered before any input is required: a consumer asking what this
      // engine can emit should not have to have something to scan.
      if (options.listCategories) {
        console.log(JSON.stringify({ schema: 1, categories: CATEGORIES }, null, 2));
        process.exitCode = 0;
        return;
      }

      const { policy, warnings } = resolvePolicy(options.policy);


      let inv;
      if (options.inventory) {
        inv = JSON.parse(fs.readFileSync(options.inventory, 'utf8'));
        if (inv && inv.schema !== 1) {
          console.error(`error: unsupported inventory schema ${inv.schema}, expected 1`);
          exitAfterFlush(2);
        }
      }

      let configScanRoots: string[] = [];
      let checked: Array<{ path: string; kind: string; found: boolean }> | null = null;
      if (options.root) {
        const root = path.resolve(options.root);
        inv = discoverInventory(root);
        configScanRoots = [root];
      } else if (!options.inventory) {
        // No --root and no --inventory: scan what an agent can actually reach.
        //
        // `--root ~` was never a reasonable default. Measured 1 Sep 2026 on a
        // real machine it took 49.7s over 3001 files and returned ten findings,
        // none of which an agent could reach: a downloaded zip, disabled
        // optional skills, an inactive profile, and this repo's own fixtures.
        // Telling a stranger to point a security tool at their whole home
        // directory is also the wrong first thing to ask of them.
        const d = discoverDefaultInventory();
        inv = d.inventory;
        checked = d.checked;
      }

      const report = await scanSurfaces(inv, {
        evidence: !!options.evidence,
        policy,
        warnings,
        configScanRoots,
      });

      if (options.json) {
        console.log(JSON.stringify(checked ? { ...report, checked } : report, null, 2));
      } else {
        // Say where we looked BEFORE saying what we found. A clean report from
        // a scanner that checked nothing looks exactly like a clean machine,
        // and absence reported is the only thing that separates them.
        if (checked) printCheckedLocations(checked);
        printSurfaceReport(report, !!options.evidence, !checked);
      }
      // Set the code and return; do NOT call process.exit() here.
      //
      // process.exit() does not flush a pending asynchronous write. Writes to a
      // terminal are synchronous, so this looks fine by hand; writes to a pipe
      // are not, so any consumer that captures stdout gets the report truncated
      // at one pipe buffer -- 64 KB, mid-JSON, with the exit code intact and
      // stderr empty. Invisible in a terminal, invisible on small inputs, and
      // certain on a large report read by a program. Returning lets node drain
      // stdout and then exit with this code.
      process.exitCode =
        report.counts.critical > 0 || report.counts.high > 0 ? 1 : 0;
      return;
    } catch (err: any) {
      console.error(`error: ${err.message}`);
      exitAfterFlush(2);
    }
  });

/**
 * What was consulted, present or absent.
 *
 * Absent locations are listed too. A person who sees "0 of 6 found" knows the
 * clean result means nothing on their machine; a person shown only findings
 * cannot tell that apart from a clean machine.
 */
function printCheckedLocations(
  checked: Array<{ path: string; kind: string; found: boolean }>
): void {
  const found = checked.filter((c) => c.found);
  console.log(`${MARK} agent surfaces`);
  console.log(`  no --root given, so only locations an agent can reach were checked.`);
  console.log(`  checked ${checked.length}, found ${found.length}`);
  for (const c of checked) {
    console.log(`    ${c.found ? 'found  ' : 'absent '} ${escapeControls(c.path)}`);
  }
  if (!found.length) {
    console.log('  nothing found to scan. This is not a clean result: it means');
    console.log('  no agent configuration was present at any known location.');
    console.log('  Pass --root <dir> to scan a specific tree.');
  }
  console.log();
}

/** Human-readable surface report. Evidence appears only when asked for. */
function printSurfaceReport(report: any, withEvidence: boolean, header = true): void {
  const c = report.counts;
  if (header) console.log(`${MARK} agent surfaces`);
  console.log(`  policy ${report.policy}  |  scanned ${report.total_scanned}  |  critical ${c.critical}  high ${c.high}  medium ${c.medium}  info ${c.info}`);
  for (const w of report.warnings || []) {
    // A warning names a path: the planted-.glance.json warning exists to say
    // WHICH file inside the scanned tree it ignored. That path is written by
    // the same person who planted the config.
    console.log(`  warning: ${escapeControls(w.message)}`);
  }
  if (!report.findings.length) {
    console.log('  nothing to report.');
    return;
  }
  console.log();
  for (const f of report.findings) {
    // Every value on this line came out of the scanned tree. The path is a
    // filename, written by whoever wrote the file; the evidence is the matched
    // line, which is attack text by definition. Both go through render-safe,
    // and severity/category/id are whitelisted because they are ours.
    const loc = renderPath(f.path, f.line);
    console.log(`  ${renderField(f.severity).padEnd(8)} ${renderField(f.category).padEnd(24)} ${loc}  [${renderField(f.id, 16)}]`);
    if (withEvidence && f.evidence) console.log(`           ${renderEvidence(f.evidence)}`);
  }
  if (!withEvidence) {
    console.log();
    console.log('  Matched text is withheld. Re-run with --evidence to see it.');
  }
}

// ── install-tools command ──────────────────────────────────────────────────
program
  .command('install-tools')
  .description('Install missing security tools (semgrep, detect-secrets, bandit, pylint, pip-audit)')
  .option('--semgrep', 'Install only semgrep (powers the default no-API-key scan)')
  .option('--secrets', 'Install only detect-secrets')
  .option('--bandit', 'Install only bandit')
  .option('--linting', 'Install only pylint')
  .option('--dependencies', 'Install only pip-audit')
  .action(async (options) => {
    try {
      const orchestrator = new ToolsOrchestrator();

      const selected: string[] = [];
      if (options.semgrep) selected.push('semgrep');
      if (options.secrets) selected.push('detect-secrets');
      if (options.bandit) selected.push('bandit');
      if (options.linting) selected.push('pylint');
      if (options.dependencies) selected.push('pip-audit');
      // If no specific tool selected, install all
      const tools = selected.length > 0 ? selected : undefined;

      console.log('🔧 Checking installed tools...\n');
      const result = orchestrator.installTools(tools);

      if (result.alreadyPresent.length > 0) {
        console.log(`  ✓ Already installed: ${result.alreadyPresent.join(', ')}`);
      }
      if (result.installed.length > 0) {
        console.log(`  ✓ Installed: ${result.installed.join(', ')}`);
      }
      if (result.failed.length > 0) {
        console.log(`  ✗ Failed: ${result.failed.join(', ')}`);
        // Never "Try: <the command that just failed>". Print the cause.
        for (const line of result.advice) console.log(`    ${line}`);
      }

      console.log('');
      if (result.failed.length === 0) {
        console.log('✅ All tools ready. Run: glance-scanner analyze --file app.py --with-all-checks');
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      exitAfterFlush(1);
    }
  });

// ── analyze command ────────────────────────────────────────────────────────
program
  .command('analyze')
  .description('Analyze code for security vulnerabilities')
  .option('--file <path>', 'Path to a single file')
  .option('--path <dir>', 'Directory to scan recursively')
  .option('--repo <url>', 'Remote Git repository URL (clones to /tmp, scans, cleans up)')
  .option('--ai', 'Enable AI-powered semantic analysis (requires AI_API_KEY)')
  .option('--semantic', 'Alias for --ai')
  .option('--semantic-only', 'Alias for --ai (deprecated)')
  .option('--with-secrets', 'Add detect-secrets scan')
  .option('--with-bandit', 'Add bandit security scan')
  .option('--with-linting', 'Add pylint scan')
  .option('--with-dependencies', 'Add pip-audit for vulnerable deps')
  .option('--with-all-checks', 'Run all 4 OSS tools (no AI)')
  .option('--json', 'Output as JSON report')
  .option('--no-cache', 'Disable caching')
  .option('--filter-fp', 'Use AI to filter false positives (requires --ai)')
  .option('-v, --verbose', 'Show code context around each finding')
  .action(async (options) => {
    try {
      quietHumanOutput = !!options.json;

      // Default to real static analysis. AI is opt-in and needs a key.
      const useAI = options.ai || options.semantic || options.semanticOnly;

      // Pre-check AI key before constructing, friendly error with provider links
      if (useAI) {
        const provider = resolveProvider();
        const resolved = resolveApiKey(provider);
        if (!resolved.key) {
          printMissingAIKeyHelp(provider);
          exitAfterFlush(1);
        }
      }

      const aiAnalyzer = useAI ? new AIAnalyzer() : null;
      const staticAnalyzer = new StaticAnalyzer();
      if (useAI) {
        const provider = resolveProvider();
        const resolved = resolveApiKey(provider);
        const via = resolved.source === 'ANTHROPIC_API_KEY' ? ' (via ANTHROPIC_API_KEY)' : '';
        say(`AI analysis enabled via ${provider}${via}. Set AI_PROVIDER to switch.\n`);
      } else if (staticAnalyzer.needsRuleDownload()) {
        // Disclosed, not buried: the only time semgrep touches the network.
        say('First semgrep run on this machine: rules will be downloaded to ~/.semgrep.');
        say('Later runs use that cache and need no network.\n');
      }

      const cache = new CacheManager();
      const orchestrator = new ToolsOrchestrator();
      const deduplicator = new FindingsDeduplicator();
      const semanticFilter = options.filterFp && useAI ? new SemanticFilter() : null;

      // Check tool availability early if tools requested
      const usingTools = options.withSecrets || options.withBandit || options.withLinting || options.withDependencies || options.withAllChecks;
      if (usingTools) {
        const availability = orchestrator.checkToolAvailability();
        const missing = availability.filter((t) => !t.installed);
        if (missing.length > 0) {
          say('⚠️  Some tools are not installed:');
          for (const t of missing) {
            say(`   → ${t.name}`);
          }
          say('   Run: glance-scanner install-tools\n');
        }
      }

      // The invocation decides who is reading. --repo is someone evaluating
      // code they did not write; --path and --file are someone scanning their
      // own tree. Stored once here and used only in the verdict and the action
      // sentences, never in what is found or how it is ranked.
      const frame: Frame = options.repo ? 'adopter' : 'author';

      let files: string[] = [];
      let scanDir: string = '';
      let cleanupDirs: string[] = [];

      // --repo flag: clone to tmp, scan, clean up
      if (options.repo) {
        const repoDir = path.join('/tmp', `glance-repo-${Date.now()}`);
        say(`📦 Cloning ${options.repo}...`);
        const { execSync } = require('child_process');
        execSync(`git clone --depth 1 ${options.repo} ${repoDir}`, { stdio: 'pipe' });
        files = getFilesRecursive(repoDir);
        scanDir = repoDir;
        cleanupDirs.push(repoDir);
        say(`   ${files.length} files found.\n`);
      } else if (options.file) {
        files = [options.file];
        scanDir = path.dirname(options.file);
      } else if (options.path) {
        files = getFilesRecursive(options.path);
        scanDir = options.path;
      } else {
        console.error('Please provide --file, --path, or --repo');
        exitAfterFlush(1);
      }

      say(`Scanning ${files.length} file(s)...\n`);
      if (semanticFilter) {
        say('🔍 Semantic filtering ENABLED (reduces false positives)\n');
      }

      let allSemanticFindings: any[] = [];
      let allToolFindings: any[] = [];
      let engineRuns: EngineRun[] = [];

      // Static engines run ONCE over the whole scan, not per file: semgrep
      // pays ~2.5s of startup per invocation, and npm audit is a property of a
      // directory. Only the AI path is per-file, because that is an API call
      // per file and the cache is keyed on file content.
      // The engines always run. `--ai` adds interpretation on top of them and
      // never replaces them: an engine result is deterministic and reproducible,
      // a model's reading of it is neither, and the report has to be able to say
      // which layer produced which sentence.
      {
        const { findings: staticFindings, engines } = await staticAnalyzer.scan(files, scanDir, {
          disposableTree: Boolean(options.repo),
        });
        allToolFindings.push(...staticFindings);
        engineRuns = engines;

        // The banner names the mode actually running. It used to say "no API
        // key" unconditionally, including on --ai runs, because the static
        // block became unconditional when the engines stopped being optional.
        say(useAI
          ? `Static analysis, then AI interpretation via ${resolveProvider()}.`
          : 'Static analysis (no API key). Add --ai to interpret each finding.');
        for (const line of StaticAnalyzer.describe(engines)) say(line);
        say('');

        // A warning here means part of the scan did not happen. It goes to
        // stderr as well, because a warning that only ever appears above a
        // report is a warning that gets scrolled past.
        for (const e of engines) {
          for (const w of e.warnings || []) console.error(`warning: ${e.name}: ${w}`);
          if (!e.ran && /scanned 0 of/.test(e.reason || '')) console.error(`warning: ${e.name}: ${e.reason}`);
        }

        if (!engines.some((e) => e.ran)) {
          // Nothing was available. Say so plainly and stop. There is no
          // fallback to fabricated output.
          say('No static analysis engine is available, so nothing was scanned.');
          say('  Install one: glance-scanner install-tools --semgrep');
          say('  Or add --ai with an AI_API_KEY for semantic analysis.');
        }
      }

      for (const file of files) {
        if (!fs.existsSync(file)) continue;
        const code = fs.readFileSync(file, 'utf-8');

        // Tool-based scans (always available, no AI needed)
        const toolOptions = {
          semanticOnly: false,
          withSecrets: options.withSecrets || options.withAllChecks,
          withBandit: options.withBandit || options.withAllChecks,
          withLinting: options.withLinting || options.withAllChecks,
          withDependencies: options.withDependencies || options.withAllChecks,
        };

        if (Object.values(toolOptions).some((v) => v)) {
          const toolFindings = await orchestrator.runAllTools(file, scanDir, toolOptions);
          allToolFindings.push(...toolFindings);
        }
      }

      // Apply semantic filter if enabled
      if (semanticFilter && allToolFindings.length > 0) {
        say(`\n🧠 Filtering ${allToolFindings.length} findings with AI...\n`);
        const filteredFindings = await semanticFilter.filterFindings(
          allToolFindings,
          files.map((f) => { try { return fs.readFileSync(f, 'utf-8'); } catch { return ''; } }).join('\n---\n')
        );

        const fpCount = filteredFindings.filter((f) => !f.isRealVulnerability).length;
        say(`  ${fpCount} likely false positives filtered out.\n`);

        allToolFindings = filteredFindings
          .filter((f) => f.isRealVulnerability)
          .map((f) => {
            const modified = { ...f.original };
            (modified as any).confidence = f.confidence;
            (modified as any).isFalsePositive = !f.isRealVulnerability;
            (modified as any).filteringReasoning = f.reasoning;
            return modified;
          });
      }

      // The interpreter: one bounded question per finding, on the user's key.
      //
      // It runs AFTER the engines and its output is attached to findings rather
      // than merged into them. applyInterpretations is the only writer, and it
      // writes two fields; nothing here can drop a finding or move a severity.
      let interpreterTotals: { input: number; output: number; calls: number } | null = null;
      if (useAI && allToolFindings.length > 0) {
        const interp = new Interpreter();
        say(`\nInterpreting ${allToolFindings.length} finding(s) with ${resolveProvider()}...`);
        const byIndex = new Map<number, Interpretation>();
        for (let i = 0; i < allToolFindings.length; i++) {
          const f: any = allToolFindings[i];
          const text = f.file ? readFileForWindow(f.file) : null;
          byIndex.set(i, await interp.interpret(f, text));
        }
        allToolFindings = applyInterpretations(allToolFindings, byIndex);
        interpreterTotals = interp.totals();
        // Never a bare zero. A run where every call failed reads nothing like a
        // run that had nothing to do, and the first version printed the same
        // "0 calls, 0 tokens" line for both.
        const summary = interpretationSummary(byIndex.size, interpreterTotals, interp.failures);
        say(`  ${summary}`);
        say('  Interpretation is best effort and never changes a finding.\n');
        // A run where nothing was interpreted is a partial result, and partial
        // results go to stderr as well, like a skipped engine.
        if (interpreterTotals.calls === 0 && byIndex.size > 0) {
          console.error(`warning: AI interpretation: ${summary}`);
        }
      }

      // Deduplicate and generate report.
      //
      // Paths are relativised BEFORE dedup, not after: the dedup key is built
      // from the file path, so rewriting afterwards would leave keys naming a
      // directory that no longer exists, and two runs of the same repo would
      // never agree.
      if (options.repo && scanDir) {
        allToolFindings = relativiseFindings(allToolFindings, scanDir);
        allSemanticFindings = relativiseFindings(allSemanticFindings, scanDir);
      }
      const unifiedFindings = deduplicator.deduplicate(allSemanticFindings, allToolFindings);
      const report = deduplicator.generateReport(unifiedFindings);

      // Close the cache BEFORE writing the report, not after. It is the only
      // thing on this path that can throw once the findings are in hand, and a
      // throw after the write reaches the catch below, which exits. An exit
      // after a large write to a pipe is how output gets truncated. Nothing
      // that can fail may run between the report and the end of the process.
      await cache.close();

      if (options.json) {
        // `engines` rides along so a machine consumer can tell a clean scan
        // from a scan that did not happen. Without it, `findings: []` is
        // ambiguous in exactly the way this work exists to fix.
        console.log(deduplicator.generateJSON({ ...report, engines: engineRuns }));
      } else {
        printUnifiedReport(report, options.verbose ? files : [], frame, engineRuns, files.length);
      }

      // Cleanup cloned repos. Already total: rmSync is wrapped, so nothing
      // here can reach the catch below. `cache.close()` ran before the report
      // was written, deliberately -- see above.
      for (const dir of cleanupDirs) {
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      exitAfterFlush(1);
    }
  });

function printMissingAIKeyHelp(provider: string): void {
  console.log('AI_API_KEY not set. This is your AI provider key, not a Glance account.');
  console.log('   Get one from your provider:');
  console.log('   -> Anthropic: https://console.anthropic.com');
  console.log('   -> OpenAI: https://platform.openai.com/api-keys');
  console.log('   -> OpenRouter: https://openrouter.ai/keys');
  console.log('   Then: export AI_API_KEY=***');
  console.log('   Or skip `--ai` to run in free mock mode.');
  console.log('');
  console.log(`   Provider is currently: ${provider}. Set AI_PROVIDER to switch.`);
  console.log('');
}

function getFilesRecursive(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const files: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!entry.name.startsWith('.') && entry.name !== 'node_modules') {
        files.push(...getFilesRecursive(path.join(dir, entry.name)));
      }
    } else if (['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.sh', '.rb', '.php', '.yaml', '.yml', '.json', '.xml'].includes(path.extname(entry.name))) {
      files.push(path.join(dir, entry.name));
    }
  }

  return files;
}

function printCodeContext(filePath: string, line: number, scannedFiles: string[], contextLines: number = 4): void {
  // Resolve file: if "unknown", try to find the right file from scanned files
  let resolvedPath = filePath;
  if (filePath === 'unknown' && scannedFiles.length > 0) {
    // If only one file was scanned, use it
    if (scannedFiles.length === 1) {
      resolvedPath = scannedFiles[0];
    }
  }

  try {
    const code = fs.readFileSync(resolvedPath, 'utf-8');
    const lines = code.split('\n');
    const start = Math.max(0, line - contextLines - 1);
    const end = Math.min(lines.length, line + contextLines);

    // Only show if the line number is valid
    if (line < 1 || line > lines.length) return;

    const pad = String(end).length;

    for (let i = start; i < end; i++) {
      const lineNum = i + 1;
      const marker = lineNum === line ? '>' : ' ';
      const gutter = String(lineNum).padStart(pad);
      // Sixth site, and the one the grep can never see: this is a raw source
      // line out of the file under report, printed under --verbose. It is the
      // same class as evidence and worse in volume, nine lines of it per
      // finding. Escaped, not quoted, because a gutter already marks where the
      // line begins and quoting every context line would make code unreadable.
      console.log(`   ${marker} ${gutter} | ${escapeControls(lines[i])}`);
    }
    console.log('');
  } catch {
    // File not readable — skip context
  }
}

function printUnifiedReport(
  report: any,
  verboseFiles: string[] = [],
  frame: Frame = 'author',
  engines: { name: string; ran: boolean; reason?: string }[] = [],
  fileCount = 0
) {
  const { summary, findings } = report;

  console.log(`\n=== ${MARK} GLANCE SECURITY REPORT ===\n`);

  // The verdict, first, before any counts. It answers the question the reader
  // actually has; the counts below are the evidence for it. Derived from the
  // severity mix and the rule classes -- see verdict.ts.
  //
  // Not passed through renderField: every character of it is generated here
  // from integers and fixed strings, with no tool output interpolated.
  // The verdict is computed from the ENGINE results only. `--ai` may append a
  // best-effort count after it; it can never change a severity claim, because
  // verdictLine never sees an interpretation.
  const triaged = triagedFalsePositives(findings);
  const tail = triaged > 0
    ? ` ${triaged} finding${triaged === 1 ? '' : 's'} triaged likely false positive by AI review (best effort).`
    : '';
  console.log(`${verdictLine(findings, engines, frame, fileCount)}${tail}\n`);

  console.log(`📊 Summary:`);
  console.log(`  Total Issues: ${summary.total}`);
  console.log(`  Critical: ${summary.critical}`);
  console.log(`  High: ${summary.high}`);
  console.log(`  Medium: ${summary.medium}`);
  console.log(`  Low: ${summary.low}`);
  console.log(`  Tools: ${summary.toolsCovered.join(', ')}\n`);

  if (findings.length === 0) {
    // No "✓ clean" line here. The verdict above already said what ran and what
    // it does not cover, and a tick beside it would undo that.
    return;
  }

  console.log(`📋 Findings (${findings.length}):\n`);

  for (const finding of findings) {
    const severityEmoji: Record<string, string> = {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🔵',
    };

    // The line number is ours, an integer field, so renderPath places it outside
    // the quotes where it can never read as part of the name. It is passed in
    // rather than concatenated afterwards so there is one code path for both.
    const confidenceNote = finding.confidence ? ` [${renderField(finding.confidence)} confidence]` : '';
    // Same values as the surfaces report, different command. Found by
    // tools/render-safety.js, not by the work order that fixed the other one,
    // which is the whole reason that check exists.
    // An audit-class rule reports a construct worth looking at, not a defect
    // it has established. Tagged inline so the severity is never read alone.
    const auditTag = isAuditClass(finding) ? ' [audit]' : '';
    console.log(`${severityEmoji[finding.severity]} [${renderField(finding.severity)}]${auditTag} ${renderPath(finding.file, finding.line)}${confidenceNote}`);
    // More than one category at one line means the rules disagree about what
    // the problem IS, not that one of them is noise. Both get named.
    const others = (finding.categories || []).filter((c) => c !== finding.category);
    console.log(`   Category: ${renderField(finding.category)}${others.length ? ` (also: ${others.map((c: string) => renderField(c)).join(', ')})` : ''}`);
    // A tool's message quotes the offending source line, so it is attacker
    // text with a vendor's wrapper around it.
    console.log(`   Message: ${escapeControls(finding.message)}`);
    console.log(`   Tools: ${finding.tools.map((x: string) => renderField(x)).join(', ')}`);
    // Every rule that fired here. With collapsing on file+line, this is the
    // only place the count of contributing rules is visible.
    if (finding.rules && finding.rules.length) {
      console.log(`   Rules: ${finding.rules.map((r: string) => renderField(r, 80)).join(', ')}`);
    }
    // One sentence on what to do, derived from the rule class. Absent when the
    // rule does not support one: see actionFor.
    const action = actionFor(finding);
    if (action) console.log(`   Action: ${escapeControls(action)}`);

    // The interpretation, labelled as a separate layer. The engine said the
    // finding; the model said this. A reader must never have to guess which.
    if (finding.interpretation) {
      const it = finding.interpretation;
      const TRIAGE_LABEL: Record<string, string> = {
        looks_real: 'looks real',
        likely_false_positive: 'likely false positive',
        needs_human: 'needs a human',
      };
      if (it.skipped) {
        // Not an opinion. Say plainly that no review happened and why, so this
        // can never be mistaken for "the reviewer looked and had nothing to add".
        console.log(`   AI review: NOT AVAILABLE — ${escapeControls(it.skipped)}`);
        console.log(`     ${escapeControls(it.explanation)}`);
      } else {
        // NOT renderField. That escaper is for values a tool or a model
        // supplied; it allows [A-Za-z0-9._-] and turns everything else into
        // '?', which rendered "needs a human" as "needs?a?human". This label is
        // a literal chosen from a closed enum in this file, so there is nothing
        // untrusted to escape. `it.triage` is only reached when the enum check
        // already passed, and it is escaped, because that is the model's word.
        const label = TRIAGE_LABEL[it.triage] || renderField(it.triage);
        console.log(`   AI review (best effort): ${label}`);
        console.log(`     ${escapeControls(it.explanation)}`);
      }
      if (it.suggested_fix) {
        // Rendered, never applied. The scanner does not write to the tree it
        // was pointed at, and a diff from a model reading attacker-authored
        // code is the last thing that should be an exception to that.
        console.log('     Suggested fix (not applied):');
        for (const l of String(it.suggested_fix).split('\n').slice(0, 40)) {
          console.log(`       ${escapeControls(l)}`);
        }
      }
    }

    if (finding.filteringReasoning) {
      // Fifth instance of the same bug, found 1 Sep by auditing the sites the
      // grep does not know about. This string is the model's REASONING line,
      // parsed at semantic-filter.ts:169. The model is fed the scanned file's
      // content, so the text it echoes back is attacker-influenceable. The
      // capture stops at U+000A, so it cannot forge a line break, but ESC,
      // U+2028 and the bidi marks passed straight through to the terminal.
      console.log(`   Verification: ${escapeControls(finding.filteringReasoning)}`);
    }

    // Verbose mode: show code context around the finding
    if (verboseFiles.length > 0 && finding.line && finding.file) {
      let filePath = finding.file;
      // If the finding file path is relative, try to resolve against verboseFiles
      if (!path.isAbsolute(filePath)) {
        // Try to find the file in the scanned files list
        const match = verboseFiles.find((f) => f.endsWith(filePath) || f.endsWith(finding.file));
        if (match) filePath = match;
      }
      printCodeContext(filePath, finding.line, verboseFiles);
    }

    console.log();
  }
}

program.parse();