#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import { AIAnalyzer } from './analyzer';
import { MockAnalyzer } from './mock-analyzer';
import { CacheManager } from './cache';
import { ToolsOrchestrator } from './tools-orchestrator';
import { FindingsDeduplicator } from './deduplicator';
import { SemanticFilter } from './semantic-filter';
import { resolveProvider, resolveApiKey } from './env-key';
import { registerGuardCommands } from './guard/cli';

dotenv.config();

const program = new Command();

program
  .name('glance-scanner')
  .description('Semantic security scanner for AI agents. Mock mode by default — no API costs.')
  .version(require('../package.json').version);

registerGuardCommands(program);


// ── install-tools command ──────────────────────────────────────────────────
program
  .command('install-tools')
  .description('Install missing Python security tools (detect-secrets, bandit, pylint, pip-audit)')
  .option('--secrets', 'Install only detect-secrets')
  .option('--bandit', 'Install only bandit')
  .option('--linting', 'Install only pylint')
  .option('--dependencies', 'Install only pip-audit')
  .action(async (options) => {
    try {
      const orchestrator = new ToolsOrchestrator();

      const selected: string[] = [];
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
        console.log('    Try: python3 -m pip install --user ' + result.failed.join(' '));
      }

      console.log('');
      if (result.failed.length === 0) {
        console.log('✅ All tools ready. Run: glance-scanner analyze --file app.py --with-all-checks');
      }
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
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
      // Default to mock mode (pattern-based). Only use AI if user explicitly opts in.
      const useAI = options.ai || options.semantic || options.semanticOnly;

      // Pre-check AI key before constructing, friendly error with provider links
      if (useAI) {
        const provider = resolveProvider();
        const resolved = resolveApiKey(provider);
        if (!resolved.key) {
          printMissingAIKeyHelp(provider);
          process.exit(1);
        }
      }

      const analyzer = useAI ? new AIAnalyzer() : new MockAnalyzer();
      if (!useAI) {
        console.log('Mock mode (pattern-based detection). Add --ai for semantic analysis.\n');
      } else {
        const provider = resolveProvider();
        const resolved = resolveApiKey(provider);
        const via = resolved.source === 'ANTHROPIC_API_KEY' ? ' (via ANTHROPIC_API_KEY)' : '';
        console.log(`AI analysis enabled via ${provider}${via}. Set AI_PROVIDER to switch.\n`);
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
          console.log('⚠️  Some tools are not installed:');
          for (const t of missing) {
            console.log(`   → ${t.name}`);
          }
          console.log('   Run: glance-scanner install-tools\n');
        }
      }

      let files: string[] = [];
      let scanDir: string = '';
      let cleanupDirs: string[] = [];

      // --repo flag: clone to tmp, scan, clean up
      if (options.repo) {
        const repoDir = path.join('/tmp', `glance-repo-${Date.now()}`);
        console.log(`📦 Cloning ${options.repo}...`);
        const { execSync } = require('child_process');
        execSync(`git clone --depth 1 ${options.repo} ${repoDir}`, { stdio: 'pipe' });
        files = getFilesRecursive(repoDir);
        scanDir = repoDir;
        cleanupDirs.push(repoDir);
        console.log(`   ${files.length} files found.\n`);
      } else if (options.file) {
        files = [options.file];
        scanDir = path.dirname(options.file);
      } else if (options.path) {
        files = getFilesRecursive(options.path);
        scanDir = options.path;
      } else {
        console.error('Please provide --file, --path, or --repo');
        process.exit(1);
      }

      console.log(`Scanning ${files.length} file(s)...\n`);
      if (semanticFilter) {
        console.log('🔍 Semantic filtering ENABLED (reduces false positives)\n');
      }

      let allSemanticFindings: any[] = [];
      let allToolFindings: any[] = [];

      for (const file of files) {
        if (!fs.existsSync(file)) continue;
        const code = fs.readFileSync(file, 'utf-8');

        // Run analyzer (mock = pattern detection, AI = semantic analysis)
        let semanticResult;
        if (options.cache !== false) {
          semanticResult = await cache.get(code);
        }

        if (!semanticResult) {
          console.log(`⏳ ${file}...`);
          semanticResult = await analyzer.analyze(code, file);

          if (options.cache !== false) {
            await cache.set(code, semanticResult);
          }
        }

        // Inject file path into each finding
        const findWithFile = (semanticResult.findings || []).map((f: any) => ({
          ...f,
          file: file,
        }));
        allSemanticFindings.push(...findWithFile);

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
        console.log(`\n🧠 Filtering ${allToolFindings.length} findings with AI...\n`);
        const filteredFindings = await semanticFilter.filterFindings(
          allToolFindings,
          files.map((f) => { try { return fs.readFileSync(f, 'utf-8'); } catch { return ''; } }).join('\n---\n')
        );

        const fpCount = filteredFindings.filter((f) => !f.isRealVulnerability).length;
        console.log(`  ${fpCount} likely false positives filtered out.\n`);

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

      // Deduplicate and generate report
      const unifiedFindings = deduplicator.deduplicate(allSemanticFindings, allToolFindings);
      const report = deduplicator.generateReport(unifiedFindings);

      if (options.json) {
        console.log(deduplicator.generateJSON(report));
      } else {
        printUnifiedReport(report, options.verbose ? files : []);
      }

      // Cleanup cloned repos
      for (const dir of cleanupDirs) {
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
      }

      await cache.close();
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
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
      console.log(`   ${marker} ${gutter} | ${lines[i]}`);
    }
    console.log('');
  } catch {
    // File not readable — skip context
  }
}

function printUnifiedReport(report: any, verboseFiles: string[] = []) {
  const { summary, findings } = report;

  console.log('\n=== GLANCE SECURITY REPORT ===\n');

  console.log(`📊 Summary:`);
  console.log(`  Total Issues: ${summary.total}`);
  console.log(`  Critical: ${summary.critical}`);
  console.log(`  High: ${summary.high}`);
  console.log(`  Medium: ${summary.medium}`);
  console.log(`  Low: ${summary.low}`);
  console.log(`  Tools: ${summary.toolsCovered.join(', ')}\n`);

  if (findings.length === 0) {
    console.log('✓ No security issues found!\n');
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

    const lineInfo = finding.line ? `:${finding.line}` : '';
    const confidenceNote = finding.confidence ? ` [${finding.confidence} confidence]` : '';
    console.log(`${severityEmoji[finding.severity]} [${finding.severity}] ${finding.file}${lineInfo}${confidenceNote}`);
    console.log(`   Category: ${finding.category}`);
    console.log(`   Message: ${finding.message}`);
    console.log(`   Tools: ${finding.tools.join(', ')}`);
    if (finding.filteringReasoning) {
      console.log(`   Verification: ${finding.filteringReasoning}`);
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