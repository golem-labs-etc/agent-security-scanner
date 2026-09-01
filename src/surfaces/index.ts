/**
 * The agent-surface scan engine.
 *
 * Takes an Inventory (produced by a platform adapter) and returns findings.
 * It contains no knowledge of Hermes, Claude Code, Cursor or any other host.
 * The adapter knows where the files are; this knows what is wrong with them.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { Inventory, Finding, SurfaceReport, Severity, Policy, Warning } from './types';
import { scanMcpServer, RawFinding } from './mcp-rules';
import { scanPromptFile } from './prompt-rules';
import { StaticAnalyzer } from '../static-analyzer';
import { canonical } from './text';
import { DEFAULT_POLICY, findPlantedConfigs, plantedConfigWarnings } from './config';

export * from './types';
export { discoverInventory, discoverDefaultInventory, defaultSurfaceLocations } from './discover';
export * from './config';
export { findObfuscation } from './obfuscation';

/**
 * Stable fingerprint over category, path, line and normalized evidence.
 *
 * Normalized, so a whitespace edit or a case change does not mint a new id and
 * re-alert something a caller has already baselined. Evidence is folded
 * through the same canonicalisation the detectors use, so an attacker cannot
 * defeat a baseline by re-hiding the same directive a different way.
 */
export function fingerprint(
  category: string,
  filePath: string,
  line: number | undefined,
  evidence: string
): string {
  const h = crypto.createHash('sha256');
  h.update(
    [
      category,
      filePath,
      line === undefined ? '' : String(line),
      canonical(evidence || '').replace(/\s+/g, ' ').trim(),
    ].join(' ')
  );
  return h.digest('hex').slice(0, 8);
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'info'];

function severityOfTool(s: string): Severity {
  const v = (s || '').toLowerCase();
  if (v === 'critical') return 'critical';
  if (v === 'high' || v === 'error') return 'high';
  if (v === 'medium' || v === 'moderate' || v === 'warning') return 'medium';
  return 'info';
}

export interface ScanOptions {
  /**
   * Include the matched text on each finding.
   *
   * Off by default, and that default lives here rather than in the caller,
   * because the caller is sometimes an LLM prompt. Quoting an injection
   * payload into an agent's context is delivering it.
   */
  evidence?: boolean;
  engineVersion?: string;
  /** Injected in tests. Defaults to the real static engine. */
  staticAnalyzer?: StaticAnalyzer | null;
  /** Set false to skip the code engine entirely (surfaces only). */
  scanCode?: boolean;
  now?: string;
  /** How a directive inside a code fence is reported. Defaults to balanced. */
  policy?: Policy;
  /** Warnings raised before the scan started, e.g. by policy resolution. */
  warnings?: Warning[];
  /** Directories to sweep for a planted config. Root mode passes the root. */
  configScanRoots?: string[];
}

export async function scanSurfaces(
  inv: Inventory,
  opts: ScanOptions = {}
): Promise<SurfaceReport> {
  const raws: RawFinding[] = [];
  const policy: Policy = opts.policy || DEFAULT_POLICY;

  const servers = inv.mcp_servers || [];
  const prompts = inv.prompt_files || [];
  const code = inv.code_files || [];

  // A config file inside the scan target is never read. It is reported,
  // because a tree that tries to configure the tool inspecting it is itself
  // worth knowing about.
  const planted = findPlantedConfigs(
    ([] as string[])
      .concat(prompts.map((p) => p.path))
      .concat(code.map((c) => c.path))
      .concat(servers.map((s2) => s2.source)),
    opts.configScanRoots || []
  );
  const warnings: Warning[] = (opts.warnings || []).concat(plantedConfigWarnings(planted));

  for (const s of servers) {
    try {
      raws.push(...scanMcpServer(s));
    } catch (e) {
      // A malformed entry must not take the scan down. Skipping it is one
      // missed detection; throwing is every detection missed.
    }
  }

  // Content key per prompt file. The same skill copied into every profile is
  // the same file, and its findings are the same findings.
  const contentKey: Record<string, string> = {};

  for (const p of prompts) {
    try {
      const text = fs.readFileSync(p.path, 'utf8');
      contentKey[p.path] = crypto.createHash('sha256').update(text).digest('hex');
      raws.push(...scanPromptFile(p.path, text, policy));
    } catch (e) {
      // Unreadable file: not a finding, and not fatal.
    }
  }

  const findings: Finding[] = raws.map((r) => {
    const key = r.surface === 'prompt' ? contentKey[r.path] : undefined;
    const f: Finding = {
      // Prompt findings key on content, not path: see `Finding.id`.
      id: fingerprint(r.category, key ? 'content:' + key : r.path, r.line, r.evidence),
      category: r.category,
      severity: r.severity,
      surface: r.surface,
      path: r.path,
    };
    if (r.line !== undefined) f.line = r.line;
    if (r.endLine !== undefined && r.endLine !== r.line) f.end_line = r.endLine;
    if (opts.evidence) f.evidence = r.evidence;
    return f;
  });

  // code_files route to the existing engine, unchanged.
  if (code.length && opts.scanCode !== false) {
    const analyzer = opts.staticAnalyzer || new StaticAnalyzer();
    try {
      const files = code.map((c) => c.path);
      const dir = path.dirname(files[0] || '.');
      const res = await analyzer.scan(files, dir);
      for (const tf of res.findings) {
        const category = (tf.category || tf.tool) as any;
        const f: Finding = {
          id: fingerprint(category, tf.file, tf.line, tf.message),
          category,
          severity: severityOfTool(tf.severity),
          surface: 'code',
          path: tf.file,
        };
        if (tf.line !== undefined) f.line = tf.line;
        if (opts.evidence) f.evidence = tf.message;
        findings.push(f);
      }
    } catch (e) {
      // The code engine is optional and can be absent (no semgrep installed).
      // Surface findings still stand on their own.
    }
  }

  // Dedupe on the fingerprint, and keep the locations.
  //
  // The same finding reached twice is one finding, and because a prompt
  // finding's id is keyed on file content rather than on path, "twice" now
  // includes the same skill file copied into twenty-two profiles. Dropping the
  // duplicates silently would hide where the problem actually lives, so the
  // extra locations are reported on the finding instead: one problem, every
  // address it has.
  const byId: Record<string, Finding> = {};
  const locations: Record<string, string[]> = {};
  const unique: Finding[] = [];
  for (const f of findings) {
    if (!byId[f.id]) {
      byId[f.id] = f;
      locations[f.id] = [f.path];
      unique.push(f);
    } else if (locations[f.id].indexOf(f.path) === -1) {
      locations[f.id].push(f.path);
    }
  }
  for (const f of unique) {
    const paths = locations[f.id].slice().sort();
    if (paths.length > 1) {
      f.path = paths[0];
      f.occurrences = paths.length;
      f.also_in = paths.slice(1);
    }
  }

  unique.sort((a, b) => {
    const d =
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (d !== 0) return d;
    if (a.path !== b.path) return a.path < b.path ? -1 : 1;
    return (a.line || 0) - (b.line || 0);
  });

  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    info: 0,
  };
  for (const f of unique) counts[f.severity]++;

  return {
    schema: 1,
    engine_version:
      opts.engineVersion || require('../../package.json').version,
    scanned_at: opts.now || new Date().toISOString(),
    policy,
    evidence: !!opts.evidence,
    warnings,
    total_scanned: servers.length + prompts.length + code.length,
    counts,
    findings: unique,
  };
}
