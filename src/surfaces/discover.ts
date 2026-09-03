/**
 * Convenience discovery for `surfaces --root <dir>`.
 *
 * This is a fallback for people running the CLI by hand. The real inventory
 * comes from a platform adapter, which knows where its host keeps things.
 * Nothing here is host-specific: it looks for the file names every agent
 * platform happens to use, and it does not pretend to know about any of them.
 *
 * `discoverInventory` validates `root` before walking it, and throws if it is
 * missing or is not a directory. It used to just walk, and `walk()`'s catch
 * turned a typo'd path into an empty inventory: `scanned 0 ... nothing to
 * report`, exit 0, identical to a clean machine. Absence and "I never looked"
 * must not render the same, which is the whole reason
 * `discoverDefaultInventory` reports each location present or absent.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Inventory, McpServerEntry, PromptFileEntry } from './types';

const PROMPT_NAMES = [
  'SKILL.md',
  'AGENTS.md',
  'CLAUDE.md',
  'GEMINI.md',
  'SYSTEM.md',
  'PROMPT.md',
  'INSTRUCTIONS.md',
];

const MCP_CONFIG_NAMES = [
  '.mcp.json',
  'mcp.json',
  'mcp_servers.json',
  'claude_desktop_config.json',
  'settings.json',
  // Claude Code's USER-scope MCP servers. Verified 1 Sep 2026 on a real
  // install: top-level `mcpServers`, dict shape, which `parseMcpConfig`
  // already reads. Its absence here meant a Claude Code user scanned their
  // project, found project-scope `.mcp.json`, and was told they were clean
  // while every user-scope server went unread.
  //
  // NOTE THE PATH, because it is the other half of the defect. This file
  // lives at `$HOME/.claude.json`, NOT inside `~/.claude/`. Adding the name
  // only helps a walk that actually reaches `$HOME`; scanning `~/.claude`
  // still misses it, because the file is a sibling of that directory.
  '.claude.json',
];

const SKIP_DIRS = [
  'node_modules', '.git', 'dist', 'build', '.venv', 'venv',
  '__pycache__', '.next', 'target', 'vendor', '.cache',
];

/** Bounded walk. A runaway recursion into a home directory is a hang. */
function walk(root: string, maxDepth: number): string[] {
  const out: string[] = [];
  const stack: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];
  while (stack.length) {
    const { dir, depth } = stack.pop()!;
    if (depth > maxDepth) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        if (SKIP_DIRS.indexOf(e.name) !== -1) continue;
        stack.push({ dir: full, depth: depth + 1 });
      } else if (e.isFile()) {
        out.push(full);
      }
    }
  }
  return out;
}

/**
 * Pull MCP server entries out of a JSON config.
 *
 * Handles the two shapes in the wild: `{"mcpServers": {name: {...}}}` and
 * `{"mcp_servers": [{name, ...}]}`. Anything else is left alone rather than
 * guessed at.
 */
function parseMcpConfig(file: string): McpServerEntry[] {
  let doc: any;
  try {
    doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return [];
  }
  const out: McpServerEntry[] = [];

  const asEntry = (name: string, v: any): McpServerEntry => ({
    source: file,
    name,
    transport: v.transport || v.type || (v.url ? 'http' : 'stdio'),
    command: v.command || null,
    args: Array.isArray(v.args) ? v.args : [],
    url: v.url || null,
    env_keys: v.env && typeof v.env === 'object' ? Object.keys(v.env) : [],
    // The discovery path reads the config directly, so it sees inline values
    // and passes them through. An adapter that hashes instead should send
    // `env_values_hashed` and omit `env`.
    env: v.env && typeof v.env === 'object' ? v.env : null,
  });

  const dict = doc.mcpServers || doc.mcp_servers;
  if (dict && !Array.isArray(dict) && typeof dict === 'object') {
    for (const name of Object.keys(dict)) out.push(asEntry(name, dict[name]));
  } else if (Array.isArray(dict)) {
    for (const v of dict) out.push(asEntry(v.name || '(unnamed)', v));
  }
  return out;
}

/**
 * Where an agent's surfaces actually live, when nobody passed `--root`.
 *
 * WHY THIS EXISTS. Measured 1 Sep 2026: `surfaces --root ~` on a real Mac took
 * 49.7s over 3001 files and returned ten findings, and NOT ONE was reachable by
 * an agent. Four sat in `~/Downloads` including the only critical, three in
 * Hermes `optional-skills`, two in an inactive profile, one in this repo's own
 * test fixtures. A file that merely looks like a skill is not a surface. What
 * an agent loads is.
 *
 * SCOPE. This is the hand-run path. A platform adapter passes `--inventory` and
 * does its own discovery, so Hermes is deliberately not traversed here.
 *
 * WHAT IS EXCLUDED, AND WHY IT IS A LIST OF DIRECTORIES RATHER THAN OF NAMES.
 * `~/.claude` holds `.credentials.json`, `history.jsonl`, `projects/`,
 * `sessions/`, `shell-snapshots/` and `paste-cache/`: credentials and
 * conversation transcripts. Walking that directory and relying on filename
 * matching to skip them is one added filename away from reading a person's
 * chat history and quoting it back as a finding. So the named subdirectories
 * are entered and nothing else is.
 */
export interface CheckedLocation {
  path: string;
  kind: 'file' | 'tree';
  found: boolean;
}

export interface DefaultDiscoveryOptions {
  home?: string;
  cwd?: string;
  platform?: string;
}

/** The locations, resolved but not yet tested for existence. */
export function defaultSurfaceLocations(
  opts: DefaultDiscoveryOptions = {}
): Array<{ path: string; kind: 'file' | 'tree' }> {
  const home = opts.home || os.homedir();
  const cwd = opts.cwd || process.cwd();
  const platform = opts.platform || process.platform;

  const out: Array<{ path: string; kind: 'file' | 'tree' }> = [
    // User scope. `.claude.json` is at $HOME, NOT inside ~/.claude/, which is
    // why naming the directory was never enough.
    { path: path.join(home, '.claude.json'), kind: 'file' },
    { path: path.join(home, '.claude', 'CLAUDE.md'), kind: 'file' },
    { path: path.join(home, '.claude', 'settings.json'), kind: 'file' },
    { path: path.join(home, '.claude', 'settings.local.json'), kind: 'file' },
    { path: path.join(home, '.claude', 'skills'), kind: 'tree' },
    { path: path.join(home, '.claude', 'plugins'), kind: 'tree' },
    // Project scope, relative to where the person ran the command.
    { path: path.join(cwd, '.mcp.json'), kind: 'file' },
    { path: path.join(cwd, 'CLAUDE.md'), kind: 'file' },
    { path: path.join(cwd, 'AGENTS.md'), kind: 'file' },
    { path: path.join(cwd, '.claude', 'skills'), kind: 'tree' },
  ];

  if (platform === 'darwin') {
    out.push({
      path: path.join(home, 'Library', 'Application Support', 'Claude',
                      'claude_desktop_config.json'),
      kind: 'file',
    });
  } else if (platform === 'win32') {
    const appdata = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    out.push({
      path: path.join(appdata, 'Claude', 'claude_desktop_config.json'),
      kind: 'file',
    });
  } else {
    out.push({
      path: path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
      kind: 'file',
    });
  }

  return out;
}

/** Classify one file into the inventory. Shared with `discoverInventory`. */
function classify(
  f: string,
  mcp_servers: McpServerEntry[],
  prompt_files: PromptFileEntry[]
): void {
  const base = path.basename(f);
  if (MCP_CONFIG_NAMES.indexOf(base) !== -1) {
    mcp_servers.push(...parseMcpConfig(f));
  }
  if (PROMPT_NAMES.indexOf(base) !== -1) {
    prompt_files.push({ path: f });
  }
}

/**
 * Discovery with no `--root`: only what an agent can reach.
 *
 * Returns the inventory AND the locations consulted, present or absent.
 * Absence is reported rather than passed over, because a clean report from a
 * scanner that checked nothing is indistinguishable from a clean machine, and
 * that is the failure this whole function exists to avoid.
 */
export function discoverDefaultInventory(
  opts: DefaultDiscoveryOptions = {}
): { inventory: Inventory; checked: CheckedLocation[] } {
  const mcp_servers: McpServerEntry[] = [];
  const prompt_files: PromptFileEntry[] = [];
  const checked: CheckedLocation[] = [];

  for (const loc of defaultSurfaceLocations(opts)) {
    let found = false;
    try {
      const st = fs.statSync(loc.path);
      if (loc.kind === 'file' && st.isFile()) {
        found = true;
        classify(loc.path, mcp_servers, prompt_files);
      } else if (loc.kind === 'tree' && st.isDirectory()) {
        found = true;
        // Shallower than `--root`. A skills directory is not deep, and a
        // bounded walk here is the difference between reading a plugin tree
        // and reading a home directory.
        for (const f of walk(loc.path, 4)) classify(f, mcp_servers, prompt_files);
      }
    } catch (e) {
      found = false;
    }
    checked.push({ path: loc.path, kind: loc.kind, found });
  }

  return {
    inventory: { schema: 1, mcp_servers, prompt_files, code_files: [] },
    checked,
  };
}

export function discoverInventory(root: string, maxDepth = 6): Inventory {
  // Check the root itself once, here, rather than loosening what `walk()`
  // tolerates. `walk()` must keep skipping a subdirectory it cannot read --
  // a permissions change or a vanishing mount mid-walk is not a reason to
  // fail the whole scan. The root not existing is.
  //
  // Thrown rather than returned: `cli.ts`'s `.action()` already wraps this in
  // a try/catch that prints `error: <message>` and exits 2, the same path that
  // handles an unsupported inventory schema. The return type stays `Inventory`
  // so existing callers keep destructuring the result as they do today.
  let stat: fs.Stats;
  try {
    stat = fs.statSync(root);
  } catch (e) {
    throw new Error(`Root directory does not exist: ${root}`);
  }
  if (!stat.isDirectory()) {
    throw new Error(`Root path exists but is not a directory: ${root}`);
  }

  const files = walk(root, maxDepth);
  const mcp_servers: McpServerEntry[] = [];
  const prompt_files: PromptFileEntry[] = [];

  for (const f of files) {
    const base = path.basename(f);
    if (MCP_CONFIG_NAMES.indexOf(base) !== -1) {
      mcp_servers.push(...parseMcpConfig(f));
    }
    if (PROMPT_NAMES.indexOf(base) !== -1) {
      prompt_files.push({ path: f });
    }
  }

  return { schema: 1, mcp_servers, prompt_files, code_files: [] };
}
