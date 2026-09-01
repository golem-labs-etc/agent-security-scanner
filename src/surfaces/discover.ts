/**
 * Convenience discovery for `surfaces --root <dir>`.
 *
 * This is a fallback for people running the CLI by hand. The real inventory
 * comes from a platform adapter, which knows where its host keeps things.
 * Nothing here is host-specific: it looks for the file names every agent
 * platform happens to use, and it does not pretend to know about any of them.
 */

import * as fs from 'fs';
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

export function discoverInventory(root: string, maxDepth = 6): Inventory {
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
