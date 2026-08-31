/**
 * Rules for MCP server entries.
 *
 * Severity discipline matters more here than coverage does. `unpinned_remote_exec`
 * is `info` and stays `info`: `npx -y` is how very nearly every MCP server in
 * the ecosystem ships, so raising it turns the status chip red on a clean
 * machine. A tool that is red on install is a tool people learn to ignore, and
 * an ignored tool catches nothing.
 */

import { McpServerEntry, Finding, Category, Severity } from './types';
import { secretShape } from './secrets';

export interface RawFinding {
  category: Category;
  severity: Severity;
  surface: 'mcp' | 'prompt';
  path: string;
  line?: number;
  /** Last line of the match, when a rule's window is wider than one line. */
  endLine?: number;
  evidence: string;
}

/**
 * Hosts that never leave the machine, so plain HTTP to them crosses no
 * network. Checked against the parsed hostname, never a substring of the URL:
 * `http://localhost.evil.com/` must not pass, and it does not, because its
 * hostname is `localhost.evil.com`.
 */
function isLoopback(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1' || h === '0.0.0.0' || h === '::') return true;
  if (h.endsWith('.localhost')) return true;
  if (h.endsWith('.local')) return true;
  // 127.0.0.0/8
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)) return true;
  return false;
}

function hostOf(url: string): string | null {
  // Deliberately not `new URL`: an unparseable URL should be treated as
  // unknown rather than throwing out of the scan.
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?(\[[^\]]+\]|[^/:?#]+)/i.exec(url);
  return m ? m[1] : null;
}

/** Shell metacharacters that change what a command does. */
const METACHAR_RE = /[;&|`\n\r]|\$\(|\|\||&&|>>|[<>]/;
const SHELLS = ['sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'fish', 'cmd', 'cmd.exe', 'powershell', 'pwsh'];

function isShell(command: string): boolean {
  const base = (command || '').split(/[\\/]/).pop() || '';
  return SHELLS.indexOf(base.toLowerCase()) !== -1;
}

/** Package specifiers that fetch-and-run without a pinned version. */
function unpinnedRemoteExec(command: string, args: string[]): string | null {
  const base = (command || '').split(/[\\/]/).pop() || '';
  const cmd = base.toLowerCase();

  if (cmd === 'npx') {
    const yes = args.some((a) => a === '-y' || a === '--yes');
    // First non-flag argument is the package spec.
    const pkg = args.find((a) => !a.startsWith('-'));
    if (!pkg) return null;
    // A version is pinned when the spec carries `@x` after the package name.
    // `@scope/name` alone is not a pin.
    const pinned = /^(@[^/]+\/)?[^@]+@.+/.test(pkg);
    if (yes && !pinned) return 'npx ' + pkg;
    return null;
  }
  if (cmd === 'uvx') {
    const pkg = args.find((a) => !a.startsWith('-'));
    if (pkg && !/[=<>~]=?|@/.test(pkg)) return 'uvx ' + pkg;
    return null;
  }
  if (cmd === 'deno') {
    if (args[0] === 'run' && args.some((a) => /^https?:\/\//.test(a))) {
      return 'deno run ' + args.filter((a) => /^https?:\/\//.test(a))[0];
    }
    return null;
  }
  if (cmd === 'pip' || cmd === 'pip3') {
    if (args[0] === 'run') return 'pip run';
    return null;
  }
  return null;
}

export function scanMcpServer(entry: McpServerEntry): RawFinding[] {
  const out: RawFinding[] = [];
  const path = entry.source;
  const args = entry.args || [];
  const command = entry.command || '';

  // ── unencrypted_transport ────────────────────────────────────────────────
  if (entry.url && /^http:\/\//i.test(entry.url.trim())) {
    const host = hostOf(entry.url.trim());
    if (host && !isLoopback(host)) {
      out.push({
        category: 'unencrypted_transport',
        severity: 'high',
        surface: 'mcp',
        path,
        evidence: entry.name + ' -> ' + entry.url,
      });
    }
  }

  // ── secret_in_config ─────────────────────────────────────────────────────
  // Only where the config carries the value inline. `env_keys` alone can
  // never fire this: a name is not a secret.
  if (entry.env) {
    for (const k of Object.keys(entry.env)) {
      const shape = secretShape(entry.env[k]);
      if (shape) {
        out.push({
          category: 'secret_in_config',
          severity: 'critical',
          surface: 'mcp',
          path,
          evidence: entry.name + ' env ' + k + ' = <' + shape + '>',
        });
      }
    }
  }

  // ── command_injection_risk ───────────────────────────────────────────────
  // Args handed to execve are not shell-interpreted, so a bare `|` in an
  // argument is not a finding. It becomes one when a shell is the command, or
  // when the argument carries a substitution that some wrapper will expand.
  if (command && METACHAR_RE.test(command)) {
    out.push({
      category: 'command_injection_risk',
      severity: 'high',
      surface: 'mcp',
      path,
      evidence: entry.name + ' command: ' + command,
    });
  } else if (isShell(command)) {
    const inline = args.filter((a) => METACHAR_RE.test(a));
    if (inline.length) {
      out.push({
        category: 'command_injection_risk',
        severity: 'high',
        surface: 'mcp',
        path,
        evidence: entry.name + ' shell arg: ' + inline[0],
      });
    }
  } else {
    const subst = args.filter((a) => /\$\(|`/.test(a));
    if (subst.length) {
      out.push({
        category: 'command_injection_risk',
        severity: 'high',
        surface: 'mcp',
        path,
        evidence: entry.name + ' arg substitution: ' + subst[0],
      });
    }
  }

  // ── unpinned_remote_exec (info, always) ──────────────────────────────────
  const unpinned = unpinnedRemoteExec(command, args);
  if (unpinned) {
    out.push({
      category: 'unpinned_remote_exec',
      severity: 'info',
      surface: 'mcp',
      path,
      evidence: entry.name + ': ' + unpinned,
    });
  }

  return out;
}
