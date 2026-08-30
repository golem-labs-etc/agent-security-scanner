/**
 * Agent-surface scanning: shared types.
 *
 * An "agent surface" is a file an agent reads as instruction or configuration
 * rather than as code: an MCP server entry, a skill or prompt markdown file.
 * Neither `npm audit` nor semgrep reads either one, so they are a distinct
 * scan target from the code engine, and they are identical on every host --
 * Hermes, Claude Code and Cursor all keep MCP configs and skill files.
 *
 * This module contains no knowledge of any specific host. A platform adapter
 * produces an Inventory; this engine consumes it.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'info';

export type SurfaceKind = 'mcp' | 'prompt' | 'code';

export type Category =
  // MCP server entries
  | 'unencrypted_transport'
  | 'secret_in_config'
  | 'command_injection_risk'
  | 'unpinned_remote_exec'
  // prompt files
  | 'prompt_injection'
  | 'hidden_instruction'
  | 'exfiltration_instruction'
  | 'credential_leak';

export interface McpServerEntry {
  /** Config file this entry was read from. Used as the finding path. */
  source: string;
  name: string;
  transport?: string | null;
  command?: string | null;
  args?: string[] | null;
  url?: string | null;
  /** Names only. Always safe to carry. */
  env_keys?: string[] | null;
  /** Hashes, never plaintext. Present when the adapter chose to hash. */
  env_values_hashed?: string[] | null;
  /**
   * Inline env values, when and only when the config carried the value
   * literally rather than as a reference. `secret_in_config` fires on the
   * shape of these. An adapter that cannot distinguish inline from reference
   * should omit this and accept the missed detection.
   */
  env?: Record<string, string> | null;
}

export interface PromptFileEntry {
  path: string;
}

export interface CodeFileEntry {
  path: string;
}

export interface Inventory {
  schema: 1;
  mcp_servers?: McpServerEntry[];
  prompt_files?: PromptFileEntry[];
  code_files?: CodeFileEntry[];
}

export interface Finding {
  /** Stable fingerprint over category, path, line and normalized evidence. */
  id: string;
  category: Category;
  severity: Severity;
  surface: SurfaceKind;
  path: string;
  line?: number;
  /**
   * The matched text. Present ONLY when --evidence is passed.
   *
   * Absent by default, and that default is set here rather than left to the
   * caller, because the caller is sometimes an LLM prompt. A scanner that
   * quotes an injection payload into an agent's context has delivered the
   * payload.
   */
  evidence?: string;
}

export interface SurfaceReport {
  schema: 1;
  engine_version: string;
  scanned_at: string;
  total_scanned: number;
  counts: Record<Severity, number>;
  findings: Finding[];
}
