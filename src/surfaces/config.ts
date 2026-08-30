/**
 * Where policy comes from, and where it must never come from.
 *
 * Two hard constraints, both security properties rather than preferences.
 *
 * **Config is never read from the tree being scanned.** A `.glance.json` inside
 * a scanned repository or skill directory is an attack, not a convenience: ship
 * a repository that turns detection off on itself and the scan reports clean.
 * Policy comes from the user's own config location or from the flag, and a
 * config file found inside the scan target is ignored and named in a warning.
 *
 * **There is no `off`.** A level that silences a category is the first thing a
 * person reaches for when a tool is noisy, and from then on they are blind to
 * every future instance of it. Suppression belongs at the baseline, per finding
 * id, where it names one finding rather than a whole class.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Policy, POLICIES, Warning } from './types';

export const DEFAULT_POLICY: Policy = 'balanced';

/**
 * Config file names that are honoured in the user's own config location and
 * refused anywhere inside a scan target.
 */
export const CONFIG_NAMES = [
  '.glance.json',
  'glance.json',
  '.glance.config.json',
  'glance.config.json',
];

/** The user's own config location. Never anywhere inside a scan target. */
export function userConfigPath(env: NodeJS.ProcessEnv = process.env): string {
  const xdg = env.XDG_CONFIG_HOME;
  if (xdg && xdg.trim()) return path.join(xdg, 'glance', 'config.json');
  return path.join(os.homedir(), '.glance', 'config.json');
}

export function isValidPolicy(v: any): v is Policy {
  return typeof v === 'string' && POLICIES.indexOf(v as Policy) !== -1;
}

/**
 * Resolve the policy. Flag beats user config, user config beats the default.
 *
 * An unreadable or malformed user config is not an error: it falls back to the
 * default and says so. An *invalid* policy value is reported as a warning
 * rather than silently corrected, because `"policy": "off"` in a config file is
 * someone trying to do the thing this module exists to prevent.
 */
export function resolvePolicy(
  flag: string | undefined,
  env: NodeJS.ProcessEnv = process.env
): { policy: Policy; warnings: Warning[] } {
  const warnings: Warning[] = [];

  if (flag !== undefined) {
    if (!isValidPolicy(flag)) {
      throw new Error(
        'unknown policy "' + flag + '". Valid values are: ' + POLICIES.join(', ') +
        '. There is no "off" level; suppress individual findings with a baseline.'
      );
    }
    return { policy: flag, warnings };
  }

  const cfgPath = userConfigPath(env);
  try {
    const doc = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    if (doc && doc.policy !== undefined) {
      if (isValidPolicy(doc.policy)) return { policy: doc.policy, warnings };
      warnings.push({
        code: 'invalid_policy',
        path: cfgPath,
        message:
          'ignored invalid policy ' + JSON.stringify(doc.policy) + ' in ' + cfgPath +
          '; using "' + DEFAULT_POLICY + '". There is no "off" level.',
      });
    }
  } catch (e) {
    // Absent or unreadable user config is the normal case, not a problem.
  }
  return { policy: DEFAULT_POLICY, warnings };
}

/** Directories to check for a planted config, deduped. */
function dirsOf(paths: string[]): string[] {
  const seen: Record<string, true> = {};
  const out: string[] = [];
  for (const p of paths) {
    if (!p) continue;
    const d = path.dirname(p);
    if (!seen[d]) {
      seen[d] = true;
      out.push(d);
    }
  }
  return out;
}

/**
 * Find config files planted inside the scan target.
 *
 * These are never read. They are reported so the person running the scan knows
 * the tree tried to configure the tool that was inspecting it, which is itself
 * worth knowing.
 */
export function findPlantedConfigs(
  inventoryPaths: string[],
  roots: string[] = []
): string[] {
  const found: string[] = [];
  const seen: Record<string, true> = {};

  const check = (dir: string) => {
    for (const name of CONFIG_NAMES) {
      const full = path.join(dir, name);
      if (seen[full]) continue;
      try {
        if (fs.statSync(full).isFile()) {
          seen[full] = true;
          found.push(full);
        }
      } catch (e) {
        // not there
      }
    }
  };

  for (const d of dirsOf(inventoryPaths)) check(d);

  // Root mode: the planted file may sit anywhere under the tree, not only
  // beside a file that happened to be inventoried.
  for (const root of roots) {
    const stack: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];
    while (stack.length) {
      const { dir, depth } = stack.pop()!;
      if (depth > 6) continue;
      check(dir);
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch (e) {
        continue;
      }
      for (const e of entries) {
        if (!e.isDirectory() || e.isSymbolicLink()) continue;
        if (['node_modules', '.git', 'dist', 'build', '__pycache__'].indexOf(e.name) !== -1) continue;
        stack.push({ dir: path.join(dir, e.name), depth: depth + 1 });
      }
    }
  }

  return found.sort();
}

export function plantedConfigWarnings(paths: string[]): Warning[] {
  return paths.map((p) => ({
    code: 'planted_config' as const,
    path: p,
    message:
      'ignored config file inside the scan target: ' + p +
      '. Configuration is never read from the tree being scanned.',
  }));
}
