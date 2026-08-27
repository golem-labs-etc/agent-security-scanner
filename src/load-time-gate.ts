/**
 * Load-Time Trigger: Gate unsafe skills before they're loaded
 * 
 * Flow:
 * 1. Agent loads new skill
 * 2. Scan skill file(s) with security scanner
 * 3. If CRITICAL findings found: Block load, log reason
 * 4. If PASS: Allow load, cache result
 * 
 * Use Case: Prevent compromised or unsafe skills from entering agent context
 */

import { spawn } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface LoadTimeCheckResult {
  safe: boolean;
  criticalFindings: number;
  findings: any[];
  cached: boolean;
  checkTime: number;
  fingerprintHash: string;
}

export class LoadTimeGate {
  private scannerPath: string;
  private cacheDir: string;

  constructor(scannerPath: string = './dist/cli.js', cacheDir: string = './.security-cache') {
    this.scannerPath = scannerPath;
    this.cacheDir = cacheDir;

    // Create cache dir if doesn't exist
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
  }

  /**
   * Check if skill/file is safe to load
   * Returns false if CRITICAL findings detected (blocks load)
   */
  async isSafeToLoad(skillPath: string): Promise<LoadTimeCheckResult> {
    const startTime = Date.now();

    try {
      // 1. Compute fingerprint
      const fingerprint = this.computeFingerprint(skillPath);

      // 2. Check cache first
      const cached = this.checkCache(fingerprint);
      if (cached) {
        return {
          safe: !cached.hasCritical,
          criticalFindings: cached.criticalCount,
          findings: cached.findings,
          cached: true,
          checkTime: Date.now() - startTime,
          fingerprintHash: fingerprint,
        };
      }

      // 3. Run scanner
      const scanResult = await this.scanFile(skillPath);

      // 4. Extract critical findings
      const criticalFindings = scanResult.filter((f: any) => f.severity === 'CRITICAL');
      const hasCritical = criticalFindings.length > 0;

      // 5. Cache result
      this.cacheResult(fingerprint, hasCritical, scanResult);

      return {
        safe: !hasCritical,
        criticalFindings: criticalFindings.length,
        findings: scanResult,
        cached: false,
        checkTime: Date.now() - startTime,
        fingerprintHash: fingerprint,
      };
    } catch (error) {
      // On error, fail safe (block load)
      console.error('LoadTimeGate error:', error);
      return {
        safe: false,
        criticalFindings: 1,
        findings: [{ severity: 'CRITICAL', message: 'Security scan failed' }],
        cached: false,
        checkTime: Date.now() - startTime,
        fingerprintHash: '',
      };
    }
  }

  private computeFingerprint(filePath: string): string {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return crypto.createHash('sha256').update(content).digest('hex');
    } catch {
      return 'error-reading-file';
    }
  }

  private checkCache(fingerprint: string): any {
    const cachePath = path.join(this.cacheDir, `${fingerprint}.json`);
    if (fs.existsSync(cachePath)) {
      try {
        const cached = JSON.parse(fs.readFileSync(cachePath, 'utf-8'));
        return cached;
      } catch {
        return null;
      }
    }
    return null;
  }

  private cacheResult(fingerprint: string, hasCritical: boolean, findings: any[]): void {
    const cachePath = path.join(this.cacheDir, `${fingerprint}.json`);
    const cacheData = {
      hasCritical,
      criticalCount: findings.filter((f) => f.severity === 'CRITICAL').length,
      findings,
      timestamp: Date.now(),
    };
    fs.writeFileSync(cachePath, JSON.stringify(cacheData, null, 2));
  }

  private async scanFile(filePath: string): Promise<any[]> {
    return new Promise((resolve) => {
      const proc = spawn('node', [this.scannerPath, 'analyze', '--file', filePath, '--json']);

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      proc.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      proc.on('close', () => {
        try {
          // Extract JSON object from stdout (find the summary object)
          // Look for lines that start with { and capture complete JSON
          const lines = stdout.split('\n');
          let jsonText = '';
          let bracketCount = 0;
          let inJson = false;

          for (const line of lines) {
            if (line.trim().startsWith('{')) {
              inJson = true;
            }
            if (inJson) {
              jsonText += line + '\n';
              bracketCount += (line.match(/\{/g) || []).length;
              bracketCount -= (line.match(/\}/g) || []).length;

              if (bracketCount === 0 && jsonText.trim().length > 10) {
                break;
              }
            }
          }

          if (!jsonText || bracketCount !== 0) {
            resolve([]);
            return;
          }

          const result = JSON.parse(jsonText);
          resolve(result.findings || []);
        } catch {
          resolve([]);
        }
      });

      // Timeout after 5 seconds
      setTimeout(() => {
        proc.kill();
        resolve([]);
      }, 5000);
    });
  }
}
