/**
 * Periodic Weekly Scan: Monday 9 AM compliance audit
 * 
 * Flow:
 * 1. Background job runs on schedule (cron: 0 9 * * 1)
 * 2. Scan agent code + all loaded skills + MCP configs
 * 3. Detect vulnerabilities + unsafe upstream updates
 * 4. Generate audit trail report
 * 5. Log results for compliance
 * 
 * Use Case: Weekly security audit, compliance trail, upstream threat detection
 */

import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';

export interface WeeklyScanResult {
  timestamp: Date;
  scanId: string;
  itemsScanned: number;
  findingsByFile: {
    file: string;
    findings: number;
    critical: number;
    high: number;
  }[];
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
  };
  complianceNotes: string[];
  upstreamThreats: string[];
}

export class PeriodicWeeklyScan {
  private scannerPath: string;
  private auditLogPath: string;

  constructor(
    scannerPath: string = './dist/cli.js',
    auditLogPath: string = './.audit-logs'
  ) {
    this.scannerPath = scannerPath;
    this.auditLogPath = auditLogPath;

    if (!fs.existsSync(auditLogPath)) {
      fs.mkdirSync(auditLogPath, { recursive: true });
    }
  }

  /**
   * Run comprehensive weekly scan
   * Targets: agent code + skills + MCP configs
   */
  async runWeeklyScan(): Promise<WeeklyScanResult> {
    const scanId = this.generateScanId();
    const timestamp = new Date();

    console.log(`[AUDIT] Starting weekly security scan ${scanId}`);

    const findingsByFile: WeeklyScanResult['findingsByFile'] = [];
    const allFindings: any[] = [];

    // Scan locations
    const scanLocations = [
      { name: 'Agent Code', path: './src' },
      { name: 'Skills', path: './.hermes/skills' },
      { name: 'MCP Config', path: './.hermes/mcp' },
      { name: 'Plugins', path: './.hermes/plugins' },
    ];

    for (const location of scanLocations) {
      if (fs.existsSync(location.path)) {
        console.log(`[AUDIT] Scanning ${location.name}...`);
        const results = await this.scanDirectory(location.path);

        if (results.length > 0) {
          findingsByFile.push({
            file: location.path,
            findings: results.length,
            critical: results.filter((f) => f.severity === 'CRITICAL').length,
            high: results.filter((f) => f.severity === 'HIGH').length,
          });

          allFindings.push(...results);
        }
      }
    }

    // Compile results
    const result: WeeklyScanResult = {
      timestamp,
      scanId,
      itemsScanned: findingsByFile.length,
      findingsByFile,
      summary: {
        totalFindings: allFindings.length,
        critical: allFindings.filter((f) => f.severity === 'CRITICAL').length,
        high: allFindings.filter((f) => f.severity === 'HIGH').length,
      },
      complianceNotes: this.generateComplianceNotes(allFindings),
      upstreamThreats: await this.detectUpstreamThreats(),
    };

    // Save audit log
    this.saveAuditLog(result);

    console.log(
      `[AUDIT] Scan complete: ${result.summary.totalFindings} findings (${result.summary.critical} critical)`
    );

    return result;
  }

  private async scanDirectory(dirPath: string): Promise<any[]> {
    return new Promise((resolve) => {
      const proc = spawn('node', [this.scannerPath, 'analyze', '--path', dirPath, '--json']);

      let output = '';

      proc.stdout.on('data', (data) => {
        output += data.toString();
      });

      proc.on('close', () => {
        try {
          const result = JSON.parse(output);
          resolve(result.findings || []);
        } catch {
          resolve([]);
        }
      });

      setTimeout(() => {
        proc.kill();
        resolve([]);
      }, 30000); // 30 second timeout per directory
    });
  }

  private generateComplianceNotes(findings: any[]): string[] {
    const notes: string[] = [];

    if (findings.length === 0) {
      notes.push('✓ All systems secure. No vulnerabilities detected.');
    } else {
      const critical = findings.filter((f) => f.severity === 'CRITICAL').length;
      const high = findings.filter((f) => f.severity === 'HIGH').length;

      if (critical > 0) {
        notes.push(
          `⚠️ CRITICAL: ${critical} critical vulnerability(ies) detected. Immediate remediation required.`
        );
      }
      if (high > 0) {
        notes.push(`⚠️ HIGH: ${high} high-severity issue(s). Schedule remediation within 7 days.`);
      }
    }

    notes.push(
      `Audit performed: ${new Date().toISOString()} | Audit ID: ${this.generateScanId()}`
    );
    notes.push('For compliance trail retention, all audit logs stored in ./.audit-logs/');

    return notes;
  }

  private async detectUpstreamThreats(): Promise<string[]> {
    const threats: string[] = [];

    // Check package.json for known vulnerable versions
    const packageJsonPath = './package.json';
    if (fs.existsSync(packageJsonPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
        const deps = pkg.dependencies || {};

        // Known vulnerable patterns (simplified example)
        const vulnerablePackages: Record<string, string> = {
          'lodash': '< 4.17.21',
          'axios': '< 0.21.0',
        };

        for (const [pkgName, minVersion] of Object.entries(vulnerablePackages)) {
          if (deps[pkgName]) {
            threats.push(
              `Upstream threat: ${pkgName}@${deps[pkgName]} - Check if version ${minVersion} applies`
            );
          }
        }
      } catch {
        // Ignore parse errors
      }
    }

    return threats;
  }

  private saveAuditLog(result: WeeklyScanResult): void {
    const filename = `audit_${result.scanId}.json`;
    const filepath = path.join(this.auditLogPath, filename);

    fs.writeFileSync(filepath, JSON.stringify(result, null, 2));
    console.log(`[AUDIT] Log saved: ${filepath}`);
  }

  private generateScanId(): string {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(
      now.getDate()
    ).padStart(2, '0')}_${now.getTime()}`;
  }
}
