import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs';

const DEFAULT_CACHE_PATH = path.join(process.cwd(), '.scan-cache.json');

interface CacheStore {
  [hash: string]: {
    findings: any;
    timestamp: number;
  };
}

export class CacheManager {
  private store: CacheStore = {};
  private cachePath: string;

  constructor(cachePath: string = DEFAULT_CACHE_PATH) {
    this.cachePath = cachePath;
    this.load();
  }

  private load(): void {
    try {
      if (fs.existsSync(this.cachePath)) {
        const raw = fs.readFileSync(this.cachePath, 'utf-8');
        this.store = JSON.parse(raw);
      }
    } catch {
      this.store = {};
    }
  }

  private persist(): void {
    try {
      fs.writeFileSync(this.cachePath, JSON.stringify(this.store, null, 2));
    } catch {
      // Cache write failure is non-fatal
    }
  }

  hash(code: string): string {
    return crypto.createHash('sha256').update(code).digest('hex');
  }

  async get(code: string): Promise<any | null> {
    const h = this.hash(code);
    return this.store[h] ? this.store[h].findings : null;
  }

  async set(code: string, findings: any): Promise<void> {
    const h = this.hash(code);
    this.store[h] = { findings, timestamp: Date.now() };
    this.persist();
  }

  async close(): Promise<void> {
    this.persist();
  }
}
