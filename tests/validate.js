#!/usr/bin/env node

/**
 * Validation script for security scanner
 * Tests FP rate on 5 code snippets with known vulnerabilities
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const TEST_CASES = [
  {
    file: 'snippet1_sql.js',
    expectVulnerable: true,
    expectedPatterns: ['sql_injection'],
  },
  {
    file: 'snippet2_secrets.js',
    expectVulnerable: true,
    expectedPatterns: ['hardcoded_secrets'],
  },
  {
    file: 'snippet3_path_traversal.js',
    expectVulnerable: true,
    expectedPatterns: ['path_traversal'],
  },
  {
    file: 'snippet4_xss.js',
    expectVulnerable: true,
    expectedPatterns: ['xss'],
  },
  {
    file: 'snippet5_safe.js',
    expectVulnerable: false,
    expectedPatterns: [],
  },
];

async function runTest(testCase) {
  const filepath = path.join(__dirname, testCase.file);

  return new Promise((resolve) => {
    const proc = spawn('node', ['dist/cli.js', 'analyze', '--file', filepath]);

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      resolve({ stdout, stderr, code, testCase, filepath });
    });
  });
}

async function main() {
  console.log('🔍 Security Scanner Validation\n');
  console.log(`Testing ${TEST_CASES.length} snippets...\n`);

  let passed = 0;
  let failed = 0;
  const fpCount = [];

  for (const testCase of TEST_CASES) {
    process.stdout.write(`Testing ${testCase.file}... `);
    const result = await runTest(testCase);

    if (result.code !== 0) {
      console.log('❌ CLI error');
      console.log(result.stderr);
      failed++;
      continue;
    }

    const output = result.stdout;
    const hasVulnerabilities = output.includes('🔴') || output.includes('🟠') || output.includes('🟡');
    const foundPatterns = [];

    for (const pattern of testCase.expectedPatterns) {
      if (output.includes(pattern)) {
        foundPatterns.push(pattern);
      }
    }

    if (testCase.expectVulnerable && hasVulnerabilities) {
      console.log('✓ Correctly detected vulnerability');
      passed++;
    } else if (!testCase.expectVulnerable && !hasVulnerabilities) {
      console.log('✓ Correctly identified safe code');
      passed++;
    } else if (!testCase.expectVulnerable && hasVulnerabilities) {
      console.log('❌ FALSE POSITIVE detected');
      fpCount.push(testCase.file);
      failed++;
    } else {
      console.log('❌ MISSED vulnerability');
      failed++;
    }
  }

  console.log(`\n📊 Results:`);
  console.log(`  ✓ Passed: ${passed}/${TEST_CASES.length}`);
  console.log(`  ✗ Failed: ${failed}/${TEST_CASES.length}`);

  if (fpCount.length > 0) {
    const fpRate = ((fpCount.length / TEST_CASES.length) * 100).toFixed(1);
    console.log(`  🚨 False Positive Rate: ${fpRate}% (${fpCount.length} false positives)`);
    if (fpRate > 20) {
      console.log('     ⚠️  FP rate exceeds 20% target!');
    }
  }

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(console.error);
