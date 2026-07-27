#!/usr/bin/env node
// test/animation/run_all.js
// Master test runner for the MeshDesk animation test suite.
// Runs all three suites sequentially and reports aggregate results.
//
// Usage:
//   node test/animation/run_all.js

const { execSync, spawnSync } = require('child_process');
const path = require('path');

const SUITES = [
  { file: 'anim_contract_test.js',    name: 'Promise API Contract Tests' },
  { file: 'module_state_test.js',     name: 'Module Post-Animation State Tests' },
  { file: 'visual_regression_test.js', name: 'Visual Regression Tests' },
];

const TESTS_DIR = __dirname;

let totalPassed = 0;
let totalFailed = 0;
const suiteResults = [];

console.log('╔══════════════════════════════════════════════════════════════╗');
console.log('║       MeshDesk Animation Test Suite — Full Run               ║');
console.log('╚══════════════════════════════════════════════════════════════╝\n');

for (const suite of SUITES) {
  console.log(`\n▶ ${suite.name}`);
  console.log('─'.repeat(60));

  const result = spawnSync('node', [path.join(TESTS_DIR, suite.file)], {
    cwd: path.resolve(TESTS_DIR, '..', '..'),
    timeout: 120000,
    encoding: 'utf-8',
  });

  // Output the test output
  const output = result.stdout + result.stderr;

  // Parse results
  const passMatch = output.match(/Results: (\d+) passed/);
  const failMatch = output.match(/(\d+) failed/);
  const passed = passMatch ? parseInt(passMatch[1]) : 0;
  const failed = failMatch ? parseInt(failMatch[1]) : 0;

  totalPassed += passed;
  totalFailed += failed;

  const status = result.status === 0 ? '✓ PASS' : '✗ FAIL';
  suiteResults.push({ name: suite.name, passed, failed, status });

  // Print a condensed view
  const lines = output.split('\n');
  // Show just the result lines (✓/✗)
  for (const line of lines) {
    if (line.includes('  ✓ ') || line.includes('  ✗ ')) {
      console.log(line);
    }
  }

  console.log(`\n  ${status}: ${passed} passed, ${failed} failed`);
}

// ── Aggregate Summary ─────────────────────────────────────────────────
console.log(`\n${'═'.repeat(60)}`);
console.log('AGGREGATE SUMMARY');
console.log('═'.repeat(60));
for (const r of suiteResults) {
  console.log(`  ${r.status === '✓ PASS' ? '✓' : '✗'} ${r.name}: ${r.passed} passed, ${r.failed} failed`);
}
console.log('─'.repeat(60));
console.log(`  TOTAL: ${totalPassed} passed, ${totalFailed} failed, ${totalPassed + totalFailed} assertions`);
console.log(`  STATUS: ${totalFailed === 0 ? 'ALL GREEN' : 'SOME FAILURES'}`);
console.log(`  Screenshots: test/animation/screenshots/`);
console.log('═'.repeat(60));

process.exit(totalFailed > 0 ? 1 : 0);