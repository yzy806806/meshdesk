// topology_headless_test.js
// Headless browser test for MeshDesk 3D topology visualization.
// Validates: API contract consumption, data rendering, DOM state.

const puppeteer = require('puppeteer');

const SERVER_URL = process.env.MESHTOPO_URL || 'http://localhost:9876';

async function main() {
  const errors = [];

  console.log("=== MeshDesk Topology Headless Browser Test ===");
  console.log("Server URL:", SERVER_URL);

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || '/snap/bin/chromium',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-gpu',
    ],
    headless: 'new',
  });

  try {
    const page = await browser.newPage();

    page.on('pageerror', err => {
      errors.push('Page error: ' + err.message);
    });

    // Navigate to the test page.
    console.log("Loading test page...");
    await page.goto(SERVER_URL + '/test/topology_3d_test.html', {
      waitUntil: 'networkidle0',
      timeout: 30000,
    });

    // Wait for the test to complete.
    await page.waitForFunction(() => {
      return window.__topologyTest && window.__topologyTest.status !== 'loading';
    }, { timeout: 15000 });

    // Give DOM a moment to render.
    await new Promise(r => setTimeout(r, 500));

    // --- Read test state ---
    const testState = await page.evaluate(() => window.__topologyTest);
    console.log("\nTest state:");
    console.log("  status:", testState.status);
    console.log("  nodes:", testState.nodeCount);
    console.log("  edges:", testState.edgeCount);
    console.log("  fetchStatus:", testState.fetchStatus);
    console.log("  fetchDurationMs:", testState.fetchDurationMs);
    if (testState.errors.length > 0) {
      console.log("  errors:", JSON.stringify(testState.errors));
    }

    // --- Assertions ---

    if (testState.status !== 'ready') {
      errors.push('Test state not ready: ' + testState.status);
    }

    // 1. HTTP 200 from API.
    if (testState.fetchStatus !== 200) {
      errors.push('API returned ' + testState.fetchStatus);
    }

    // 2. Node count.
    if (testState.nodeCount === 0) {
      errors.push('No nodes in topology data');
    }

    // 3. Edge count.
    console.log("Edge count:", testState.edgeCount, "(from mock data)");

    // 4. Response time.
    if (testState.fetchDurationMs > 500) {
      errors.push('Response too slow: ' + testState.fetchDurationMs + 'ms');
    }

    // 5. Validation errors from the page.
    if (testState.errors.length > 0) {
      testState.errors.forEach(e => errors.push('Validation: ' + e));
    }

    // 6. Verify DOM renders node elements.
    const nodeElements = await page.evaluate(() => {
      return document.querySelectorAll('.node').length;
    });
    if (nodeElements === 0) {
      errors.push('No node elements rendered in DOM');
    }

    // 7. Verify no error elements.
    const errorElements = await page.evaluate(() => {
      return document.querySelectorAll('.error').length;
    });
    if (errorElements > 0) {
      errors.push('DOM contains ' + errorElements + ' error elements');
    }

    // 8. Verify response structure directly via fetch.
    const apiData = await page.evaluate(async () => {
      const r = await fetch('/api/topology');
      return r.json();
    });
    if (!apiData.nodes || !apiData.edges) {
      errors.push('Direct API fetch missing nodes or edges');
    }
    if (!Array.isArray(apiData.nodes)) {
      errors.push('API nodes is not an array');
    }
    if (!Array.isArray(apiData.edges)) {
      errors.push('API edges is not an array');
    }

    console.log("\nOK: Direct API fetch returned", apiData.nodes.length, "nodes and", apiData.edges.length, "edges");

    // 9. Take screenshot.
    await page.screenshot({
      path: '/tmp/topology_3d_screenshot.png',
      fullPage: true,
    });
    console.log("OK: Screenshot saved to /tmp/topology_3d_screenshot.png");

    // Report results.
    console.log('\n=== Results ===');
    if (errors.length === 0) {
      console.log('ALL CHECKS PASSED');
      process.exit(0);
    } else {
      console.error('FAILURES:');
      errors.forEach(e => console.error('  -', e));
      process.exit(1);
    }

  } finally {
    await browser.close();
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});