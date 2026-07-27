// module_state_test.js
// Post-animation DOM state assertions for each migrated MeshDesk module.
// Validates that after MeshAnim helpers complete, the DOM state matches
// the documented pattern (display, opacity, child presence, class state).
//
// Usage:
//   node test/animation/module_state_test.js [--base-url=http://localhost:9876]

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

let passed = 0;
let failed = 0;
const failures = [];

async function assert(condition, label) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    failures.push(label);
    console.log(`  ✗ ${label}`);
  }
}

function summary() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    failures.forEach((f, i) => console.log(`  ${i + 1}. ${f}`));
  }
  console.log('='.repeat(60));
}

// Standalone test page loading anim.js + anime.min.js via local file paths
// No server needed — puppeteer loads file:// URLs for the scripts.

const WEB_ROOT = path.resolve(__dirname, '..', '..', 'web');
const ANIME_JS = 'file://' + path.join(WEB_ROOT, 'static', 'js', 'anime.min.js');
const ANIM_JS = 'file://' + path.join(WEB_ROOT, 'static', 'js', 'anim.js');

const testPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>module state test</title>
<style>
  .toast-container { position: fixed; top: 10px; right: 10px; z-index: 999; }
  .toast { padding: 8px 16px; margin: 4px 0; border-radius: 4px; color: #fff; }
  .toast.info { background: #58a6ff; }
  .toast.success { background: #3fb950; }
  .toast.warning { background: #d29922; }
  .toast.error { background: #f85149; }
  .config-tab { padding: 6px 12px; cursor: pointer; }
  .config-tab.active { background: #58a6ff; }
  .cfg-section-content { padding: 16px; }
  .cfg-feedback { padding: 8px 16px; margin: 8px 0; border-radius: 4px; display: none; }
  .cfg-feedback-info { background: #1f6feb33; color: #58a6ff; }
  .cfg-feedback-success { background: #23863633; color: #3fb950; }
  .cfg-feedback-warning { background: #9e6a0333; color: #d29922; }
  .cfg-feedback-error { background: #da363333; color: #f85149; }
  .modal-overlay {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.6); display: none; align-items: center; justify-content: center; z-index: 1000;
  }
  .modal-content { background: #161b22; padding: 24px; border-radius: 8px; max-width: 600px; width: 90%; }
  .topology-status {
    padding: 4px 12px; margin: 4px 0; border-radius: 4px; display: none;
  }
  .topology-status.status-info { background: #1f6feb33; color: #58a6ff; }
  .topology-status.status-warn { background: #9e6a0333; color: #d29922; }
  .topology-status.status-error { background: #da363333; color: #f85149; }
  .topology-tooltip {
    position: absolute; padding: 8px 12px; background: #21262d; border: 1px solid #30363d;
    border-radius: 4px; display: none; z-index: 500;
  }
  .node-card { width: 200px; height: 120px; background: #21262d; border-radius: 8px; margin: 8px; display: inline-block; }
  .xray-logs-panel { padding: 16px; background: #0d1117; border: 1px solid #30363d; display: none; }
  .xray-share-result { padding: 16px; background: #161b22; border-radius: 8px; display: none; }
  .pending-restart-banner { padding: 8px 16px; background: #9e6a0333; color: #d29922; display: none; align-items: center; }
  #sandbox { padding: 16px; }
</style>
</head><body>
<div id="sandbox">
  <!-- Toast patterns -->
  <!-- Modal overlay patterns -->
  <div id="cfg-stepup-modal" class="modal-overlay">
    <div class="modal-content">
      <h3>Step-up Auth</h3>
      <input id="cfg-stepup-password" type="password">
      <button id="cfg-stepup-submit">Submit</button>
      <button id="cfg-stepup-close" onclick="configCloseStepUp()">Cancel</button>
    </div>
  </div>
  <div id="cfg-diff-modal" class="modal-overlay">
    <div class="modal-content">
      <h3>Config Diff</h3>
      <div id="cfg-diff-body"></div>
      <button id="cfg-diff-close" onclick="configCloseDiff()">Close</button>
    </div>
  </div>
  <!-- Feedback banner -->
  <div id="cfg-feedback" class="cfg-feedback"></div>
  <!-- Config section -->
  <div id="cfg-content"></div>
  <!-- Config tabs -->
  <div id="cfg-tabs">
    <button class="config-tab" data-section="node">Node</button>
    <button class="config-tab" data-section="mesh">Mesh</button>
  </div>
  <!-- Pending restart -->
  <div id="cfg-pending-restart" class="pending-restart-banner">
    <span>Pending restart: </span><span id="cfg-pending-fields"></span>
  </div>
  <!-- Dashboard cards -->
  <div id="node-grid"></div>
  <!-- Proxy logs panel -->
  <div id="xray-logs-panel" class="xray-logs-panel">
    <pre id="xray-log-output"></pre>
  </div>
  <!-- x-ui share result -->
  <div id="xui-share-result" class="xray-share-result">
    <input id="xui-share-link" type="text">
  </div>
  <!-- Topology status banner -->
  <div id="topology-status" class="topology-status"></div>
  <!-- Topology tooltip -->
  <div id="topology-tooltip" class="topology-tooltip"></div>
  <!-- Topology page sections -->
  <div class="topology-header">Header</div>
  <div class="topology-toolbar">Toolbar</div>
  <div class="topology-canvas-wrapper">Canvas</div>
  <div class="topology-legend">Legend</div>
</div>
<script src="${ANIME_JS}"></script>
<script src="${ANIM_JS}"></script>
</body></html>`;

async function main() {
  console.log('=== Module Post-Animation State Tests ===\n');

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || '/snap/bin/chromium',
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--allow-file-access-from-files'],
  });

  try {
    const page = await browser.newPage();
    page.on('pageerror', e => {
      console.error('  PAGE ERROR:', e.message);
      failures.push('page error: ' + e.message);
      failed++;
    });

    // Write test page to temp file so file:// scripts can load
    const PAGES_DIR = path.join(__dirname, 'pages');
    fs.mkdirSync(PAGES_DIR, { recursive: true });
    const tmpPath = path.join(PAGES_DIR, 'module_state_test.html');
    fs.writeFileSync(tmpPath, testPage);
    await page.goto('file://' + tmpPath, { waitUntil: 'networkidle0' });

    // Wait for scripts to load
    await page.waitForFunction(() => typeof window.MeshAnim !== 'undefined', { timeout: 5000 });

    // ── 1. Toast lifecycle (config.js/xui.js/proxy-nodes.js pattern) ──
    console.log('--- 1. Toast lifecycle ---');
    let toastResult = await page.evaluate(async () => {
      const results = {};
      // Simulate showToast pattern:
      //   create div.toast-container, create div.toast.info, appendoChild, opactiy=0,
      //   slideInRight, setTimeout 4000, slideOutRight, removeChild
      const container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);

      const toast = document.createElement('div');
      toast.className = 'toast info';
      toast.textContent = 'Test toast message';
      toast.style.opacity = '0';
      container.appendChild(toast);

      // Verify pre-animation state
      results.preInContainer = container.contains(toast);
      results.preOpacity = parseFloat(getComputedStyle(toast).opacity);
      results.preDisplay = getComputedStyle(toast).display;

      // slideInRight
      await window.MeshAnim.slideInRight(toast, { duration: 50 });
      results.postSlideInOpacity = parseFloat(getComputedStyle(toast).opacity);
      results.postSlideInContainer = container.contains(toast);

      // simulate auto-dismiss: slideOutRight then removeChild
      await window.MeshAnim.slideOutRight(toast, { duration: 50 });
      window.__postSlideOutOpacity = parseFloat(getComputedStyle(toast).opacity);
      if (toast.parentNode) toast.parentNode.removeChild(toast);
      results.postRemoveContainer = container.contains(toast);

      return results;
    });

    await assert(toastResult.preInContainer === true, 'toast added to container');
    await assert(toastResult.preOpacity === 0, 'toast starts opacity 0');
    await assert(toastResult.postSlideInOpacity === 1, 'toast opacity 1 after slideInRight');
    await assert(toastResult.postSlideInContainer === true, 'toast still in container after slideInRight');
    await assert(toastResult.postRemoveContainer === false, 'toast removed from DOM after slideOutRight');

    // ── 2. Modal lifecycle: fadeIn/fadeOut with display toggle ──
    console.log('\n--- 2. Modal lifecycle (step-up auth) ---');
    let modalResult = await page.evaluate(async () => {
      const modal = document.getElementById('cfg-stepup-modal');
      modal.style.display = 'flex';
      modal.style.opacity = '0';
      await window.MeshAnim.fadeIn(modal, { duration: 50 });

      const postOpenDisplay = getComputedStyle(modal).display;
      const postOpenOpacity = parseFloat(getComputedStyle(modal).opacity);

      await window.MeshAnim.fadeOut(modal, { duration: 50 });
      modal.style.display = 'none';

      const postCloseDisplay = getComputedStyle(modal).display;

      return {
        postOpenDisplay,
        postOpenOpacity,
        postCloseDisplay,
      };
    });

    await assert(modalResult.postOpenDisplay === 'flex', 'modal display:flex after fadeIn');
    await assert(modalResult.postOpenOpacity === 1, 'modal opacity 1 after fadeIn');
    await assert(modalResult.postCloseDisplay === 'none', 'modal display:none after fadeOut');

    // ── 3. Diff modal: same pattern, different modal ──
    console.log('\n--- 3. Diff modal lifecycle ---');
    let diffResult = await page.evaluate(async () => {
      const modal = document.getElementById('cfg-diff-modal');
      modal.style.display = 'flex';
      modal.style.opacity = '0';
      await window.MeshAnim.fadeIn(modal, { duration: 50 });

      const postOpenOpacity = parseFloat(getComputedStyle(modal).opacity);

      await window.MeshAnim.fadeOut(modal, { duration: 50 });
      modal.style.display = 'none';

      const postCloseOpacity = parseFloat(getComputedStyle(modal).opacity);

      return { postOpenOpacity, postCloseOpacity };
    });

    await assert(diffResult.postOpenOpacity === 1, 'diff modal opacity 1 after fadeIn');
    await assert(diffResult.postCloseOpacity === 0, 'diff modal opacity 0 after fadeOut');

    // ── 4. Feedback banner lifecycle ──
    console.log('\n--- 4. Feedback banner lifecycle ---');
    let feedbackResult = await page.evaluate(async () => {
      const el = document.getElementById('cfg-feedback');
      el.className = 'cfg-feedback cfg-feedback-success';
      el.textContent = 'Operation successful';
      el.style.display = 'block';
      el.style.opacity = '0';
      await window.MeshAnim.fadeIn(el, { duration: 50 });

      const postOpenDisplay = getComputedStyle(el).display;
      const postOpenOpacity = parseFloat(getComputedStyle(el).opacity);

      // simulate setTimeout + fadeOut
      await window.MeshAnim.fadeOut(el, { duration: 50 });
      el.style.display = 'none';

      const postCloseDisplay = getComputedStyle(el).display;

      return { postOpenDisplay, postOpenOpacity, postCloseDisplay };
    });

    await assert(feedbackResult.postOpenDisplay === 'block', 'feedback display:block after fadeIn');
    await assert(feedbackResult.postOpenOpacity === 1, 'feedback opacity 1 after fadeIn');
    await assert(feedbackResult.postCloseDisplay === 'none', 'feedback display:none after fadeOut');

    // ── 5. Config section render with slideIn ──
    console.log('\n--- 5. Config section slideIn ---');
    let sectionResult = await page.evaluate(async () => {
      const content = document.getElementById('cfg-content');
      // Simulate renderSection: innerHTML then slideIn
      content.innerHTML = '<div class="cfg-section-content" data-section="node"><p>Section content</p></div>';
      const section = content.querySelector('.cfg-section-content');
      section.style.opacity = '0';
      await window.MeshAnim.slideIn(section, { duration: 50 });

      const postAnimOpacity = parseFloat(getComputedStyle(section).opacity);
      return { postAnimOpacity };
    });

    await assert(sectionResult.postAnimOpacity === 1, 'config section opacity 1 after slideIn');

    // ── 6. Dashboard staggeredAppear ──
    console.log('\n--- 6. Dashboard staggeredAppear ---');
    let dashResult = await page.evaluate(async () => {
      const grid = document.getElementById('node-grid');
      grid.innerHTML = '';
      for (let i = 0; i < 5; i++) {
        const card = document.createElement('article');
        card.className = 'node-card';
        card.style.opacity = '0';
        card.textContent = 'Node ' + (i + 1);
        grid.appendChild(card);
      }
      const cards = grid.querySelectorAll('article');
      await window.MeshAnim.staggeredAppear(cards, 30, { duration: 100 });

      const opacities = Array.from(cards).map(c => parseFloat(getComputedStyle(c).opacity));
      return { count: cards.length, allOne: opacities.every(o => o === 1) };
    });

    await assert(dashResult.count === 5, '5 node cards in grid');
    await assert(dashResult.allOne === true, 'all dashboard cards opacity 1 after staggeredAppear');

    // ── 7. x-ui share result fadeIn ──
    console.log('\n--- 7. x-ui share result fadeIn ---');
    let shareResult = await page.evaluate(async () => {
      const resultDiv = document.getElementById('xui-share-result');
      resultDiv.style.display = 'block';
      resultDiv.style.opacity = '0';
      await window.MeshAnim.fadeIn(resultDiv, { duration: 50 });

      const postOpenDisplay = getComputedStyle(resultDiv).display;
      const postOpenOpacity = parseFloat(getComputedStyle(resultDiv).opacity);

      return { postOpenDisplay, postOpenOpacity };
    });

    await assert(shareResult.postOpenDisplay !== 'none', 'share result visible after fadeIn (display not none)');
    await assert(shareResult.postOpenOpacity === 1, 'share result opacity 1 after fadeIn');

    // ── 8. Proxy logs panel fadeIn ──
    console.log('\n--- 8. Proxy logs panel fadeIn ---');
    let logsResult = await page.evaluate(async () => {
      const panel = document.getElementById('xray-logs-panel');
      panel.style.display = 'block';
      panel.style.opacity = '0';
      await window.MeshAnim.fadeIn(panel, { duration: 50 });

      const postOpenDisplay = getComputedStyle(panel).display;
      const postOpenOpacity = parseFloat(getComputedStyle(panel).opacity);

      return { postOpenDisplay, postOpenOpacity };
    });

    await assert(logsResult.postOpenDisplay !== 'none', 'logs panel visible after fadeIn (display not none)');
    await assert(logsResult.postOpenOpacity === 1, 'logs panel opacity 1 after fadeIn');

    // ── 9. Pending restart banner fadeIn/fadeOut ──
    console.log('\n--- 9. Pending restart banner ---');
    let pendingResult = await page.evaluate(async () => {
      const el = document.getElementById('cfg-pending-restart');
      // Simulate: display:flex + fadeIn
      el.style.display = 'flex';
      el.style.opacity = '0';
      await window.MeshAnim.fadeIn(el, { duration: 50 });

      const postInDisplay = getComputedStyle(el).display;
      const postInOpacity = parseFloat(getComputedStyle(el).opacity);

      // Simulate: fadeOut → display:none
      await window.MeshAnim.fadeOut(el, { duration: 50 });
      el.style.display = 'none';

      const postOutDisplay = getComputedStyle(el).display;
      const postOutOpacity = parseFloat(getComputedStyle(el).opacity);

      return { postInDisplay, postInOpacity, postOutDisplay, postOutOpacity };
    });

    await assert(pendingResult.postInDisplay === 'flex', 'pending restart display:flex after fadeIn');
    await assert(pendingResult.postInOpacity === 1, 'pending restart opacity 1 after fadeIn');
    await assert(pendingResult.postOutDisplay === 'none', 'pending restart display:none after fadeOut');
    await assert(pendingResult.postOutOpacity === 0, 'pending restart opacity 0 after fadeOut');

    // ── 10. Topology status banner with fadeIn/fadeOut and timer ──
    console.log('\n--- 10. Topology status banner ---');
    let statusResult = await page.evaluate(async () => {
      const el = document.getElementById('topology-status');
      el.textContent = 'Topology loaded';
      el.className = 'topology-status status-info';
      el.style.opacity = '';
      el.style.display = 'block';
      await window.MeshAnim.fadeIn(el, { duration: 50 });

      const postInDisplay = getComputedStyle(el).display;
      const postInOpacity = parseFloat(getComputedStyle(el).opacity);

      // Simulate delayed fadeOut (statusHideTimer pattern)
      await window.MeshAnim.fadeOut(el, { duration: 50 });
      el.style.display = 'none';

      const postOutDisplay = getComputedStyle(el).display;
      const postOutOpacity = parseFloat(getComputedStyle(el).opacity);

      return { postInDisplay, postInOpacity, postOutDisplay, postOutOpacity };
    });

    await assert(statusResult.postInDisplay === 'block', 'topology status display:block after fadeIn');
    await assert(statusResult.postInOpacity === 1, 'topology status opacity 1 after fadeIn');
    await assert(statusResult.postOutDisplay === 'none', 'topology status display:none after fadeOut');
    await assert(statusResult.postOutOpacity === 0, 'topology status opacity 0 after fadeOut');

    // ── 11. Topology tooltip with visibility guard ──
    console.log('\n--- 11. Topology tooltip fadeIn/fadeOut ---');
    let tooltipResult = await page.evaluate(async () => {
      const tooltip = document.getElementById('topology-tooltip');
      tooltip.textContent = 'Node: test-node (entry, cpu 42%)';
      tooltip.style.display = 'block';
      tooltip.style.opacity = '0';
      await window.MeshAnim.fadeIn(tooltip, { duration: 50 });

      const postInDisplay = getComputedStyle(tooltip).display;
      const postInOpacity = parseFloat(getComputedStyle(tooltip).opacity);

      await window.MeshAnim.fadeOut(tooltip, { duration: 50 });
      tooltip.style.display = 'none';

      const postOutDisplay = getComputedStyle(tooltip).display;
      const postOutOpacity = parseFloat(getComputedStyle(tooltip).opacity);

      return { postInDisplay, postInOpacity, postOutDisplay, postOutOpacity };
    });

    await assert(tooltipResult.postInDisplay === 'block', 'tooltip display:block after fadeIn');
    await assert(tooltipResult.postInOpacity === 1, 'tooltip opacity 1 after fadeIn');
    await assert(tooltipResult.postOutDisplay === 'none', 'tooltip display:none after fadeOut');
    await assert(tooltipResult.postOutOpacity === 0, 'tooltip opacity 0 after fadeOut');

    // ── 12. Topology page entrance staggeredAppear ──
    console.log('\n--- 12. Topology page entrance staggeredAppear ---');
    let topoEntranceResult = await page.evaluate(async () => {
      const sections = document.querySelectorAll(
        '.topology-header, .topology-toolbar, .topology-canvas-wrapper, .topology-legend'
      );
      // Reset
      sections.forEach(s => { s.style.opacity = '0'; });
      await window.MeshAnim.staggeredAppear(sections, 50, { duration: 100 });

      const opacities = Array.from(sections).map(s => parseFloat(getComputedStyle(s).opacity));
      return { count: sections.length, allOne: opacities.every(o => o === 1) };
    });

    await assert(topoEntranceResult.count === 4, '4 topology page sections targeted');
    await assert(topoEntranceResult.allOne === true, 'all topology sections opacity 1 after staggeredAppear');

    // ── 13. Tab switch section render (config.js configSelectTab pattern) ──
    console.log('\n--- 13. Config tab switch ---');
    let tabResult = await page.evaluate(async () => {
      const content = document.getElementById('cfg-content');
      // Simulate tab switch: deactivate old, activate new, render, slideIn
      content.innerHTML = '<div class="cfg-section-content" data-section="mesh"><p>Mesh section</p></div>';
      const section = content.querySelector('.cfg-section-content');
      section.style.opacity = '0';
      await window.MeshAnim.slideIn(section, { duration: 50 });
      const postAnimOpacity = parseFloat(getComputedStyle(section).opacity);
      return { postAnimOpacity };
    });

    await assert(tabResult.postAnimOpacity === 1, 'switched section opacity 1 after slideIn');

    // ── 14. Chaining: fadeOut().then(display:none) pattern ──
    console.log('\n--- 14. Chaining pattern: fadeOut.then(display:none) ---');
    let chainResult = await page.evaluate(async () => {
      const el = document.createElement('div');
      el.style.display = 'block';
      el.style.opacity = '1';
      document.getElementById('sandbox').appendChild(el);

      await window.MeshAnim.fadeOut(el, { duration: 50 });
      // After fadeOut resolves, set display:none — this is the pattern used everywhere
      el.style.display = 'none';

      const finalDisplay = getComputedStyle(el).display;
      const finalOpacity = parseFloat(getComputedStyle(el).opacity);
      return { finalDisplay, finalOpacity };
    });

    await assert(chainResult.finalDisplay === 'none', 'fadeOut.then(display:none): element display none');
    await assert(chainResult.finalOpacity === 0, 'fadeOut.then(display:none): element opacity 0');

  } finally {
    await browser.close();
    summary();
    process.exit(failures.length > 0 ? 1 : 0);
  }
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});