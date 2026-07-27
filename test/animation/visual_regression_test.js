// visual_regression_test.js
// Visual regression for key MeshDesk animation transitions.
// Captures screenshots at critical transition points and validates
// computed-style properties that define the visual state (opacity,
// display, transform, position, etc.).
//
// Screenshots are saved to test/animation/screenshots/ for manual
// review. Each test verifies DOM/computed-style state at the frame
// level so visual regressions are caught even without pixel-diffing.
//
// Usage:
//   node test/animation/visual_regression_test.js

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

let passed = 0;
let failed = 0;
const failures = [];

const SCREENSHOT_DIR = path.resolve(__dirname, 'screenshots');
if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

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

async function capture(page, name) {
  const filepath = path.join(SCREENSHOT_DIR, name + '.png');
  await page.screenshot({ path: filepath, fullPage: false });
  console.log(`    [screenshot: ${name}.png]`);
  return filepath;
}

function summary() {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  console.log(`Screenshots saved to: ${SCREENSHOT_DIR}`);
  if (failures.length > 0) {
    console.log('\nFailures:');
    failures.forEach((f, i) => console.log(`  ${i + 1}. ${f}`));
  }
  console.log('='.repeat(60));
}

// ── Test page ──────────────────────────────────────────────────────────

const WEB_ROOT = path.resolve(__dirname, '..', '..', 'web');
const ANIME_JS = 'file://' + path.join(WEB_ROOT, 'static', 'js', 'anime.min.js');
const ANIM_JS = 'file://' + path.join(WEB_ROOT, 'static', 'js', 'anim.js');

const testPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>visual regression test</title>
<style>
  body { margin: 0; padding: 20px; background: #0d1117; font-family: sans-serif; color: #c9d1d9; }

  .scene { position: relative; width: 800px; height: 500px; border: 1px solid #30363d; border-radius: 8px; margin: 16px 0; overflow: hidden; background: #0d1117; }

  .node-circle { position: absolute; width: 32px; height: 32px; border-radius: 50%; display: none; opacity: 0; transition: none; }
  .node-circle.entry { background: #58a6ff; box-shadow: 0 0 8px #58a6ff88; }
  .node-circle.relay { background: #d29922; box-shadow: 0 0 8px #d2992288; }
  .node-circle.exit { background: #3fb950; box-shadow: 0 0 8px #3fb95088; }

  .config-section { padding: 16px; margin: 8px 0; background: #161b22; border: 1px solid #30363d; border-radius: 8px; display: none; opacity: 0; }
  .config-section h3 { margin: 0 0 8px 0; color: #58a6ff; }
  .config-section .field { padding: 8px; margin: 4px 0; background: #21262d; border-radius: 4px; }

  .toast-bar { position: fixed; top: 16px; right: 16px; z-index: 999; width: 300px; }
  .toast-msg { padding: 12px 16px; margin: 8px 0; border-radius: 6px; color: #fff; opacity: 0; display: block; }
  .toast-msg.success { background: #238636; }
  .toast-msg.error { background: #da3633; }
  .toast-msg.info { background: #1f6feb; }

  .modal-backdrop {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0,0,0,0.7); display: none; align-items: center; justify-content: center; z-index: 1000;
  }
  .modal-box { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; width: 400px; opacity: 0; }

  .card-grid { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; }
  .card-item { width: 180px; height: 100px; background: #21262d; border: 1px solid #30363d; border-radius: 8px; padding: 12px; opacity: 0; }
  .card-item h4 { color: #58a6ff; margin: 0 0 4px 0; font-size: 14px; }
  .card-item .stat { color: #8b949e; font-size: 12px; }

  .toolbar { margin: 16px 0; display: flex; gap: 8px; }
  .btn { padding: 6px 16px; border: 1px solid #30363d; border-radius: 6px; background: #21262d; color: #c9d1d9; cursor: pointer; }
  .btn.primary { background: #1f6feb; border-color: #1f6feb; color: #fff; }
</style>
</head><body>
<h3>MeshDesk Animation Visual Regression</h3>

<!-- Scene 1: Topology Nodes -->
<div class="scene" id="scene-topology">
  <div class="node-circle entry" style="left: 100px; top: 200px; display: block;"></div>
  <div class="node-circle relay" style="left: 300px; top: 150px; display: block;"></div>
  <div class="node-circle exit" style="left: 500px; top: 250px; display: block;"></div>
  <div class="node-circle entry" style="left: 200px; top: 350px; display: block;"></div>
  <div class="node-circle relay" style="left: 400px; top: 300px; display: block;"></div>
  <div class="node-circle exit" style="left: 600px; top: 180px; display: block;"></div>
</div>
<div class="toolbar">
  <button class="btn primary" onclick="window.__showNodes()">Show Nodes</button>
  <button class="btn" onclick="window.__hideNodes()">Hide Nodes</button>
</div>

<!-- Scene 2: Config Section Expand -->
<div class="toolbar">
  <button class="btn primary" id="btn-expand-config" data-section="node">Expand: Node Config</button>
  <button class="btn" id="btn-collapse-config" data-section="node">Collapse: Node Config</button>
</div>
<div class="config-section" id="config-node-section">
  <h3>Node Configuration</h3>
  <div class="field">Hostname: meshdesk-node-01</div>
  <div class="field">Role: entry+relay</div>
  <div class="field">Port: 8080</div>
</div>

<!-- Scene 3: Toast Show/Hide -->
<div class="toolbar">
  <button class="btn primary" onclick="window.__showToast('success', 'Configuration saved successfully')">Show Success Toast</button>
  <button class="btn primary" style="background:#da3633;border-color:#da3633" onclick="window.__showToast('error', 'Connection refused: timeout after 30s')">Show Error Toast</button>
  <button class="btn" onclick="window.__hideToasts()">Dismiss All Toasts</button>
</div>
<div class="toast-bar" id="toast-bar"></div>

<!-- Scene 4: Modal -->
<div class="toolbar">
  <button class="btn primary" onclick="window.__openModal()">Open Config Modal</button>
  <button class="btn" onclick="window.__closeModal()">Close Config Modal</button>
</div>
<div class="modal-backdrop" id="test-modal">
  <div class="modal-box" id="test-modal-box">
    <h3>Configuration Diff</h3>
    <p>Running config has 3 pending changes that differ from the saved config.</p>
    <div style="margin-top:16px; text-align:right;">
      <button class="btn" onclick="window.__closeModal()">Close</button>
    </div>
  </div>
</div>

<!-- Scene 5: Dashboard Cards -->
<div class="toolbar">
  <button class="btn primary" onclick="window.__showCards()">Staggered Appear (Cards)</button>
</div>
<div class="card-grid" id="card-grid">
  <div class="card-item"><h4>alpha-01</h4><div class="stat">CPU: 23% MEM: 2.1/8.0 GB</div><div class="stat">Role: entry</div></div>
  <div class="card-item"><h4>beta-relay</h4><div class="stat">CPU: 45% MEM: 4.5/16.0 GB</div><div class="stat">Role: relay</div></div>
  <div class="card-item"><h4>gamma-exit</h4><div class="stat">CPU: 12% MEM: 1.2/4.0 GB</div><div class="stat">Role: exit</div></div>
  <div class="card-item"><h4>delta-hub</h4><div class="stat">CPU: 67% MEM: 6.8/8.0 GB</div><div class="stat">Role: entry+relay</div></div>
</div>

<script src="${ANIME_JS}"></script>
<script src="${ANIM_JS}"></script>
</body></html>`;

async function main() {
  console.log('=== MeshDesk Animation Visual Regression Tests ===\n');

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || '/snap/bin/chromium',
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--allow-file-access-from-files'],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 900, height: 700 });
    page.on('pageerror', e => {
      console.error('  PAGE ERROR:', e.message);
      failures.push('page error: ' + e.message);
      failed++;
    });

    // Write test page to temp file so file:// scripts can load
    const PAGES_DIR = path.join(__dirname, 'pages');
    fs.mkdirSync(PAGES_DIR, { recursive: true });
    const tmpPath = path.join(PAGES_DIR, 'visual_regression_test.html');
    fs.writeFileSync(tmpPath, testPage);
    await page.goto('file://' + tmpPath, { waitUntil: 'networkidle0' });
    await page.waitForFunction(() => typeof window.MeshAnim !== 'undefined', { timeout: 5000 });

    // Register helpers in page context
    await page.evaluate(() => {
      // Toast pattern: create invisible → slideInRight → slideOutRight → removeChild
      window.__showToast = (type, msg) => {
        const bar = document.getElementById('toast-bar');
        const toast = document.createElement('div');
        toast.className = 'toast-msg ' + type;
        toast.textContent = msg;
        toast.style.opacity = '0';
        bar.appendChild(toast);
        window.MeshAnim.slideInRight(toast);
        setTimeout(() => {
          window.MeshAnim.slideOutRight(toast).then(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
          });
        }, 4000);
      };
      window.__hideToasts = () => {
        const bar = document.getElementById('toast-bar');
        const toasts = bar.querySelectorAll('.toast-msg');
        Promise.all(Array.from(toasts).map(t =>
          window.MeshAnim.slideOutRight(t, { duration: 200 }).then(() => {
            if (t.parentNode) t.parentNode.removeChild(t);
          })
        ));
      };

      // Topology nodes appear
      window.__showNodes = () => {
        const nodes = document.querySelectorAll('.node-circle');
        window.MeshAnim.staggeredAppear(nodes, 40, { duration: 500 });
      };
      window.__hideNodes = () => {
        const nodes = document.querySelectorAll('.node-circle');
        Promise.all(Array.from(nodes).map(n =>
          window.MeshAnim.fadeOut(n, { duration: 300 }).then(() => {
            n.style.display = 'none';
          })
        ));
      };

      // Modal open/close
      window.__openModal = () => {
        const backdrop = document.getElementById('test-modal');
        const box = document.getElementById('test-modal-box');
        backdrop.style.display = 'flex';
        box.style.opacity = '0';
        window.MeshAnim.scaleIn(box, { duration: 400 });
      };
      window.__closeModal = () => {
        const backdrop = document.getElementById('test-modal');
        const box = document.getElementById('test-modal-box');
        window.MeshAnim.scaleOut(box, { duration: 300 }).then(() => {
          backdrop.style.display = 'none';
        });
      };

      // Staggered card appear
      window.__showCards = () => {
        const cards = document.querySelectorAll('#card-grid .card-item');
        window.MeshAnim.staggeredAppear(cards, 60, { duration: 400 });
      };
    });

    // ── 1. Topology node appear ──────────────────────────────────────
    console.log('--- 1. Topology node appear (staggeredAppear) ---');
    await capture(page, '01_topology_nodes_before');

    await page.evaluate(async () => {
      window.__showNodes();
      // Wait for staggered animation (6 nodes × 40ms stagger + 500ms duration)
      await new Promise(r => setTimeout(r, 1200));
    });

    await capture(page, '01_topology_nodes_after');

    let topoNodesResult = await page.evaluate(() => {
      const nodes = document.querySelectorAll('.node-circle');
      const opacities = Array.from(nodes).map(n => parseFloat(getComputedStyle(n).opacity));
      const displays = Array.from(nodes).map(n => getComputedStyle(n).display);
      return {
        count: nodes.length,
        allOne: opacities.every(o => o === 1),
        allVisible: displays.every(d => d !== 'none'),
      };
    });

    await assert(topoNodesResult.count === 6, '6 topology nodes exist');
    await assert(topoNodesResult.allOne === true, 'all topology nodes opacity 1 after staggeredAppear');
    await assert(topoNodesResult.allVisible === true, 'all topology nodes visible (display not none)');

    // ── 2. Config section expand ──────────────────────────────────────
    console.log('\n--- 2. Config section expand (fadeIn + slideIn) ---');
    await capture(page, '02_config_section_before');

    await page.evaluate(async () => {
      const section = document.getElementById('config-node-section');
      section.style.display = 'block';
      section.style.opacity = '0';
      await window.MeshAnim.slideIn(section, { duration: 600 });
    });

    await capture(page, '02_config_section_after');

    let configSectionResult = await page.evaluate(() => {
      const section = document.getElementById('config-node-section');
      return {
        display: getComputedStyle(section).display,
        opacity: parseFloat(getComputedStyle(section).opacity),
      };
    });

    await assert(configSectionResult.display === 'block', 'config section display:block after slideIn');
    await assert(configSectionResult.opacity === 1, 'config section opacity 1 after slideIn');

    // ── 3. Toast show/hide ────────────────────────────────────────────
    console.log('\n--- 3. Toast show (slideInRight) ---');
    await capture(page, '03_toast_before');

    await page.evaluate(async () => {
      window.__showToast('success', 'Configuration saved successfully — 3 fields applied');
      // Wait for slideInRight animation to complete
      await new Promise(r => setTimeout(r, 600));
    });

    await capture(page, '03_toast_after_show');

    let toastShowResult = await page.evaluate(() => {
      const toasts = document.querySelectorAll('.toast-msg');
      return {
        count: toasts.length,
        opacity: toasts.length > 0 ? parseFloat(getComputedStyle(toasts[0]).opacity) : null,
      };
    });

    await assert(toastShowResult.count === 1, '1 toast in DOM');
    await assert(toastShowResult.opacity === 1, 'toast opacity 1 after slideInRight');

    // Now dismiss the toast
    console.log('    --- Toast hide (slideOutRight → remove) ---');
    await page.evaluate(async () => {
      window.__hideToasts();
      await new Promise(r => setTimeout(r, 600));
    });

    await capture(page, '03_toast_after_hide');

    let toastHideResult = await page.evaluate(() => {
      const toasts = document.querySelectorAll('.toast-msg');
      return { count: toasts.length };
    });

    await assert(toastHideResult.count === 0, 'toast removed from DOM after slideOutRight');

    // ── 4. Modal open/close ──────────────────────────────────────────
    console.log('\n--- 4. Modal open (scaleIn) ---');
    await capture(page, '04_modal_before');

    await page.evaluate(async () => {
      window.__openModal();
      await new Promise(r => setTimeout(r, 600));
    });

    await capture(page, '04_modal_after_open');

    let modalOpenResult = await page.evaluate(() => {
      const backdrop = document.getElementById('test-modal');
      const box = document.getElementById('test-modal-box');
      return {
        backdropDisplay: getComputedStyle(backdrop).display,
        boxOpacity: parseFloat(getComputedStyle(box).opacity),
      };
    });

    await assert(modalOpenResult.backdropDisplay === 'flex', 'modal backdrop display:flex');
    await assert(modalOpenResult.boxOpacity === 1, 'modal box opacity 1 after scaleIn');

    console.log('    --- Modal close (scaleOut → display:none) ---');
    await page.evaluate(async () => {
      window.__closeModal();
      await new Promise(r => setTimeout(r, 500));
    });

    await capture(page, '04_modal_after_close');

    let modalCloseResult = await page.evaluate(() => {
      const backdrop = document.getElementById('test-modal');
      const box = document.getElementById('test-modal-box');
      return {
        backdropDisplay: getComputedStyle(backdrop).display,
        boxOpacity: parseFloat(getComputedStyle(box).opacity),
      };
    });

    await assert(modalCloseResult.backdropDisplay === 'none', 'modal backdrop display:none after scaleOut');
    await assert(modalCloseResult.boxOpacity === 0, 'modal box opacity 0 after scaleOut');

    // ── 5. Dashboard cards staggered appear ──────────────────────────
    console.log('\n--- 5. Dashboard cards staggered appear ---');
    await capture(page, '05_cards_before');

    await page.evaluate(async () => {
      window.__showCards();
      // Wait for staggered animation (4 cards × 60ms stagger + 400ms duration)
      await new Promise(r => setTimeout(r, 1000));
    });

    await capture(page, '05_cards_after');

    let cardsResult = await page.evaluate(() => {
      const cards = document.querySelectorAll('#card-grid .card-item');
      const opacities = Array.from(cards).map(c => parseFloat(getComputedStyle(c).opacity));
      return {
        count: cards.length,
        allOne: opacities.every(o => o === 1),
      };
    });

    await assert(cardsResult.count === 4, '4 dashboard cards exist');
    await assert(cardsResult.allOne === true, 'all cards opacity 1 after staggeredAppear');

    // ── 6. Topology nodes hide (fadeOut) ─────────────────────────────
    console.log('\n--- 6. Topology node disappear (fadeOut) ---');
    await page.evaluate(async () => {
      window.__hideNodes();
      await new Promise(r => setTimeout(r, 600));
    });

    await capture(page, '06_nodes_hidden');

    let topoHideResult = await page.evaluate(() => {
      const nodes = document.querySelectorAll('.node-circle');
      const opacities = Array.from(nodes).map(n => parseFloat(getComputedStyle(n).opacity));
      const displays = Array.from(nodes).map(n => getComputedStyle(n).display);
      return {
        allZero: opacities.every(o => o === 0),
        allHidden: displays.every(d => d === 'none'),
      };
    });

    await assert(topoHideResult.allZero === true, 'all nodes opacity 0 after fadeOut');
    await assert(topoHideResult.allHidden === true, 'all nodes display:none after fadeOut');

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