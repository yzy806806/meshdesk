// anim_contract_test.js
// MeshAnim Promise API contract tests — validates the anime.js wrapper.
// All tests run in a real browser (Puppeteer) because anim.js depends on
// anime global, DOM APIs (document.querySelectorAll), and RAF.
//
// Usage:
//   node test/animation/anim_contract_test.js [--base-url=http://localhost:9876]
//
// Requires a MeshDesk process serving /static/js/anime.min.js and /static/js/anim.js.

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const BASE_URL = process.argv.find(a => a.startsWith('--base-url='))
  ? process.argv.find(a => a.startsWith('--base-url=')).split('=')[1]
  : 'http://localhost:9876';

const WEB_ROOT = path.resolve(__dirname, '..', '..', 'web');
const STATIC_JS = path.join(WEB_ROOT, 'static', 'js');

let passed = 0;
let failed = 0;
const failures = [];

// ── helpers ──────────────────────────────────────────────────────────────

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

// ── test HTML page that loads anim.js + anime.min.js ────────────────────

const ANIME_JS = 'file://' + path.join(WEB_ROOT, 'static', 'js', 'anime.min.js');
const ANIM_JS = 'file://' + path.join(WEB_ROOT, 'static', 'js', 'anim.js');

const testPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>anim contract test</title>
<style>
  .test-target { width: 100px; height: 100px; background: #58a6ff; margin: 4px; display: inline-block; }
  .test-target-multi { width: 50px; height: 50px; background: #3fb950; margin: 2px; display: inline-block; }
</style>
</head><body>
<div id="sandbox"><div id="target1" class="test-target"></div></div>
<div id="sandbox-multi">
  <div class="test-target-multi"></div>
  <div class="test-target-multi"></div>
  <div class="test-target-multi"></div>
  <div class="test-target-multi"></div>
  <div class="test-target-multi"></div>
</div>
<script src="${ANIME_JS}"></script>
<script src="${ANIM_JS}"></script>
</body></html>`;

// ── main ─────────────────────────────────────────────────────────────────

async function main() {
  console.log('=== MeshAnim Promise API Contract Tests ===');
  console.log('Base URL:', BASE_URL);

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || '/snap/bin/chromium',
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu'],
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
    const tmpPath = path.join(PAGES_DIR, 'anim_contract_test.html');
    fs.writeFileSync(tmpPath, testPage);
    await page.goto('file://' + tmpPath, { waitUntil: 'networkidle0' });

    // ── Section 1: API shape ──────────────────────────────────────────
    console.log('\n--- 1. API shape ---');

    const apiShape = await page.evaluate(() => {
      if (typeof window.MeshAnim === 'undefined') return { error: 'MeshAnim not defined' };
      const m = window.MeshAnim;
      return {
        exports: Object.keys(m).sort(),
        defaults: m.DEFAULTS,
        fadeInType: typeof m.fadeIn,
        fadeOutType: typeof m.fadeOut,
        slideInType: typeof m.slideIn,
        slideInRightType: typeof m.slideInRight,
        slideOutRightType: typeof m.slideOutRight,
        scaleInType: typeof m.scaleIn,
        scaleOutType: typeof m.scaleOut,
        staggeredAppearType: typeof m.staggeredAppear,
        cancelAllType: typeof m.cancelAll,
      };
    });

    if (apiShape.error) {
      await assert(false, 'MeshAnim global is defined');
      console.log('  (skipping remaining tests — MeshAnim missing)');
      summary();
      process.exit(1);
    }

    await assert(true, 'MeshAnim global is defined');
    await assert(
      JSON.stringify(apiShape.exports) ===
        '["DEFAULTS","cancelAll","fadeIn","fadeOut","scaleIn","scaleOut","slideIn","slideInRight","slideOutRight","staggeredAppear"]',
      'MeshAnim exports 10 named members'
    );
    await assert(
      apiShape.defaults && apiShape.defaults.duration === 400,
      'DEFAULTS.duration is 400'
    );
    await assert(
      apiShape.defaults && apiShape.defaults.ease === 'out(3)',
      'DEFAULTS.ease is "out(3)"'
    );
    await assert(apiShape.fadeInType === 'function', 'fadeIn is a function');
    await assert(apiShape.fadeOutType === 'function', 'fadeOut is a function');
    await assert(apiShape.slideInType === 'function', 'slideIn is a function');
    await assert(apiShape.slideInRightType === 'function', 'slideInRight is a function');
    await assert(apiShape.slideOutRightType === 'function', 'slideOutRight is a function');
    await assert(apiShape.scaleInType === 'function', 'scaleIn is a function');
    await assert(apiShape.scaleOutType === 'function', 'scaleOut is a function');
    await assert(apiShape.staggeredAppearType === 'function', 'staggeredAppear is a function');
    await assert(apiShape.cancelAllType === 'function', 'cancelAll is a function');

    // ── Section 2: fadeIn returns Promise, resolves, changes opacity ──
    console.log('\n--- 2. fadeIn ---');

    await page.evaluate(() => {
      const el = document.getElementById('target1');
      el.style.opacity = '0';
    });

    let fadeInResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      window.__fadeInResult = { started: false, resolved: false, opacityBefore: null, opacityAfter: null };
      const r = window.__fadeInResult;
      r.opacityBefore = parseFloat(getComputedStyle(el).opacity);
      r.started = true;
      const p = window.MeshAnim.fadeIn(el, { duration: 100 });
      const isPromise = p instanceof Promise;
      if (isPromise) {
        await p;
        r.resolved = true;
        r.opacityAfter = parseFloat(getComputedStyle(el).opacity);
      }
      r.isPromise = isPromise;
      return r;
    });

    await assert(fadeInResult.isPromise === true, 'fadeIn returns a Promise');
    await assert(fadeInResult.resolved === true, 'fadeIn Promise resolves');
    await assert(fadeInResult.opacityBefore === 0, 'fadeIn starts from opacity 0');
    await assert(fadeInResult.opacityAfter === 1, 'fadeIn ends at opacity 1');

    // ── Section 3: fadeOut returns Promise, resolves, changes opacity ──
    console.log('\n--- 3. fadeOut ---');

    await page.evaluate(() => {
      const el = document.getElementById('target1');
      el.style.opacity = '1';
    });

    let fadeOutResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      window.__fadeOutResult = { started: false, resolved: false, opacityBefore: null, opacityAfter: null };
      const r = window.__fadeOutResult;
      r.opacityBefore = parseFloat(getComputedStyle(el).opacity);
      r.started = true;
      const p = window.MeshAnim.fadeOut(el, { duration: 100 });
      const isPromise = p instanceof Promise;
      if (isPromise) {
        await p;
        r.resolved = true;
        r.opacityAfter = parseFloat(getComputedStyle(el).opacity);
      }
      r.isPromise = isPromise;
      return r;
    });

    await assert(fadeOutResult.isPromise === true, 'fadeOut returns a Promise');
    await assert(fadeOutResult.resolved === true, 'fadeOut Promise resolves');
    await assert(fadeOutResult.opacityBefore === 1, 'fadeOut starts from opacity 1');
    await assert(fadeOutResult.opacityAfter === 0, 'fadeOut ends at opacity 0');

    // ── Section 4: slideIn ───────────────────────────────────────────
    console.log('\n--- 4. slideIn ---');

    let slideInResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      el.style.opacity = '0';
      el.style.transform = '';
      const before = getComputedStyle(el).transform;
      const p = window.MeshAnim.slideIn(el, { duration: 100 });
      const isPromise = p instanceof Promise;
      if (isPromise) await p;
      const after = getComputedStyle(el).transform;
      return { isPromise, before, after, opacityAfter: parseFloat(getComputedStyle(el).opacity) };
    });

    await assert(slideInResult.isPromise === true, 'slideIn returns a Promise');
    await assert(slideInResult.opacityAfter === 1, 'slideIn ends at opacity 1');
    await assert(slideInResult.before !== slideInResult.after, 'slideIn changes transform');

    // ── Section 5: slideInRight ────────────────────────────────────────
    console.log('\n--- 5. slideInRight ---');

    let slideInRightResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      el.style.opacity = '0';
      el.style.transform = '';
      const before = getComputedStyle(el).transform;
      const p = window.MeshAnim.slideInRight(el, { duration: 100 });
      const isPromise = p instanceof Promise;
      if (isPromise) await p;
      const after = getComputedStyle(el).transform;
      return { isPromise, before, after, opacityAfter: parseFloat(getComputedStyle(el).opacity) };
    });

    await assert(slideInRightResult.isPromise === true, 'slideInRight returns a Promise');
    await assert(slideInRightResult.opacityAfter === 1, 'slideInRight ends at opacity 1');
    await assert(slideInRightResult.before !== slideInRightResult.after, 'slideInRight changes transform');

    // ── Section 6: slideOutRight ────────────────────────────────────────
    console.log('\n--- 6. slideOutRight ---');

    let slideOutRightResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      el.style.opacity = '1';
      el.style.transform = '';
      const before = getComputedStyle(el).transform;
      const p = window.MeshAnim.slideOutRight(el, { duration: 100 });
      const isPromise = p instanceof Promise;
      if (isPromise) await p;
      const after = getComputedStyle(el).transform;
      return { isPromise, before, after, opacityAfter: parseFloat(getComputedStyle(el).opacity) };
    });

    await assert(slideOutRightResult.isPromise === true, 'slideOutRight returns a Promise');
    await assert(slideOutRightResult.opacityAfter === 0, 'slideOutRight ends at opacity 0');
    await assert(slideOutRightResult.before !== slideOutRightResult.after, 'slideOutRight changes transform');

    // ── Section 7: scaleIn ────────────────────────────────────────────
    console.log('\n--- 7. scaleIn ---');

    let scaleInResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      el.style.opacity = '0';
      el.style.transform = '';
      const before = getComputedStyle(el).transform;
      const p = window.MeshAnim.scaleIn(el, { duration: 100 });
      const isPromise = p instanceof Promise;
      if (isPromise) await p;
      const after = getComputedStyle(el).transform;
      return { isPromise, before, after, opacityAfter: parseFloat(getComputedStyle(el).opacity) };
    });

    await assert(scaleInResult.isPromise === true, 'scaleIn returns a Promise');
    await assert(scaleInResult.opacityAfter === 1, 'scaleIn ends at opacity 1');
    await assert(scaleInResult.before !== scaleInResult.after, 'scaleIn changes transform');

    // ── Section 8: scaleOut ────────────────────────────────────────────
    console.log('\n--- 8. scaleOut ---');

    let scaleOutResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      el.style.opacity = '1';
      el.style.transform = '';
      const before = getComputedStyle(el).transform;
      const p = window.MeshAnim.scaleOut(el, { duration: 100 });
      const isPromise = p instanceof Promise;
      if (isPromise) await p;
      const after = getComputedStyle(el).transform;
      return { isPromise, before, after, opacityAfter: parseFloat(getComputedStyle(el).opacity) };
    });

    await assert(scaleOutResult.isPromise === true, 'scaleOut returns a Promise');
    await assert(scaleOutResult.opacityAfter === 0, 'scaleOut ends at opacity 0');
    await assert(scaleOutResult.before !== scaleOutResult.after, 'scaleOut changes transform');

    // ── Section 9: staggeredAppear ────────────────────────────────────
    console.log('\n--- 9. staggeredAppear ---');

    let staggeredResult = await page.evaluate(async () => {
      const els = document.querySelectorAll('#sandbox-multi .test-target-multi');
      // Reset them
      els.forEach(e => { e.style.opacity = '0'; e.style.transform = ''; });
      const opacitiesBefore = Array.from(els).map(e => parseFloat(getComputedStyle(e).opacity));
      const p = window.MeshAnim.staggeredAppear('#sandbox-multi .test-target-multi', 30, { duration: 100 });
      const isPromise = p instanceof Promise;
      if (isPromise) await p;
      const opacitiesAfter = Array.from(els).map(e => parseFloat(getComputedStyle(e).opacity));
      return {
        isPromise,
        count: els.length,
        opacitiesBefore,
        opacitiesAfter,
        allOne: opacitiesAfter.every(o => o === 1),
      };
    });

    await assert(staggeredResult.isPromise === true, 'staggeredAppear returns a Promise');
    await assert(staggeredResult.count === 5, 'staggeredAppear targets 5 elements');
    await assert(staggeredResult.allOne === true, 'staggeredAppear sets all elements to opacity 1');
    await assert(
      staggeredResult.opacitiesBefore.every(o => o === 0),
      'staggeredAppear starts from opacity 0'
    );

    // ── Section 10: onComplete callback ───────────────────────────────
    console.log('\n--- 10. onComplete callback ---');

    let onCompleteResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      el.style.opacity = '0';
      let callbackFired = false;
      await window.MeshAnim.fadeIn(el, {
        duration: 100,
        onComplete: function () { callbackFired = true; },
      });
      return { callbackFired };
    });

    await assert(onCompleteResult.callbackFired === true, 'onComplete callback fires when animation completes');

    // ── Section 11: custom options override defaults ──────────────────
    console.log('\n--- 11. option override ---');

    let customOptsResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      el.style.opacity = '0';
      const t0 = performance.now();
      await window.MeshAnim.fadeIn(el, { duration: 200, ease: 'linear' });
      const elapsed = performance.now() - t0;
      return { elapsed };
    });

    await assert(
      customOptsResult.elapsed >= 150,
      `custom duration honoured (expected >= 150ms, got ${customOptsResult.elapsed.toFixed(0)}ms)`
    );

    // ── Section 12: cancelAll ─────────────────────────────────────────
    console.log('\n--- 12. cancelAll ---');

    let cancelResult = await page.evaluate(async () => {
      const el = document.getElementById('target1');
      el.style.opacity = '0';
      // Start a long animation
      const p = window.MeshAnim.fadeIn(el, { duration: 5000 });
      window.MeshAnim.cancelAll();
      // Promise should NOT resolve (or resolve with cancelled state)
      let resolved = false;
      let timedOut = false;
      const race = Promise.race([
        p.then(() => { resolved = true; }),
        new Promise(r => setTimeout(() => { timedOut = true; r(); }, 500)),
      ]);
      await race;
      return { resolved, timedOut };
    });

    await assert(cancelResult.timedOut === true, 'cancelAll prevents Promise resolution within 500ms');
    await assert(cancelResult.resolved === false, 'cancelAll Promise remains unresolved');

    // ── Section 13: concurrent animation tracking ─────────────────────
    console.log('\n--- 13. concurrent animations ---');

    let concurrentResult = await page.evaluate(async () => {
      const els = document.querySelectorAll('#sandbox-multi .test-target-multi');
      els.forEach(e => { e.style.opacity = '0'; });
      // Start 5 concurrent animations (one per element)
      const promises = Array.from(els).map((el, i) =>
        window.MeshAnim.fadeIn(el, { duration: 100, delay: i * 10 })
      );
      // Count active animations before they complete
      const activeQuery = await window.MeshAnim.fadeIn(
        document.getElementById('target1'),
        { duration: 1 }
      );
      // All should resolve
      await Promise.all(promises);
      const finalOpacities = Array.from(els).map(e => parseFloat(getComputedStyle(e).opacity));
      return { allOne: finalOpacities.every(o => o === 1), count: promises.length };
    });

    await assert(concurrentResult.count === 5, '5 concurrent animations started');
    await assert(concurrentResult.allOne === true, 'all concurrent animations complete successfully');

    // ── Section 14: edge case — animation on detached/invisible element ──
    console.log('\n--- 14. edge cases ---');

    let edgeResult = await page.evaluate(async () => {
      // Animation on non-existent selector should not throw
      let threw = false;
      try {
        await window.MeshAnim.fadeIn('#nonexistent-selector-xyz', { duration: 50 });
      } catch (e) {
        threw = true;
      }
      return { threw };
    });

    await assert(edgeResult.threw === false, 'fadeIn on non-existent selector does not throw');

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