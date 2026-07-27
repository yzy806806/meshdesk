// MeshDesk Dashboard — SSE live metrics + htmx partial refresh
(function() {
  'use strict';

  let eventSource = null;
  let reconnectDelay = 1000;

  function connectSSE() {
    if (eventSource) eventSource.close();

    eventSource = new EventSource('/api/events');

    eventSource.addEventListener('metrics', function(e) {
      reconnectDelay = 1000; // reset on success
      try {
        const data = JSON.parse(e.data);
        updateNodeCards(data);
        updateStats(data);
      } catch (err) {
        console.error('SSE parse error:', err);
      }
    });

    eventSource.addEventListener('open', function() {
      console.log('[MeshDesk] SSE connected');
    });

    eventSource.onerror = function() {
      console.warn('[MeshDesk] SSE disconnected, reconnecting in ' + reconnectDelay + 'ms');
      eventSource.close();
      setTimeout(connectSSE, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 1.5, 10000);
    };
  }

  function updateNodeCards(data) {
    if (!data.nodes) return;
    const grid = document.getElementById('node-grid');
    if (!grid) return;

    data.nodes.forEach(function(node) {
      const card = grid.querySelector('[data-node="' + node.node_id + '"]');
      if (!card) return;

      // Flash update — remove class on animationend instead of setTimeout
      card.classList.add('updated');
      card.addEventListener('animationend', function handler(e) {
        if (e.animationName === 'metric-flash') {
          card.classList.remove('updated');
          card.removeEventListener('animationend', handler);
        }
      });

      // Update metrics
      const cpuBar = card.querySelector('.metric:nth-child(1) .bar-fill');
      if (cpuBar) {
        cpuBar.style.width = node.cpu_usage.toFixed(0) + '%';
        cpuBar.className = 'bar-fill ' + metricClass(node.cpu_usage);
      }
      const cpuSpan = card.querySelector('.metric:nth-child(1) span');
      if (cpuSpan) cpuSpan.textContent = node.cpu_usage.toFixed(1) + '%';

      const memBar = card.querySelector('.metric:nth-child(2) .bar-fill');
      if (memBar) {
        const memPct = node.mem_total > 0 ? (node.mem_used / node.mem_total * 100) : 0;
        memBar.style.width = memPct.toFixed(0) + '%';
        memBar.className = 'bar-fill ' + metricClass(memPct);
      }
      const memSpan = card.querySelector('.metric:nth-child(2) span');
      if (memSpan) memSpan.textContent = humanBytes(node.mem_used) + ' / ' + humanBytes(node.mem_total);

      const loadSpan = card.querySelector('.metric:nth-child(3) .load-avg');
      if (loadSpan) loadSpan.textContent = node.load1.toFixed(2) + ' / ' + node.load5.toFixed(2) + ' / ' + node.load15.toFixed(2);

      const upSpan = card.querySelector('.metric:nth-child(4) span');
      if (upSpan) upSpan.textContent = humanDuration(node.uptime_seconds);
    });

    // Update node count
    const nc = document.getElementById('node-count');
    if (nc && data.node_count !== undefined) nc.textContent = data.node_count;
  }

  function updateStats(data) {
    const sc = document.getElementById('session-count');
    if (sc && data.active_sessions !== undefined) sc.textContent = data.active_sessions;
  }

  function metricClass(val) {
    if (val >= 90) return 'crit';
    if (val >= 75) return 'warn';
    return '';
  }

  function humanBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let val = bytes;
    while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
    return val.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
  }

  function humanDuration(seconds) {
    if (!seconds) return '—';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
  }

  // Connect on page load if we're on the dashboard
  if (document.getElementById('node-grid')) {
    connectSSE();

    // Staggered appear for initial node cards
    var cards = document.querySelectorAll('#node-grid article');
    if (cards.length > 0) {
      // Override CSS animation with MeshAnim for consistent easing
      cards.forEach(function(c) { c.style.animation = 'none'; });
      MeshAnim.staggeredAppear(cards, 40);
    }
  }

  // Expose for other pages
  window.MeshDesk = {
    humanBytes: humanBytes,
    humanDuration: humanDuration,
    metricClass: metricClass
  };
})();
