// MeshDesk Alerts — notification bar (dashboard) + full alerts history page
(function() {
  'use strict';

  // ── Shared utilities ──────────────────────────────────────

  function severityClass(sev) {
    switch (sev) {
      case 'critical': return 'status-error';
      case 'warning':  return 'status-warn';
      default:         return 'status-ok';
    }
  }

  function severityIcon(sev) {
    switch (sev) {
      case 'critical': return '⛔';
      case 'warning':  return '⚠';
      default:         return 'ℹ';
    }
  }

  function formatTime(ts) {
    if (!ts) return '—';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    var now = new Date();
    var diff = (now - d) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ── Dashboard notification bar ────────────────────────────

  var DashboardBar = {
    pollInterval: null,
    dismissedAt: 0,

    init: function() {
      if (!document.getElementById('alert-bar')) return;
      this.fetch();
      // Poll every 30s for new alerts
      var self = this;
      this.pollInterval = setInterval(function() { self.fetch(); }, 30000);
    },

    fetch: function() {
      var self = this;
      fetch('/api/alerts', { credentials: 'same-origin' })
        .then(function(r) { return r.ok ? r.json() : []; })
        .then(function(alerts) {
          self.render(alerts);
        })
        .catch(function(err) {
          console.error('[MeshDesk] Alert bar fetch error:', err);
        });
    },

    render: function(alerts) {
      var bar = document.getElementById('alert-bar');
      if (!bar) return;

      // Filter: only undismissed alerts created after last dismiss time
      var active = alerts.filter(function(a) {
        return !a.dismissed && new Date(a.timestamp).getTime() > this.dismissedAt;
      }.bind(this));

      if (active.length === 0) {
        bar.style.display = 'none';
        bar.innerHTML = '';
        return;
      }

      // Count by severity
      var critical = active.filter(function(a) { return a.severity === 'critical'; }).length;
      var warning  = active.filter(function(a) { return a.severity === 'warning'; }).length;
      var info     = active.filter(function(a) { return a.severity === 'info'; }).length;

      var parts = [];
      if (critical > 0) parts.push('<span class="alert-bar-count status-error">' + severityIcon('critical') + ' ' + critical + ' critical</span>');
      if (warning > 0)  parts.push('<span class="alert-bar-count status-warn">' + severityIcon('warning') + ' ' + warning + ' warning</span>');
      if (info > 0)     parts.push('<span class="alert-bar-count status-ok">' + severityIcon('info') + ' ' + info + ' info</span>');

      // Show latest alert description
      var latest = active[active.length - 1];
      var latestDesc = escapeHtml(latest.description);

      bar.className = 'alert-bar ' + (critical > 0 ? 'alert-bar-critical' : 'alert-bar-warning');
      bar.style.display = 'flex';
      bar.innerHTML =
        '<div class="alert-bar-summary">' + parts.join(' ') + '</div>' +
        '<div class="alert-bar-latest">' + latestDesc + '</div>' +
        '<div class="alert-bar-actions">' +
          '<a href="/alerts" class="alert-bar-link">View all →</a>' +
          '<button type="button" class="small alert-bar-dismiss" onclick="MeshDeskAlerts.dismissDashboard()">Dismiss</button>' +
        '</div>';
    },

    dismiss: function() {
      var self = this;
      fetch('/api/alerts/dismiss', {
        method: 'POST',
        credentials: 'same-origin'
      }).then(function(r) {
        if (r.ok) {
          self.dismissedAt = Date.now();
          var bar = document.getElementById('alert-bar');
          if (bar) { bar.style.display = 'none'; bar.innerHTML = ''; }
        }
      }).catch(function(err) {
        console.error('[MeshDesk] Alert dismiss error:', err);
      });
    }
  };

  // ── Full alerts history page ──────────────────────────────

  var AlertsPage = {
    allAlerts: [],

    init: function() {
      if (!document.getElementById('alerts-table')) return;
      var self = this;

      // Wire up filter controls
      var sevFilter = document.getElementById('alerts-filter-severity');
      var disFilter = document.getElementById('alerts-filter-dismissed');
      var search    = document.getElementById('alerts-filter-search');
      if (sevFilter) sevFilter.addEventListener('change', function() { self.render(); });
      if (disFilter) disFilter.addEventListener('change', function() { self.render(); });
      if (search)    search.addEventListener('input', function() { self.render(); });

      this.fetch();
    },

    fetch: function() {
      var self = this;
      var loading = document.getElementById('alerts-loading');
      var content = document.getElementById('alerts-content');
      if (loading) loading.style.display = '';
      if (content) content.style.display = 'none';

      fetch('/api/alerts', { credentials: 'same-origin' })
        .then(function(r) { return r.ok ? r.json() : []; })
        .then(function(alerts) {
          self.allAlerts = alerts || [];
          if (loading) loading.style.display = 'none';
          if (content) content.style.display = '';
          self.render();
        })
        .catch(function(err) {
          console.error('[MeshDesk] Alerts fetch error:', err);
          if (loading) loading.innerHTML = '<p class="placeholder">Failed to load alerts.</p>';
        });
    },

    render: function() {
      var tbody = document.getElementById('alerts-tbody');
      var empty = document.getElementById('alerts-empty');
      var badge = document.getElementById('alerts-count-badge');
      var dismissBtn = document.getElementById('alerts-dismiss-btn');
      if (!tbody) return;

      var sevFilter = document.getElementById('alerts-filter-severity');
      var disFilter = document.getElementById('alerts-filter-dismissed');
      var search    = document.getElementById('alerts-filter-search');

      var sevVal = sevFilter ? sevFilter.value : '';
      var disVal = disFilter ? disFilter.value : '';
      var searchVal = search ? search.value.toLowerCase() : '';

      var filtered = this.allAlerts.filter(function(a) {
        if (sevVal && a.severity !== sevVal) return false;
        if (disVal === 'active' && a.dismissed) return false;
        if (disVal === 'dismissed' && !a.dismissed) return false;
        if (searchVal) {
          var hay = (a.description + ' ' + a.type + ' ' + (a.source_ip || '') + ' ' + (a.username || '')).toLowerCase();
          if (hay.indexOf(searchVal) === -1) return false;
        }
        return true;
      });

      // Sort newest first
      filtered.sort(function(a, b) {
        return new Date(b.timestamp) - new Date(a.timestamp);
      });

      // Update count badge
      var activeCount = this.allAlerts.filter(function(a) { return !a.dismissed; }).length;
      if (badge) badge.textContent = activeCount + ' active alert' + (activeCount !== 1 ? 's' : '');

      // Show/hide dismiss button
      if (dismissBtn) dismissBtn.style.display = activeCount > 0 ? '' : 'none';

      if (filtered.length === 0) {
        tbody.innerHTML = '';
        if (empty) empty.style.display = '';
        return;
      }
      if (empty) empty.style.display = 'none';

      tbody.innerHTML = filtered.map(function(a) {
        var cls = severityClass(a.severity);
        var icon = severityIcon(a.severity);
        var source = escapeHtml(a.source_ip || a.username || '—');
        var status = a.dismissed
          ? '<span class="badge status-ok">dismissed</span>'
          : '<span class="badge ' + cls + '">active</span>';
        return '<tr>' +
          '<td class="alert-time">' + formatTime(a.timestamp) + '</td>' +
          '<td><span class="badge ' + cls + '">' + icon + ' ' + escapeHtml(a.severity) + '</span></td>' +
          '<td><code>' + escapeHtml(a.type) + '</code></td>' +
          '<td>' + source + '</td>' +
          '<td class="alert-desc">' + escapeHtml(a.description) + '</td>' +
          '<td>' + status + '</td>' +
        '</tr>';
      }).join('');
    },

    refresh: function() {
      this.fetch();
    },

    dismissAll: function() {
      var self = this;
      fetch('/api/alerts/dismiss', {
        method: 'POST',
        credentials: 'same-origin'
      }).then(function(r) {
        if (r.ok) {
          self.fetch();
        }
      }).catch(function(err) {
        console.error('[MeshDesk] Alert dismiss error:', err);
      });
    }
  };

  // ── Bootstrap ─────────────────────────────────────────────

  // Expose for inline onclick handlers
  window.MeshDeskAlerts = {
    dismissDashboard: function() { DashboardBar.dismiss(); }
  };
  window.AlertsPage = {
    refresh: function() { AlertsPage.refresh(); },
    dismissAll: function() { AlertsPage.dismissAll(); }
  };

  // Auto-init on DOMContentLoaded
  document.addEventListener('DOMContentLoaded', function() {
    DashboardBar.init();
    AlertsPage.init();
  });
})();
