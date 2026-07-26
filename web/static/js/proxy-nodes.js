// MeshDesk Proxy Nodes — xray inbound CRUD UI
// Follows ADR-003 "Hybrid Islands" — inline-free external JS.
(function() {
  'use strict';

  // Toast helper (shared pattern with services.html showToast)
  function showToast(message, type) {
    var container = document.querySelector('.toast-container');
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    var toast = document.createElement('div');
    toast.className = 'toast ' + (type || 'info');
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(function() {
      toast.classList.add('removing');
      setTimeout(function() {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 300);
    }, 4000);
  }

  // fetch JSON helper with error handling
  function fetchJSON(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (opts.body && typeof opts.body === 'object') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(url, opts).then(function(r) {
      return r.json().then(function(data) {
        if (!r.ok) {
          throw new Error(data.error || 'HTTP ' + r.status);
        }
        return data;
      });
    });
  }

  // --- xray status ---

  function loadXrayStatus() {
    fetchJSON('/api/xray/status').then(function(data) {
      var badge = document.getElementById('xray-running-badge');
      var meta  = document.getElementById('xray-meta');
      if (!badge || !meta) return;

      if (data.running) {
        badge.textContent = '● Running';
        badge.className = 'xray-state-badge running';
      } else {
        badge.textContent = '○ Stopped';
        badge.className = 'xray-state-badge stopped';
      }
      var parts = [];
      if (data.pid) parts.push('PID: ' + data.pid);
      if (data.started_at) parts.push('Started: ' + data.started_at);
      parts.push('Inbounds: ' + data.inbound_count);
      parts.push('Restarts: ' + data.restart_count);
      meta.textContent = parts.join(' | ');
    }).catch(function(err) {
      // Status endpoint may return 503 if xray manager is nil
      var badge = document.getElementById('xray-running-badge');
      if (badge) {
        badge.textContent = '— Unavailable';
        badge.className = 'xray-state-badge stopped';
      }
    });
  }

  // --- inbound list ---

  function loadInbounds() {
    fetchJSON('/api/xray/inbound').then(function(data) {
      var body = document.getElementById('inbound-list-body');
      if (!body) return;

      var inbounds = data.inbounds || [];
      if (inbounds.length === 0) {
        body.innerHTML = '<tr><td colspan="7" class="placeholder">No inbounds deployed. Create one below.</td></tr>';
        return;
      }

      body.innerHTML = inbounds.map(function(ib) {
        var clientCount = (ib.vless_clients || []).length;
        var clientDetail = clientCount > 0
          ? clientCount + ' client' + (clientCount > 1 ? 's' : '')
          : '—';
        return '<tr data-tag="' + escapeAttr(ib.tag) + '">' +
          '<td><code>' + escapeHTML(ib.tag) + '</code></td>' +
          '<td>' + escapeHTML(ib.protocol || 'vless-reality') + '</td>' +
          '<td>' + (ib.port || '—') + '</td>' +
          '<td><code>' + escapeHTML(ib.listen || '0.0.0.0') + '</code></td>' +
          '<td>' + escapeHTML(ib.security || 'reality') + '</td>' +
          '<td>' + clientDetail + '</td>' +
          '<td><button type="button" class="small contrast" onclick="deleteInbound(\'' + escapeAttr(ib.tag) + '\')">Delete</button>' +
          ' <button type="button" class="small secondary" onclick="showInboundDetail(\'' + escapeAttr(ib.tag) + '\')">Details</button></td>' +
          '</tr>';
      }).join('');
    }).catch(function(err) {
      var body = document.getElementById('inbound-list-body');
      if (body) body.innerHTML = '<tr><td colspan="7" class="placeholder error">Failed to load inbounds: ' + escapeHTML(err.message) + '</td></tr>';
    });
  }

  // --- inbound detail (modal-like alert using toast) ---

  window.showInboundDetail = function(tag) {
    fetchJSON('/api/xray/inbound?tag=' + encodeURIComponent(tag)).then(function(ib) {
      var lines = [
        'Tag: ' + ib.tag,
        'Protocol: ' + ib.protocol,
        'Port: ' + ib.port,
        'Listen: ' + (ib.listen || '0.0.0.0'),
        'Security: ' + (ib.security || 'reality'),
        'Network: ' + (ib.network || 'tcp')
      ];
      if (ib.dest) lines.push('Dest: ' + ib.dest);
      if (ib.server_names && ib.server_names.length > 0) lines.push('Server Names: ' + ib.server_names.join(', '));
      if (ib.short_ids && ib.short_ids.length > 0) lines.push('Short IDs: ' + ib.short_ids.join(', '));
      if (ib.vless_clients && ib.vless_clients.length > 0) {
        ib.vless_clients.forEach(function(c) {
          lines.push('Client UUID: ' + c.id + (c.flow ? ' (' + c.flow + ')' : ''));
        });
      }
      showToast(lines.join(' | '), 'info');
    }).catch(function(err) {
      showToast('Failed to get inbound detail: ' + err.message, 'error');
    });
  };

  // --- create inbound ---

  window.createInbound = function(event) {
    event.preventDefault();

    var tag = val('inbound-tag');
    var port = parseInt(val('inbound-port'), 10);

    if (!tag) { showToast('Tag is required', 'warning'); return; }
    if (!port || port < 1 || port > 65535) { showToast('Valid port (1-65535) is required', 'warning'); return; }

    var protocol = val('inbound-protocol');
    var security = 'reality';
    if (protocol === 'vless-tls') security = 'tls';
    else if (protocol === 'vless') security = 'none';

    var req = {
      tag: tag,
      protocol: protocol,
      port: port,
      listen: val('inbound-listen') || '0.0.0.0',
      network: val('inbound-network') || 'tcp',
      security: security,
      auto_start: document.getElementById('inbound-auto-start').checked
    };

    // Optional fields — only set if user provided a value
    var dest = val('inbound-dest');
    if (dest) req.dest = dest;

    var sn = val('inbound-server-names');
    if (sn) req.server_names = sn.split(',').map(function(s) { return s.trim(); }).filter(Boolean);

    var si = val('inbound-short-ids');
    if (si && si !== 'auto') req.short_ids = si.split(',').map(function(s) { return s.trim(); }).filter(Boolean);

    var pk = val('inbound-private-key');
    if (pk && pk !== 'auto-generated') req.private_key = pk;

    var uuid = val('inbound-vless-uuid');
    if (uuid && uuid !== 'auto-generated') {
      req.vless_clients = [{ id: uuid, flow: 'xtls-rprx-vision' }];
    }

    fetchJSON('/api/xray/inbound', { method: 'POST', body: req }).then(function(data) {
      var msg = 'Inbound "' + tag + '" created';
      if (data.reload_status) msg += ' — ' + data.reload_status;
      showToast(msg, 'success');
      // Reset form
      document.getElementById('create-inbound-form').reset();
      // Reload lists
      loadInbounds();
      loadXrayStatus();
    }).catch(function(err) {
      showToast('Failed to create inbound: ' + err.message, 'error');
    });
  };

  // --- delete inbound ---

  window.deleteInbound = function(tag) {
    if (!confirm('Delete inbound "' + tag + '"? This will reload xray if running.')) return;

    fetchJSON('/api/xray/inbound?tag=' + encodeURIComponent(tag) + '&reload=true', {
      method: 'DELETE'
    }).then(function(data) {
      var msg = 'Inbound "' + tag + '" deleted';
      if (data.reload_status) msg += ' — ' + data.reload_status;
      showToast(msg, 'success');
      loadInbounds();
      loadXrayStatus();
    }).catch(function(err) {
      showToast('Failed to delete inbound: ' + err.message, 'error');
    });
  };

  // --- xray control (start/stop/reload) ---

  window.xrayControl = function(action) {
    fetchJSON('/api/xray/' + action, { method: 'POST' }).then(function(data) {
      showToast('xray ' + action + ' successful', 'success');
      loadXrayStatus();
    }).catch(function(err) {
      showToast('xray ' + action + ' failed: ' + err.message, 'error');
    });
  };

  // --- view logs ---

  window.xrayViewLogs = function() {
    var panel = document.getElementById('xray-logs-panel');
    var output = document.getElementById('xray-log-output');
    if (!panel || !output) return;

    if (panel.style.display === 'none') {
      panel.style.display = '';
      output.textContent = 'Loading logs…';
    }

    fetchJSON('/api/xray/logs?n=50').then(function(data) {
      var entries = data.entries || [];
      if (entries.length === 0) {
        output.textContent = 'No log entries captured yet.';
        return;
      }
      output.textContent = entries.map(function(e) {
        var ts = e.timestamp || '';
        var lvl = e.level || '';
        var msg = e.message || e.msg || '';
        return '[' + ts + '] ' + lvl + ' ' + msg;
      }).join('\n');
    }).catch(function(err) {
      output.textContent = 'Failed to load logs: ' + err.message;
    });
  };

  // --- helpers ---

  function val(id) {
    var el = document.getElementById(id);
    return el ? el.value.trim() : '';
  }

  function escapeHTML(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function escapeAttr(s) {
    if (!s) return '';
    return String(s).replace(/'/g, '&#39;').replace(/"/g, '&quot;');
  }

  // --- init on page load ---

  document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('xray-status-bar')) {
      loadXrayStatus();
      loadInbounds();
      // Auto-refresh status every 10s
      setInterval(loadXrayStatus, 10000);
    }
  });

})();
