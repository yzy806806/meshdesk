// MeshDesk SOCKS5 Proxy Management UI
// Fetches proxy status from /api/proxy/socks5/status and provides
// configuration editing via the existing /api/config PATCH endpoint.
// Follows the same patterns as config.js (fetchJSON, showToast, etc.)
(function() {
  'use strict';

  // --- Toast helper (same pattern as config.js) ---
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
    toast.style.opacity = '0';
    container.appendChild(toast);
    if (typeof MeshAnim !== 'undefined' && MeshAnim.slideInRight) {
      MeshAnim.slideInRight(toast);
    } else {
      toast.style.opacity = '1';
    }
    setTimeout(function() {
      if (typeof MeshAnim !== 'undefined' && MeshAnim.slideOutRight) {
        MeshAnim.slideOutRight(toast).then(function() {
          if (toast.parentNode) toast.parentNode.removeChild(toast);
        });
      } else {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }
    }, 4000);
  }

  // --- fetch JSON helper (same as config.js) ---
  function fetchJSON(url, opts) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (opts.body && typeof opts.body === 'object') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(url, opts).then(function(r) {
      if (r.status === 429) {
        return r.json().then(function(d) {
          throw new Error(d.error || d.message || 'Rate limited — wait a few seconds');
        });
      }
      return r.json().then(function(data) {
        if (!r.ok) {
          var err = new Error(data.error || data.message || 'HTTP ' + r.status);
          err.data = data;
          err.status = r.status;
          throw err;
        }
        return data;
      });
    });
  }

  // --- HTML escape ---
  function esc(s) {
    if (s === null || s === undefined) return '';
    var str = String(s);
    str = str.replace(/&/g, '&amp;');
    str = str.replace(/</g, '&lt;');
    str = str.replace(/>/g, '&gt;');
    str = str.replace(/"/g, '&quot;');
    return str;
  }

  // --- State ---
  var statusData = null;

  // --- Load proxy status from API ---
  function loadStatus() {
    fetchJSON('/api/proxy/socks5/status').then(function(data) {
      statusData = data;
      renderStatus(data);
      document.getElementById('proxy-loading').style.display = 'none';
      document.getElementById('proxy-content').style.display = 'block';
    }).catch(function(err) {
      document.getElementById('proxy-loading').innerHTML =
        '<p class="placeholder error">Failed to load proxy status: ' + esc(err.message) + '</p>';
    });
  }

  // --- Render status data into the UI ---
  function renderStatus(data) {
    // Phone client connection info
    var serverAddr = '—';
    if (data.local_node && data.local_node.id) {
      // Try to derive a usable address from reality_listen_addr or endpoints
      if (data.reality_listen_addr && data.reality_listen_addr !== '') {
        // Strip leading ":" to get just the bind address, or use as-is
        serverAddr = data.reality_listen_addr;
      } else {
        serverAddr = data.local_node.hostname || data.local_node.short_id || 'this node';
      }
    }
    setText('proxy-server-addr', serverAddr);
    setText('proxy-port', data.proxy_port || 52888);

    // Auth info
    var authText = 'No auth (mesh-encrypted)';
    if (data.socks5_config && data.socks5_config.require_mesh_peer) {
      authText = 'Mesh peer required (auto-authenticated)';
    }
    setText('proxy-auth', authText);

    // Local node status
    if (data.local_node) {
      setText('proxy-local-node', data.local_node.hostname || data.local_node.short_id || '—');
      setText('proxy-local-role', data.local_node.role || '—');
    }

    // Reality TLS status
    setBadge('proxy-reality-status', data.reality_enabled, 'Active', 'Inactive');

    // SOCKS5 handler status
    setBadge('proxy-socks5-status', data.socks5_enabled, 'Running', 'Stopped');

    // Exit handler status
    setBadge('proxy-exit-status', data.socks5_exit_enabled, 'Running', 'Stopped');

    // Active connections
    setText('proxy-active-conns', String(data.active_connections || 0));

    // SOCKS5 config fields
    var s5 = data.socks5_config || {};
    setCheckbox('cfg-socks5-enabled', s5.enabled);
    setCheckbox('cfg-socks5-require-mesh', s5.require_mesh_peer);
    setCheckbox('cfg-socks5-allow-all-ports', s5.allow_all_ports);
    setValue('cfg-socks5-max-conns', s5.max_connections || 256);
    setValue('cfg-socks5-dial-timeout', s5.dial_timeout_sec || 30);
    setValue('cfg-socks5-idle-timeout', s5.idle_timeout_sec || 300);
    setValue('cfg-socks5-allowed-ports', (s5.allowed_ports || []).join(', '));
    setValue('cfg-socks5-dest-filter', (s5.destination_filter || []).join(', '));

    // Exit config fields
    var ec = data.exit_config || {};
    setCheckbox('cfg-exit-allow-all-ports', ec.allow_all_ports);
    setValue('cfg-exit-audit-retention', ec.audit_retention_days || 7);
    setValue('cfg-exit-allowed-ports', (ec.allowed_ports || []).join(', '));
    setValue('cfg-exit-dest-filter', (ec.destination_filter || []).join(', '));

    // Path selection fields
    setValue('cfg-path-mode', data.path_mode || 'manual');
    // Strategy and max_relays not in status API; try to infer from config
    if (data.path_mode) {
      // These come from the config API, not the proxy status API.
      // We'll load them separately if needed.
    }

    // Exit address
    setValue('cfg-exit-addr', data.exit_addr || '');

    // Exit nodes list
    renderNodeList('proxy-exit-nodes-card', 'proxy-exit-nodes-list', data.exit_nodes);

    // Entry nodes list
    renderNodeList('proxy-entry-nodes-card', 'proxy-entry-nodes-list', data.entry_nodes);
  }

  // --- Render a list of mesh nodes (exit or entry) ---
  function renderNodeList(cardId, listId, nodes) {
    var card = document.getElementById(cardId);
    var list = document.getElementById(listId);
    if (!card || !list) return;

    if (!nodes || nodes.length === 0) {
      card.style.display = 'none';
      return;
    }

    card.style.display = 'block';
    var html = '';
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      var statusClass = n.status === 'online' ? 'proxy-node-online' : 'proxy-node-offline';
      html += '<div class="proxy-node-item ' + statusClass + '">';
      html += '<div class="proxy-node-name">' + esc(n.hostname || n.short_id || n.id) + '</div>';
      html += '<div class="proxy-node-detail">';
      html += '<code>' + esc(n.short_id || '') + '</code>';
      if (n.endpoint) {
        html += ' · <code>' + esc(n.endpoint) + '</code>';
      }
      html += '</div>';
      html += '<span class="proxy-node-status ' + statusClass + '">' + esc(n.status || 'unknown') + '</span>';
      html += '</div>';
    }
    list.innerHTML = html;
  }

  // --- Helper: set text content ---
  function setText(id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  // --- Helper: set input value ---
  function setValue(id, val) {
    var el = document.getElementById(id);
    if (el) el.value = val;
  }

  // --- Helper: set checkbox ---
  function setCheckbox(id, checked) {
    var el = document.getElementById(id);
    if (el) el.checked = !!checked;
  }

  // --- Helper: set status badge ---
  function setBadge(id, active, activeText, inactiveText) {
    var el = document.getElementById(id);
    if (!el) return;
    el.textContent = active ? activeText : inactiveText;
    el.className = 'proxy-status-badge ' + (active ? 'badge-active' : 'badge-inactive');
  }

  // --- Collect dirty fields from a set of input IDs ---
  function collectDirty(fieldIds) {
    var patch = {};
    for (var i = 0; i < fieldIds.length; i++) {
      var el = document.getElementById(fieldIds[i]);
      if (!el) continue;
      var path = el.getAttribute('data-config-path');
      if (!path) continue;

      var val;
      if (el.type === 'checkbox') {
        val = el.checked;
      } else if (el.type === 'number') {
        val = parseInt(el.value, 10);
        if (isNaN(val)) continue;
      } else {
        val = el.value.trim();
        // Parse comma-separated lists into arrays
        if (path.indexOf('allowed_ports') >= 0 || path.indexOf('destination_filter') >= 0) {
          if (val === '') {
            val = [];
          } else {
            val = val.split(',').map(function(s) {
              var item = s.trim();
              // Try to parse as number for ports
              if (path.indexOf('allowed_ports') >= 0) {
                var num = parseInt(item, 10);
                return isNaN(num) ? item : num;
              }
              return item;
            }).filter(function(s) { return s !== ''; });
          }
        }
      }
      setPathValue(patch, path, val);
    }
    return patch;
  }

  // --- Set a value at a dotted path in an object (same as config.js) ---
  function setPathValue(obj, path, value) {
    var parts = path.split('.');
    var current = obj;
    for (var i = 0; i < parts.length - 1; i++) {
      if (!current[parts[i]] || typeof current[parts[i]] !== 'object') {
        current[parts[i]] = {};
      }
      current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = value;
  }

  // --- Show feedback banner ---
  function showFeedback(message, type) {
    var el = document.getElementById('proxy-feedback');
    if (!el) return;
    el.className = 'cfg-feedback cfg-feedback-' + (type || 'info');
    el.textContent = message;
    el.style.display = 'block';
    if (typeof MeshAnim !== 'undefined' && MeshAnim.fadeIn) {
      MeshAnim.fadeIn(el);
    }
    if (type === 'success' || type === 'info') {
      setTimeout(function() {
        if (typeof MeshAnim !== 'undefined' && MeshAnim.fadeOut) {
          MeshAnim.fadeOut(el).then(function() {
            el.style.display = 'none';
          });
        } else {
          el.style.display = 'none';
        }
      }, 5000);
    }
  }

  // --- Save SOCKS5 config ---
  window.proxySaveSOCKS5 = function() {
    var patch = collectDirty([
      'cfg-socks5-enabled', 'cfg-socks5-require-mesh', 'cfg-socks5-allow-all-ports',
      'cfg-socks5-max-conns', 'cfg-socks5-dial-timeout', 'cfg-socks5-idle-timeout',
      'cfg-socks5-allowed-ports', 'cfg-socks5-dest-filter',
      'cfg-socks5-entry-listen', 'cfg-socks5-entry-user', 'cfg-socks5-entry-pass'
    ]);

    if (Object.keys(patch).length === 0) {
      showToast('No changes to save', 'info');
      return;
    }

    showFeedback('Saving SOCKS5 configuration...', 'info');
    fetchJSON('/api/config', { method: 'PATCH', body: patch }).then(function(result) {
      var parts = [];
      if (result.applied && result.applied.length > 0) parts.push(result.applied.length + ' field(s) applied');
      if (result.requires_restart && result.requires_restart.length > 0) {
        parts.push(result.requires_restart.length + ' field(s) require restart');
      }
      showFeedback('Saved: ' + (parts.join(', ') || 'no changes'), 'success');
      // Entry listener changes need a daemon restart to take effect —
      // trigger it automatically (step-up token required).
      var needsRestart = patch['cfg-socks5-entry-listen'] !== undefined ||
                         patch['cfg-socks5-entry-user'] !== undefined ||
                         patch['cfg-socks5-entry-pass'] !== undefined;
      if (needsRestart) {
        showFeedback('Entry config saved — restarting daemon...', 'info');
        fetchJSON('/api/config/restart', { method: 'POST' }).then(function(rr) {
          showFeedback('Restart initiated: ' + (rr.message || 'ok'), 'success');
        }).catch(function(err) {
          if (err.status === 403 && err.data && err.data.error === 'step_up_required') {
            showFeedback('Step-up auth required to restart. Please re-authenticate on the Config page, then click Restart.', 'warning');
          } else {
            showFeedback('Saved, but restart failed: ' + err.message, 'warning');
          }
        });
      }
      // Reload status after save
      setTimeout(loadStatus, 500);
    }).catch(function(err) {
      if (err.status === 403 && err.data && err.data.error === 'step_up_required') {
        showFeedback('Step-up auth required for some fields. Please use the Config page to re-authenticate.', 'warning');
      } else {
        showFeedback('Save failed: ' + err.message, 'error');
      }
    });
  };

  // --- Save Exit config ---
  window.proxySaveExit = function() {
    var patch = collectDirty([
      'cfg-exit-allow-all-ports', 'cfg-exit-audit-retention',
      'cfg-exit-allowed-ports', 'cfg-exit-dest-filter'
    ]);

    if (Object.keys(patch).length === 0) {
      showToast('No changes to save', 'info');
      return;
    }

    showFeedback('Saving exit configuration...', 'info');
    fetchJSON('/api/config', { method: 'PATCH', body: patch }).then(function(result) {
      var parts = [];
      if (result.applied && result.applied.length > 0) parts.push(result.applied.length + ' field(s) applied');
      if (result.requires_restart && result.requires_restart.length > 0) {
        parts.push(result.requires_restart.length + ' field(s) require restart');
      }
      showFeedback('Saved: ' + (parts.join(', ') || 'no changes'), 'success');
      setTimeout(loadStatus, 500);
    }).catch(function(err) {
      showFeedback('Save failed: ' + err.message, 'error');
    });
  };

  // --- Save Path config ---
  window.proxySavePaths = function() {
    var patch = collectDirty([
      'cfg-path-mode', 'cfg-path-strategy', 'cfg-path-max-relays', 'cfg-exit-addr'
    ]);

    if (Object.keys(patch).length === 0) {
      showToast('No changes to save', 'info');
      return;
    }

    showFeedback('Saving path configuration...', 'info');
    fetchJSON('/api/config', { method: 'PATCH', body: patch }).then(function(result) {
      var parts = [];
      if (result.applied && result.applied.length > 0) parts.push(result.applied.length + ' field(s) applied');
      if (result.requires_restart && result.requires_restart.length > 0) {
        parts.push(result.requires_restart.length + ' field(s) require restart');
      }
      showFeedback('Saved: ' + (parts.join(', ') || 'no changes'), 'success');
      setTimeout(loadStatus, 500);
    }).catch(function(err) {
      showFeedback('Save failed: ' + err.message, 'error');
    });
  };

  // --- Refresh status ---
  window.proxyRefresh = function() {
    showFeedback('Refreshing proxy status...', 'info');
    loadStatus();
  };

  // --- Hot reload config ---
  window.proxyHotReload = function() {
    showFeedback('Reloading configuration...', 'info');
    fetchJSON('/api/config/reload', { method: 'POST' }).then(function(result) {
      var msg;
      if (result.message && result.message.indexOf('No changes') >= 0) {
        msg = 'No changes pending — config is clean';
      } else {
        var parts = [];
        if (result.applied && result.applied.length > 0) {
          parts.push(result.applied.length + ' field(s) hot-reloaded');
        }
        if (result.rejected && result.rejected.length > 0) {
          parts.push(result.rejected.length + ' field(s) rejected');
        }
        msg = 'Reload complete: ' + (parts.join(', ') || 'no changes');
      }
      showFeedback(msg, 'success');
      loadStatus();
    }).catch(function(err) {
      showFeedback('Reload failed: ' + err.message, 'error');
    });
  };

  // --- Init: load status on page load ---
  if (document.readyState !== 'loading') {
    loadStatus();
  } else {
    document.addEventListener('DOMContentLoaded', loadStatus);
  }

})();
