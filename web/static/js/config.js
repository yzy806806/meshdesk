// MeshDesk Configuration Management UI
// Follows ADR-003 "Hybrid Islands" — external JS, no inline handlers in template.
// Renders all 11 config sections with tiered field display:
//   T0 read-only: shown greyed, disabled
//   T1 masked:    shown as dots (•••••), writable (send *** to keep existing)
//   T2 step-up:    behind re-auth modal, editable after step-up
//   T3 normal:    editable with standard session auth
(function() {
  'use strict';

  // --- Toast helper (shared pattern, uses MeshAnim anime.js wrapper) ---
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
    // Start invisible for animation
    toast.style.opacity = '0';
    container.appendChild(toast);
    // Slide in from the right
    MeshAnim.slideInRight(toast);
    // Auto-dismiss after 4s: slide out then remove
    setTimeout(function() {
      MeshAnim.slideOutRight(toast).then(function() {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      });
    }, 4000);
  }

  // --- fetch JSON helper ---
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
  var currentSection = 'node';
  var configData = {};       // raw config map from GET /api/config
  var configMeta = {};       // _meta.tier_map from GET /api/config
  var dirtyFields = {};      // track local changes: {path: newValue}
  var pendingStepUpResolve = null; // function to call after step-up
  var pendingStepUpReject = null;

  // --- 11 config sections ---
  var sections = [
    'node', 'mesh', 'peers', 'p2p', 'monitoring',
    'webssh', 'auth', 'transfer', 'proxy', 'xray', 'reality'
  ];

  // --- Section display names ---
  var sectionNames = {
    node: 'Node', mesh: 'Mesh', peers: 'Peers', p2p: 'P2P',
    monitoring: 'Monitoring', webssh: 'WebSSH', auth: 'Auth',
    transfer: 'Transfer', proxy: 'Proxy', xray: 'Xray', reality: 'Reality'
  };

  // --- Tier icons/badges ---
  var tierBadges = {
    'read-only': '<span class="tier-badge tier-readonly" title="Read-only — cannot be modified">🔒 RO</span>',
    'masked': '<span class="tier-badge tier-masked" title="Masked — value hidden, send *** to keep">⚫ M</span>',
    'step-up': '<span class="tier-badge tier-stepup" title="Step-up required — re-enter password to edit">⚠ SU</span>',
    'normal': '<span class="tier-badge tier-normal" title="Normal — editable">✎ N</span>',
    'read-only+masked': '<span class="tier-badge tier-readonly" title="Read-only + Masked">🔒 M</span>'
  };

  // --- Get the tier for a field path from _meta.tier_map ---
  function getTier(path) {
    // Try exact match first
    if (configMeta[path]) return configMeta[path];
    // Try template match: convert indices to [N]
    var tmpl = pathToTemplate(path);
    return configMeta[tmpl] || 'normal';
  }

  // --- Convert actual path (peers[0].preshared_key) to template (peers[N].preshared_key) ---
  function pathToTemplate(path) {
    return path.replace(/\[\d+\]/g, '[N]');
  }

  // --- Check if a field is read-only ---
  function isReadOnly(tier) {
    return tier === 'read-only' || tier === 'read-only+masked';
  }

  // --- Check if a field is masked ---
  function isMasked(tier) {
    return tier === 'masked' || tier === 'read-only+masked';
  }

  // --- Check if a field requires step-up ---
  function isStepUp(tier) {
    return tier === 'step-up';
  }

  // --- Mask value for display (show dots) ---
  function maskValue(val) {
    if (val === null || val === undefined) return '•••••';
    var s = String(val);
    if (s === '***') return '•••••';
    var len = Math.min(s.length, 8);
    return new Array(len + 1).join('•');
  }

  // --- Render a field value for display ---
  function renderValue(val) {
    if (val === null || val === undefined) return '<span class="cfg-null">—</span>';
    if (typeof val === 'boolean') return val ? 'true' : 'false';
    if (typeof val === 'number') return String(val);
    if (Array.isArray(val)) {
      if (val.length === 0) return '<span class="cfg-null">[]</span>';
      return '[<span class="cfg-array">' + val.map(function(v) {
        return '<code>' + esc(JSON.stringify(v)) + '</code>';
      }).join(', ') + ']</span>';
    }
    if (typeof val === 'object') {
      return '<pre class="cfg-object">' + esc(JSON.stringify(val, null, 2)) + '</pre>';
    }
    return esc(val);
  }

  // --- Build input element for a leaf field ---
  function buildInput(path, val, tier) {
    var id = 'cfg-field-' + path.replace(/[^a-zA-Z0-9_]/g, '_');
    var escapedPath = esc(path);

    // Read-only: disabled display-only input
    if (isReadOnly(tier)) {
      return '<div class="cfg-field-readonly">' +
        '<input type="text" id="' + id + '" value="' + esc(String(val)) + '" disabled ' +
        'data-path="' + escapedPath + '" data-tier="' + esc(tier) + '">' +
        '</div>';
    }

    // Masked: password input showing dots, data-original "***"
    if (isMasked(tier)) {
      return '<div class="cfg-field-masked">' +
        '<input type="password" id="' + id + '" value="' + maskValue(val) + '" ' +
        'data-path="' + escapedPath + '" data-tier="' + esc(tier) + '" ' +
        'data-original="***" onfocus="configUnmaskField(this)" onblur="configRemaskField(this)" ' +
        'oninput="configMarkDirty(this)">' +
        '<button type="button" class="cfg-toggle-mask" tabindex="-1" onclick="configToggleMask(this)">👁</button>' +
        '</div>';
    }

    // Step-up: input is disabled until step-up is obtained
    if (isStepUp(tier)) {
      return '<div class="cfg-field-stepup">' +
        '<input type="text" id="' + id + '" value="' + esc(String(val)) + '" disabled ' +
        'data-path="' + escapedPath + '" data-tier="' + esc(tier) + '" ' +
        'oninput="configMarkDirty(this)">' +
        '<span class="cfg-stepup-hint">re-auth required</span>' +
        '</div>';
    }

    // Normal: editable input
    // Detect boolean → checkbox
    if (typeof val === 'boolean') {
      return '<input type="checkbox" id="' + id + '" ' + (val ? 'checked' : '') + ' ' +
        'data-path="' + escapedPath + '" data-tier="' + esc(tier) + '" ' +
        'data-type="boolean" onchange="configMarkDirty(this)">';
    }

    // Detect array of strings → textarea (one per line)
    if (Array.isArray(val)) {
      var text = val.map(function(v) { return JSON.stringify(v); }).join('\n');
      return '<textarea id="' + id + '" rows="' + Math.min(val.length, 8) + '" ' +
        'data-path="' + escapedPath + '" data-tier="' + esc(tier) + '" ' +
        'data-type="array" oninput="configMarkDirty(this)">' + esc(text) + '</textarea>';
    }

    // Number → number input
    if (typeof val === 'number') {
      return '<input type="number" id="' + id + '" value="' + esc(String(val)) + '" ' +
        'data-path="' + escapedPath + '" data-tier="' + esc(tier) + '" ' +
        'data-type="number" oninput="configMarkDirty(this)">';
    }

    // String → text input
    return '<input type="text" id="' + id + '" value="' + esc(String(val)) + '" ' +
      'data-path="' + escapedPath + '" data-tier="' + esc(tier) + '" ' +
      'oninput="configMarkDirty(this)">';
  }

  // --- Render a single field row ---
  function renderField(path, val, tier) {
    var badge = tierBadges[tier] || tierBadges['normal'];
    var label = path.split('.').pop();
    // For array element paths like peers[0].endpoint, show just "endpoint"
    if (label.indexOf(']') >= 0) {
      label = label.replace(/^.*\]\./, '');
    }

    return '<div class="cfg-field-row" data-field-path="' + esc(path) + '" data-tier="' + esc(tier) + '">' +
      '<label class="cfg-field-label" for="cfg-field-' + esc(path.replace(/[^a-zA-Z0-9_]/g, '_')) + '">' +
        esc(label) + ' ' + badge +
        '<small class="cfg-field-path">' + esc(path) + '</small>' +
      '</label>' +
      '<div class="cfg-field-input">' + buildInput(path, val, tier) + '</div>' +
      '</div>';
  }

  // --- Recursively render an object's fields ---
  function renderObject(obj, prefix, depth) {
    var html = '';
    if (obj === null || typeof obj !== 'object') {
      return '<div class="cfg-field-row"><span class="cfg-null">No fields</span></div>';
    }

    if (Array.isArray(obj)) {
      // Array of objects (e.g. peers, auth.web_users)
      for (var i = 0; i < obj.length; i++) {
        var itemPath = prefix + '[' + i + ']';
        if (typeof obj[i] === 'object' && obj[i] !== null && !Array.isArray(obj[i])) {
          html += '<div class="cfg-array-item" style="margin-left:' + (depth * 1.5) + 'rem;">';
          html += '<h4 class="cfg-array-header">' + esc(prefix.split('.').pop()) + '[' + i + ']</h4>';
          html += renderObject(obj[i], itemPath, depth + 1);
          html += '</div>';
        } else {
          // Array of scalars — render as field
          var tier = getTier(itemPath);
          html += renderField(itemPath, obj[i], tier);
        }
      }
      return html;
    }

    // Object — iterate keys
    var keys = Object.keys(obj);
    for (var k = 0; k < keys.length; k++) {
      var key = keys[k];
      var path = prefix ? prefix + '.' + key : key;
      var val = obj[key];

      if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
        // Nested object — recurse with a sub-header
        html += '<div class="cfg-group" style="margin-left:' + (depth * 1.5) + 'rem;">';
        html += '<h4 class="cfg-group-header">' + esc(key) + '</h4>';
        html += renderObject(val, path, depth + 1);
        html += '</div>';
      } else if (Array.isArray(val)) {
        if (val.length > 0 && typeof val[0] === 'object') {
          // Array of objects
          html += '<div class="cfg-group" style="margin-left:' + (depth * 1.5) + 'rem;">';
          html += '<h4 class="cfg-group-header">' + esc(key) + '</h4>';
          html += renderObject(val, path, depth);
          html += '</div>';
        } else {
          // Array of scalars
          var tier2 = getTier(path);
          html += renderField(path, val, tier2);
        }
      } else {
        // Leaf field
        var tier3 = getTier(path);
        html += renderField(path, val, tier3);
      }
    }
    return html;
  }

  // --- Load full config from API ---
  function loadConfig() {
    var content = document.getElementById('cfg-content');
    if (!content) return;
    content.innerHTML = '<p class="placeholder">Loading configuration…</p>';

    fetchJSON('/api/config').then(function(data) {
      // Extract _meta before storing config data
      configMeta = (data._meta && data._meta.tier_map) || {};
      delete data._meta;
      configData = data;

      // Check for pending restart
      updatePendingRestart();

      // Render current section
      renderSection(currentSection);
    }).catch(function(err) {
      content.innerHTML = '<p class="placeholder error">Failed to load config: ' + esc(err.message) + '</p>';
    });
  }

  // --- Render a specific section ---
  function renderSection(section) {
    var content = document.getElementById('cfg-content');
    if (!content) return;

    var sectionData = configData[section];
    if (sectionData === undefined) {
      content.innerHTML = '<p class="placeholder error">Section "' + esc(section) + '" not found in config data.</p>';
      return;
    }

    var html = '<div class="cfg-section-content" data-section="' + esc(section) + '">';

    // Section header
    html += '<div class="cfg-section-header">';
    html += '<h3>' + esc(sectionNames[section] || section) + '</h3>';
    html += '<button type="button" class="small primary" id="cfg-save-' + esc(section) + '" onclick="configSaveSection(\'' + esc(section) + '\')">Save Changes</button>';
    html += '</div>';

    // Render fields
    html += renderObject(sectionData, section, 0);

    html += '</div>';
    content.innerHTML = html;

    // Animate the new section content in
    var sectionEl = content.querySelector('.cfg-section-content');
    if (sectionEl) {
      MeshAnim.slideIn(sectionEl);
    }

    // Reset dirty state for this section
    dirtyFields = {};
    updateSaveButton(section);
  }

  // --- Update pending restart indicator ---
  function updatePendingRestart() {
    fetchJSON('/api/config/diff').then(function(data) {
      var el = document.getElementById('cfg-pending-restart');
      var fieldsEl = document.getElementById('cfg-pending-fields');
      if (!el) return;

      if (data.pending_restart) {
        el.style.display = 'flex';
        MeshAnim.fadeIn(el);
        var fields = data.running_vs_saved || {};
        var names = Object.keys(fields).slice(0, 5);
        if (fieldsEl) {
          fieldsEl.textContent = names.length > 0 ? names.join(', ') : '';
        }
      } else {
        if (el.style.display !== 'none') {
          MeshAnim.fadeOut(el).then(function() {
            el.style.display = 'none';
          });
        }
      }
    }).catch(function() {
      // Silently ignore — diff is non-critical
    });
  }

  // --- Update save button state based on dirty fields ---
  function updateSaveButton(section) {
    var btn = document.getElementById('cfg-save-' + section);
    if (!btn) return;
    var hasDirty = Object.keys(dirtyFields).length > 0;
    btn.disabled = !hasDirty;
    if (hasDirty) {
      btn.classList.add('pulse');
    } else {
      btn.classList.remove('pulse');
    }
  }

  // --- Mark a field as dirty (changed) ---
  window.configMarkDirty = function(input) {
    var path = input.getAttribute('data-path');
    if (!path) return;

    var val;
    if (input.type === 'checkbox') {
      val = input.checked;
    } else if (input.getAttribute('data-type') === 'number') {
      val = parseFloat(input.value);
    } else if (input.getAttribute('data-type') === 'array') {
      var text = input.value.trim();
      if (!text) {
        val = [];
      } else {
        val = text.split('\n').map(function(line) {
          try { return JSON.parse(line); } catch(e) { return line; }
        });
      }
    } else if (input.getAttribute('data-type') === 'boolean') {
      val = input.checked;
    } else {
      val = input.value;
    }

    // For masked fields: if value still shows dots, treat as *** (no-op)
    if (input.getAttribute('data-original') === '***' && input.value === maskValue(input.value)) {
      val = '***';
    }

    dirtyFields[path] = val;
    updateSaveButton(currentSection);
  };

  // --- Unmask a masked field on focus (show *** so user knows it's masked) ---
  window.configUnmaskField = function(input) {
    if (input.value === maskValue(input.value)) {
      input.value = '***';
      input.select();
    }
  };

  window.configRemaskField = function(input) {
    if (input.value === '***' || input.value === '') {
      input.value = maskValue(input.getAttribute('data-original') || '');
    }
  };

  // --- Toggle mask visibility ---
  window.configToggleMask = function(btn) {
    var input = btn.previousElementSibling;
    if (!input) return;
    if (input.type === 'password') {
      input.type = 'text';
      btn.textContent = '🙈';
    } else {
      input.type = 'password';
      btn.textContent = '👁';
    }
  };

  // --- Select a tab ---
  window.configSelectTab = function(section) {
    if (section === currentSection) return;

    // Update tab states
    var tabs = document.querySelectorAll('.config-tab');
    for (var i = 0; i < tabs.length; i++) {
      var isActive = tabs[i].getAttribute('data-section') === section;
      tabs[i].classList.toggle('active', isActive);
      tabs[i].setAttribute('aria-selected', isActive ? 'true' : 'false');
    }

    currentSection = section;
    renderSection(section);
  };

  // --- Save a section's changes ---
  window.configSaveSection = function(section) {
    // Collect dirty fields for this section
    var patch = {};
    var hasStepUp = false;

    var paths = Object.keys(dirtyFields);
    for (var i = 0; i < paths.length; i++) {
      var path = paths[i];
      // Only include fields for this section
      if (path.indexOf(section + '.') !== 0 && path.indexOf(section + '[') !== 0) continue;

      // Check tier
      var tier = getTier(path);
      if (isStepUp(tier)) hasStepUp = true;

      // Build nested path in patch object
      setPathValue(patch, path, dirtyFields[path]);
    }

    if (Object.keys(patch).length === 0) {
      showToast('No changes to save', 'info');
      return;
    }

    // If step-up fields are present, request step-up first
    if (hasStepUp) {
      configRequestStepUp().then(function() {
        doSave(patch);
      }).catch(function(err) {
        showToast('Step-up auth cancelled: ' + (err.message || 'cancelled'), 'warning');
      });
    } else {
      doSave(patch);
    }
  };

  // --- Actually send the PATCH request ---
  function doSave(patch) {
    showFeedback('Saving configuration…', 'info');

    fetchJSON('/api/config', {
      method: 'PATCH',
      body: patch
    }).then(function(result) {
      var parts = [];
      if (result.applied && result.applied.length > 0) {
        parts.push(result.applied.length + ' field(s) applied');
      }
      if (result.requires_restart && result.requires_restart.length > 0) {
        parts.push(result.requires_restart.length + ' field(s) require restart');
      }
      if (result.noop && result.noop.length > 0) {
        parts.push(result.noop.length + ' field(s) unchanged');
      }
      var msg = result.ok ? 'Saved: ' + parts.join(', ') : 'Save failed';
      showFeedback(msg, result.ok ? 'success' : 'error');

      if (result.ok) {
        dirtyFields = {};
        updateSaveButton(currentSection);
        // Reload config data to reflect changes
        loadConfig();
      }

      if (result.pending_restart) {
        updatePendingRestart();
      }
    }).catch(function(err) {
      // Check for step-up required
      if (err.status === 403 && err.data && err.data.error === 'step_up_required') {
        showFeedback('Step-up auth required for: ' + (err.data.fields_requiring_step_up || []).join(', '), 'warning');
        configRequestStepUp().then(function() {
          doSave(patch); // retry after step-up
        }).catch(function() {
          showFeedback('Step-up auth cancelled', 'warning');
        });
      } else {
        showFeedback('Save failed: ' + err.message, 'error');
      }
    });
  }

  // --- Set a value at a dotted path in an object ---
  function setPathValue(obj, path, value) {
    // Parse path into segments, handling array indices
    // e.g. "peers[0].endpoint" → ["peers", 0, "endpoint"]
    var segments = parsePath(path);
    var current = obj;

    for (var i = 0; i < segments.length - 1; i++) {
      var seg = segments[i];
      var next = segments[i + 1];

      if (typeof seg === 'number') {
        if (!Array.isArray(current)) current = [];
        if (!current[seg]) {
          current[seg] = (typeof next === 'number') ? [] : {};
        }
        current = current[seg];
      } else {
        if (!current[seg]) {
          current[seg] = (typeof next === 'number') ? [] : {};
        }
        if (!Array.isArray(current[seg]) && typeof current[seg] !== 'object') {
          current[seg] = (typeof next === 'number') ? [] : {};
        }
        if (typeof current[seg] === 'string') {
          current[seg] = (typeof next === 'number') ? [] : {};
        }
        if (!current[seg]) {
          current[seg] = (typeof next === 'number') ? [] : {};
        }
        current = current[seg];
      }
    }

    var lastSeg = segments[segments.length - 1];
    if (typeof lastSeg === 'number') {
      if (!Array.isArray(current)) current = [];
      current[lastSeg] = value;
    } else {
      current[lastSeg] = value;
    }
  }

  // --- Parse a dotted path into segments (string keys + numeric indices) ---
  function parsePath(path) {
    var segments = [];
    var parts = path.split('.');
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      // Check for array index notation: "peers[0]"
      var match = part.match(/^([a-zA-Z_]\w*)\[(\d+)\]$/);
      if (match) {
        segments.push(match[1]);
        segments.push(parseInt(match[2], 10));
      } else if (/^\d+$/.test(part)) {
        segments.push(parseInt(part, 10));
      } else {
        segments.push(part);
      }
    }
    return segments;
  }

  // --- Step-up auth modal ---
  window.configRequestStepUp = function() {
    return new Promise(function(resolve, reject) {
      pendingStepUpResolve = resolve;
      pendingStepUpReject = reject;
      var modal = document.getElementById('cfg-stepup-modal');
      if (modal) {
        modal.style.display = 'flex';
        MeshAnim.fadeIn(modal);
      }
      var passwordInput = document.getElementById('cfg-stepup-password');
      if (passwordInput) {
        passwordInput.value = '';
        passwordInput.focus();
      }
    });
  };

  window.configCloseStepUp = function() {
    var modal = document.getElementById('cfg-stepup-modal');
    if (modal) {
      MeshAnim.fadeOut(modal).then(function() {
        modal.style.display = 'none';
      });
    }
    if (pendingStepUpReject) {
      pendingStepUpReject(new Error('cancelled'));
      pendingStepUpReject = null;
      pendingStepUpResolve = null;
    }
  };

  window.configSubmitStepUp = function(e) {
    e.preventDefault();
    var password = (document.getElementById('cfg-stepup-password') || {}).value;

    fetch('/api/stepup/verify?op=settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'password=' + encodeURIComponent(password)
    }).then(function(r) {
      if (r.ok) {
        var modal = document.getElementById('cfg-stepup-modal');
        if (modal) {
          MeshAnim.fadeOut(modal).then(function() {
            modal.style.display = 'none';
          });
        }
        if (pendingStepUpResolve) {
          pendingStepUpResolve();
          pendingStepUpResolve = null;
          pendingStepUpReject = null;
        }
        showToast('Step-up auth granted', 'success');
      } else {
        showToast('Step-up auth failed — check password', 'error');
        var input = document.getElementById('cfg-stepup-password');
        if (input) { input.value = ''; input.focus(); }
      }
    }).catch(function() {
      showToast('Network error during step-up', 'error');
    });
  };

  // --- Hot reload ---
  window.configReload = function() {
    showFeedback('Reloading configuration…', 'info');
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

      if (result.pending_restart) {
        updatePendingRestart();
      }
    }).catch(function(err) {
      showFeedback('Reload failed: ' + err.message, 'error');
    });
  };

  // --- Restart daemon ---
  window.configRestart = function() {
    if (!confirm('Restart the MeshDesk daemon? This will cause a brief downtime (3-5 seconds).')) return;

    showFeedback('Initiating daemon restart…', 'info');
    fetchJSON('/api/config/restart', { method: 'POST' }).then(function(result) {
      showFeedback(result.message || 'Daemon restart initiated', 'warning');
      // Update UI after restart
      setTimeout(function() {
        loadConfig();
        updatePendingRestart();
      }, 6000);
    }).catch(function(err) {
      showFeedback('Restart failed: ' + err.message, 'error');
    });
  };

  // --- View diff ---
  window.configDiff = function() {
    var modal = document.getElementById('cfg-diff-modal');
    var body = document.getElementById('cfg-diff-body');
    if (!modal || !body) return;

    modal.style.display = 'flex';
    MeshAnim.fadeIn(modal);
    body.innerHTML = '<p class="placeholder">Loading diff…</p>';

    fetchJSON('/api/config/diff').then(function(data) {
      var diff = data.running_vs_saved || {};
      var keys = Object.keys(diff);

      if (keys.length === 0) {
        body.innerHTML = '<p class="placeholder">No differences — running config matches saved config.</p>';
        return;
      }

      var html = '<table class="cfg-diff-table"><thead><tr><th>Field</th><th>Running</th><th>Saved</th><th>Tier</th><th>Reload</th></tr></thead><tbody>';
      for (var i = 0; i < keys.length; i++) {
        var path = keys[i];
        var entry = diff[path];
        html += '<tr>';
        html += '<td><code>' + esc(path) + '</code></td>';
        html += '<td>' + renderValue(entry.running) + '</td>';
        html += '<td>' + renderValue(entry.saved) + '</td>';
        html += '<td>' + (entry.tier ? '<span class="tier-badge tier-' + esc(entry.tier) + '">' + esc(entry.tier) + '</span>' : '—') + '</td>';
        html += '<td>' + (entry.reload ? esc(entry.reload) : '—') + '</td>';
        html += '</tr>';
      }
      html += '</tbody></table>';

      if (data.pending_restart) {
        html += '<div class="cfg-diff-warning"><span class="badge warning">⚠ Restart required to apply pending changes</span></div>';
      }

      body.innerHTML = html;
    }).catch(function(err) {
      body.innerHTML = '<p class="placeholder error">Failed to load diff: ' + esc(err.message) + '</p>';
    });
  };

  window.configCloseDiff = function() {
    var modal = document.getElementById('cfg-diff-modal');
    if (modal) {
      MeshAnim.fadeOut(modal).then(function() {
        modal.style.display = 'none';
      });
    }
  };

  // --- Feedback banner (uses MeshAnim for show/hide) ---
  function showFeedback(message, type) {
    var el = document.getElementById('cfg-feedback');
    if (!el) return;
    el.className = 'cfg-feedback cfg-feedback-' + (type || 'info');
    el.textContent = message;
    el.style.display = 'block';
    MeshAnim.fadeIn(el);

    if (type === 'success' || type === 'info') {
      setTimeout(function() {
        MeshAnim.fadeOut(el).then(function() {
          el.style.display = 'none';
        });
      }, 5000);
    }
  }

  // --- Init: load config on page load ---
  if (document.readyState !== 'loading') {
    loadConfig();
  } else {
    document.addEventListener('DOMContentLoaded', loadConfig);
  }

})();
