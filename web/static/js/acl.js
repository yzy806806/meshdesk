// ACL Dashboard page JavaScript.
// Manages ACL rules, engine settings, and displays hit statistics.

(function() {
  'use strict';

  // State for editing a rule (null = add mode, number = edit index).
  let editingIndex = null;

  // ─── Initialization ───
  document.addEventListener('DOMContentLoaded', function() {
    aclRefresh();
  });

  // ─── Refresh: fetch current ACL status and render ───
  function aclRefresh() {
    fetch('/api/acl/status')
      .then(r => r.json())
      .then(data => {
        document.getElementById('acl-loading').style.display = 'none';
        document.getElementById('acl-content').style.display = '';

        // Engine status
        document.getElementById('acl-enabled').textContent = data.enabled ? 'Yes' : 'No';
        document.getElementById('acl-enabled').className = 'acl-status-badge ' + (data.enabled ? 'badge-ok' : 'badge-off');
        document.getElementById('acl-default-policy').textContent = data.default_policy;
        document.getElementById('acl-allow-count').textContent = data.allow_count;
        document.getElementById('acl-deny-count').textContent = data.deny_count;

        // Engine controls
        document.getElementById('acl-toggle-enabled').checked = data.enabled;
        document.getElementById('acl-toggle-default').value = data.default_policy;

        // Rule hits
        if (data.rule_hits && data.rule_hits.length > 0) {
          document.getElementById('acl-stats-card').style.display = '';
          const tbody = document.getElementById('acl-stats-tbody');
          tbody.innerHTML = data.rule_hits.map(h => 
            '<tr>' +
            '<td>' + h.index + '</td>' +
            '<td class="' + (h.action === 'allow' ? 'acl-allow' : 'acl-deny') + '">' + h.action + '</td>' +
            '<td>' + h.hits + '</td>' +
            '<td>' + escapeHtml(h.description || '') + '</td>' +
            '</tr>'
          ).join('');
        } else {
          document.getElementById('acl-stats-card').style.display = 'none';
        }

        // Render rules table (from rule_hits + descriptions)
        renderRules(data);
      })
      .catch(err => {
        showFeedback('Error loading ACL status: ' + err.message, 'error');
      });
  }
  window.aclRefresh = aclRefresh;

  // ─── Render rules table ───
  function renderRules(data) {
    const tbody = document.getElementById('acl-rules-tbody');
    if (!data.rules || data.rules.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" class="muted">No rules configured. Default policy applies to all traffic.</td></tr>';
      return;
    }

    // Build a lookup from rule_hits by index for hit counts.
    var hitMap = {};
    if (data.rule_hits) {
      data.rule_hits.forEach(function(h) {
        hitMap[h.index] = h;
      });
    }

    tbody.innerHTML = data.rules.map(function(r, i) {
      var hit = hitMap[i];
      var hits = hit ? hit.hits : 0;
      return '<tr>' +
        '<td>' + i + '</td>' +
        '<td class="' + (r.action === 'allow' ? 'acl-allow' : 'acl-deny') + '">' + r.action + '</td>' +
        '<td>' + escapeHtml(r.src_cidr || '*') + '</td>' +
        '<td>' + escapeHtml(r.dst_cidr || '*') + '</td>' +
        '<td>' + escapeHtml(r.protocol || '*') + '</td>' +
        '<td>' + (r.src_port || '*') + '</td>' +
        '<td>' + (r.dst_port || '*') + '</td>' +
        '<td>' + escapeHtml(truncateKey(r.peer_id || '*')) + '</td>' +
        '<td>' + escapeHtml(r.description || '') + '</td>' +
        '<td><button class="small secondary" onclick="aclDeleteRule(' + i + ')">Delete</button></td>' +
        '</tr>';
    }).join('');
  }

  // ─── Save rule (add or update) ───
  function aclSaveRule() {
    const rule = {
      action: document.getElementById('acl-action').value,
      src_cidr: document.getElementById('acl-src-cidr').value || '*',
      dst_cidr: document.getElementById('acl-dst-cidr').value || '*',
      protocol: document.getElementById('acl-protocol').value || '*',
      src_port: parseInt(document.getElementById('acl-src-port').value) || 0,
      dst_port: parseInt(document.getElementById('acl-dst-port').value) || 0,
      peer_id: document.getElementById('acl-peer-id').value || '*',
      description: document.getElementById('acl-description').value || '',
    };

    fetch('/api/acl/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    })
      .then(r => r.json())
      .then(data => {
        if (data.error) {
          showFeedback('Error: ' + data.error, 'error');
        } else {
          showFeedback('Rule added successfully', 'ok');
          clearForm();
          aclRefresh();
        }
      })
      .catch(err => showFeedback('Error: ' + err.message, 'error'));
  }
  window.aclSaveRule = aclSaveRule;

  // ─── Delete rule ───
  function aclDeleteRule(index) {
    if (!confirm('Delete rule #' + index + '?')) return;
    fetch('/api/acl/rules?index=' + index, { method: 'DELETE' })
      .then(r => r.json())
      .then(data => {
        if (data.error) {
          showFeedback('Error: ' + data.error, 'error');
        } else {
          showFeedback('Rule deleted', 'ok');
          aclRefresh();
        }
      })
      .catch(err => showFeedback('Error: ' + err.message, 'error'));
  }
  window.aclDeleteRule = aclDeleteRule;

  // ─── Cancel edit ───
  function aclCancelEdit() {
    clearForm();
  }
  window.aclCancelEdit = aclCancelEdit;

  // ─── Save engine settings ───
  function aclSaveEngine() {
    const enabled = document.getElementById('acl-toggle-enabled').checked;
    const defaultPolicy = document.getElementById('acl-toggle-default').value;

    fetch('/api/acl/engine', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: enabled, default_policy: defaultPolicy }),
    })
      .then(r => r.json())
      .then(data => {
        if (data.error) {
          showFeedback('Error: ' + data.error, 'error');
        } else {
          showFeedback('Engine settings applied', 'ok');
          aclRefresh();
        }
      })
      .catch(err => showFeedback('Error: ' + err.message, 'error'));
  }
  window.aclSaveEngine = aclSaveEngine;

  // ─── Helpers ───
  function clearForm() {
    document.getElementById('acl-action').value = 'allow';
    document.getElementById('acl-src-cidr').value = '';
    document.getElementById('acl-dst-cidr').value = '';
    document.getElementById('acl-protocol').value = '*';
    document.getElementById('acl-src-port').value = '';
    document.getElementById('acl-dst-port').value = '';
    document.getElementById('acl-peer-id').value = '';
    document.getElementById('acl-description').value = '';
    document.getElementById('acl-form-title').textContent = 'Add Rule';
    document.getElementById('acl-save-rule').textContent = 'Add Rule';
    document.getElementById('acl-cancel-edit').style.display = 'none';
    editingIndex = null;
  }

  function showFeedback(msg, type) {
    const el = document.getElementById('acl-feedback');
    el.textContent = msg;
    el.className = 'cfg-feedback ' + (type === 'error' ? 'error' : 'success');
    el.style.display = '';
    setTimeout(() => { el.style.display = 'none'; }, 5000);
  }

  function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function truncateKey(key) {
    if (!key || key === '*' || key.length <= 16) return key;
    return key.substring(0, 8) + '...' + key.substring(key.length - 8);
  }
})();
