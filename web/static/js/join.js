// MeshDesk One-Click Join UI
// Generates a join token and install command from the Dashboard.
(function() {
  'use strict';

  // --- Toast helper ---
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
      if (toast.parentNode) {
        if (typeof MeshAnim !== 'undefined' && MeshAnim.slideOutRight) {
          MeshAnim.slideOutRight(toast).then(function() {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
          });
        } else {
          toast.parentNode.removeChild(toast);
        }
      }
    }, 4000);
  }

  // --- Check join server status on page load ---
  function checkJoinStatus() {
    var statusEl = document.getElementById('join-status-check');
    if (!statusEl) return;

    // Try generating a token with lifetime=0 to check if join is enabled.
    // We actually just try a real token generation but we can also check
    // by looking at the response. For simplicity, we just show the form
    // and let the user try — the API will return an error if join is disabled.
    statusEl.innerHTML = '<p class="muted">Ready to generate an install command.</p>';
    document.getElementById('join-form-section').style.display = '';
  }

  // --- Generate token and install command ---
  window.joinGenerate = function(event) {
    event.preventDefault();

    var lifetime = parseInt(document.getElementById('join-lifetime').value, 10) || 30;
    var arch = document.getElementById('join-arch').value;
    var btn = document.getElementById('join-generate-btn');

    btn.disabled = true;
    btn.textContent = 'Generating...';

    fetch('/api/join/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lifetime: lifetime, arch: arch })
    })
      .then(function(resp) { return resp.json(); })
      .then(function(data) {
        btn.disabled = false;
        btn.textContent = 'Generate Install Command';

        if (!data.success) {
          showToast(data.error || 'Failed to generate token', 'error');
          document.getElementById('join-error-section').style.display = '';
          document.getElementById('join-error-message').textContent = data.error || 'Unknown error';
          document.getElementById('join-result-section').style.display = 'none';
          return;
        }

        // Show the result.
        document.getElementById('join-result-section').style.display = '';
        document.getElementById('join-error-section').style.display = 'none';
        document.getElementById('join-install-command').textContent = data.install_command;
        document.getElementById('join-url-display').textContent = data.join_url;
        document.getElementById('join-token-display').textContent = data.token;

        var expiresMin = Math.round(data.expires_in_seconds / 60);
        document.getElementById('join-expires-display').textContent = expiresMin + ' minute(s)';

        showToast('Install command generated! Token expires in ' + expiresMin + ' min.', 'success');
      })
      .catch(function(err) {
        btn.disabled = false;
        btn.textContent = 'Generate Install Command';
        showToast('Network error: ' + err.message, 'error');
      });
  };

  // --- Copy install command to clipboard ---
  window.joinCopyCommand = function() {
    var codeEl = document.getElementById('join-install-command');
    var text = codeEl.textContent;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function() {
        showToast('Copied to clipboard!', 'success');
      }).catch(function() {
        fallbackCopy(text);
      });
    } else {
      fallbackCopy(text);
    }
  };

  function fallbackCopy(text) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      showToast('Copied to clipboard!', 'success');
    } catch (e) {
      showToast('Copy failed — select and copy manually', 'error');
    }
    document.body.removeChild(textarea);
  }

  // Initialize on DOM ready.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkJoinStatus);
  } else {
    checkJoinStatus();
  }
})();
