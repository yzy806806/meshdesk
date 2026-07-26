// MeshDesk x-ui Panel — traffic stats, client management, share links
// Follows ADR-003 "Hybrid Islands" — inline-free external JS.
(function() {
  'use strict';

  // --- Toast helper (shared pattern) ---
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

  // fetch JSON helper
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

  // --- Human bytes helper ---
  function humanBytes(bytes) {
    if (!bytes || bytes < 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = 0;
    while (bytes >= 1024 && i < units.length - 1) {
      bytes /= 1024;
      i++;
    }
    return bytes.toFixed(i > 0 ? 2 : 0) + ' ' + units[i];
  }

  // --- HTML escape helpers ---
  function escapeHTML(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function escapeAttr(s) {
    if (!s) return '';
    return String(s).replace(/'/g, '&#39;').replace(/"/g, '&quot;');
  }

  function val(id) {
    var el = document.getElementById(id);
    return el ? el.value.trim() : '';
  }

  // =====================
  // Traffic Stats
  // =====================

  var statsAutoRefreshTimer = null;

  window.loadStats = function() {
    fetchJSON('/api/xray/stats').then(function(data) {
      var body = document.getElementById('xui-stats-body');
      if (!body) return;

      var inbounds = data.inbounds || [];
      if (inbounds.length === 0) {
        body.innerHTML = '<tr><td colspan="4" class="placeholder">No traffic stats available yet.</td></tr>';
      } else {
        body.innerHTML = inbounds.map(function(ib) {
          return '<tr>' +
            '<td><code>' + escapeHTML(ib.tag) + '</code></td>' +
            '<td>' + humanBytes(ib.uplink) + '</td>' +
            '<td>' + humanBytes(ib.downlink) + '</td>' +
            '<td><strong>' + humanBytes(ib.total) + '</strong></td>' +
            '</tr>';
        }).join('');
      }

      // Client stats
      var clientBody = document.getElementById('xui-client-stats-body');
      if (clientBody) {
        var clients = data.clients || [];
        if (clients.length === 0) {
          clientBody.innerHTML = '<tr><td colspan="4" class="placeholder">No client traffic stats.</td></tr>';
        } else {
          clientBody.innerHTML = clients.map(function(c) {
            return '<tr>' +
              '<td>' + escapeHTML(c.email) + '</td>' +
              '<td>' + humanBytes(c.uplink) + '</td>' +
              '<td>' + humanBytes(c.downlink) + '</td>' +
              '<td><strong>' + humanBytes(c.total) + '</strong></td>' +
              '</tr>';
          }).join('');
        }
      }
    }).catch(function(err) {
      var body = document.getElementById('xui-stats-body');
      if (body) body.innerHTML = '<tr><td colspan="4" class="placeholder error">Failed to load stats: ' + escapeHTML(err.message) + '</td></tr>';
    });
  };

  // Auto-refresh toggle
  document.addEventListener('change', function(e) {
    if (e.target && e.target.id === 'xui-stats-auto') {
      if (e.target.checked) {
        loadStats();
        statsAutoRefreshTimer = setInterval(loadStats, 5000);
      } else {
        if (statsAutoRefreshTimer) {
          clearInterval(statsAutoRefreshTimer);
          statsAutoRefreshTimer = null;
        }
      }
    }
  });

  // =====================
  // Client Management
  // =====================

  window.loadInboundOptions = function() {
    fetchJSON('/api/xray/inbound').then(function(data) {
      var inbounds = data.inbounds || [];
      populateInboundSelects(inbounds);
    }).catch(function(err) {
      showToast('Failed to load inbounds: ' + err.message, 'error');
    });
  };

  function populateInboundSelects(inbounds) {
    var selects = ['xui-inbound-select', 'xui-share-inbound'];
    selects.forEach(function(id) {
      var sel = document.getElementById(id);
      if (!sel) return;
      var currentVal = sel.value;
      sel.innerHTML = '<option value="">— Select an inbound —</option>' +
        inbounds.map(function(ib) {
          return '<option value="' + escapeAttr(ib.tag) + '">' + escapeHTML(ib.tag) + ' (port ' + ib.port + ')</option>';
        }).join('');
      if (currentVal) sel.value = currentVal;
    });
  }

  window.loadClients = function() {
    var tag = val('xui-inbound-select');
    var body = document.getElementById('xui-clients-body');
    if (!body) return;

    if (!tag) {
      body.innerHTML = '<tr><td colspan="4" class="placeholder">Select an inbound to view clients.</td></tr>';
      return;
    }

    // Set hidden field for add-client form
    var hiddenTag = document.getElementById('xui-client-inbound-tag');
    if (hiddenTag) hiddenTag.value = tag;

    fetchJSON('/api/xray/inbound/client?tag=' + encodeURIComponent(tag)).then(function(data) {
      var clients = data.clients || [];
      if (clients.length === 0) {
        body.innerHTML = '<tr><td colspan="4" class="placeholder">No clients configured.</td></tr>';
      } else {
        body.innerHTML = clients.map(function(c) {
          return '<tr>' +
            '<td><code>' + escapeHTML(c.id) + '</code></td>' +
            '<td>' + escapeHTML(c.flow || '—') + '</td>' +
            '<td>' + escapeHTML(c.email || '—') + '</td>' +
            '<td><button type="button" class="small contrast" onclick="removeClient(\'' + escapeAttr(c.id) + '\')">Remove</button>' +
            ' <button type="button" class="small secondary" onclick="loadShareLinkForClient(\'' + escapeAttr(c.id) + '\')">Share Link</button></td>' +
            '</tr>';
        }).join('');
      }

      // Also populate the share-link client dropdown
      updateShareClientDropdown(tag);
    }).catch(function(err) {
      body.innerHTML = '<tr><td colspan="4" class="placeholder error">Failed to load clients: ' + escapeHTML(err.message) + '</td></tr>';
    });
  };

  function updateShareClientDropdown(inboundTag) {
    var sel = document.getElementById('xui-share-client');
    if (!sel) return;

    fetchJSON('/api/xray/inbound/client?tag=' + encodeURIComponent(inboundTag)).then(function(data) {
      var clients = data.clients || [];
      sel.innerHTML = '<option value="">— Select a client —</option>' +
        clients.map(function(c) {
          return '<option value="' + escapeAttr(c.id) + '">' + escapeHTML(c.id.substring(0, 8) + '...') + (c.email ? ' (' + c.email + ')' : '') + '</option>';
        }).join('');
    }).catch(function() {
      sel.innerHTML = '<option value="">— Select a client —</option>';
    });
  }

  window.addClient = function(event) {
    event.preventDefault();
    var inboundTag = val('xui-inbound-select') || document.getElementById('xui-client-inbound-tag').value;

    if (!inboundTag) {
      showToast('Select an inbound first', 'warning');
      return;
    }

    var req = {
      inbound_tag: inboundTag,
      uuid: val('xui-client-uuid') || undefined,
      flow: val('xui-client-flow'),
      email: val('xui-client-email'),
      auto_reload: document.getElementById('xui-client-auto-reload').checked
    };

    fetchJSON('/api/xray/inbound/client', { method: 'POST', body: req }).then(function(data) {
      var msg = 'Client added: ' + data.uuid.substring(0, 8) + '...';
      if (data.reload_status) msg += ' — ' + data.reload_status;
      showToast(msg, 'success');
      // Reset form
      document.getElementById('xui-client-uuid').value = '';
      document.getElementById('xui-client-email').value = '';
      // Reload clients
      loadClients();
    }).catch(function(err) {
      showToast('Failed to add client: ' + err.message, 'error');
    });
  };

  window.removeClient = function(uuid) {
    var tag = val('xui-inbound-select');
    if (!tag) {
      showToast('No inbound selected', 'warning');
      return;
    }
    if (!confirm('Remove client ' + uuid.substring(0, 8) + '... from inbound ' + tag + '?')) return;

    fetchJSON('/api/xray/inbound/client?tag=' + encodeURIComponent(tag) + '&uuid=' + encodeURIComponent(uuid) + '&reload=true', {
      method: 'DELETE'
    }).then(function(data) {
      var msg = 'Client removed';
      if (data.reload_status) msg += ' — ' + data.reload_status;
      showToast(msg, 'success');
      loadClients();
    }).catch(function(err) {
      showToast('Failed to remove client: ' + err.message, 'error');
    });
  };

  // =====================
  // Share Link + QR Code
  // =====================

  window.generateShareLink = function(event) {
    event.preventDefault();
    var inboundTag = val('xui-share-inbound');
    var clientUUID = val('xui-share-client');
    var serverAddress = val('xui-share-address');

    if (!inboundTag) { showToast('Select an inbound', 'warning'); return; }
    if (!clientUUID) { showToast('Select a client', 'warning'); return; }
    if (!serverAddress) { showToast('Server address is required', 'warning'); return; }

    fetchJSON('/api/xray/share', {
      method: 'POST',
      body: {
        inbound_tag: inboundTag,
        client_uuid: clientUUID,
        server_address: serverAddress
      }
    }).then(function(data) {
      var resultDiv = document.getElementById('xui-share-result');
      var linkInput = document.getElementById('xui-share-link');
      var detailsDiv = document.getElementById('xui-share-details');
      if (!resultDiv || !linkInput) return;

      resultDiv.style.display = '';
      linkInput.value = data.link;

      // Show details
      var info = data.info || {};
      var detailsHTML = '<div class="xui-share-info-grid">';
      detailsHTML += '<div><strong>UUID:</strong> <code>' + escapeHTML(info.uuid) + '</code></div>';
      detailsHTML += '<div><strong>Address:</strong> ' + escapeHTML(info.address) + ':' + info.port + '</div>';
      detailsHTML += '<div><strong>Security:</strong> ' + escapeHTML(info.security) + '</div>';
      detailsHTML += '<div><strong>Network:</strong> ' + escapeHTML(info.network) + '</div>';
      if (info.flow) detailsHTML += '<div><strong>Flow:</strong> ' + escapeHTML(info.flow) + '</div>';
      if (info.server_name) detailsHTML += '<div><strong>SNI:</strong> ' + escapeHTML(info.server_name) + '</div>';
      if (info.public_key) detailsHTML += '<div><strong>Public Key:</strong> <code>' + escapeHTML(info.public_key) + '</code></div>';
      if (info.short_id) detailsHTML += '<div><strong>Short ID:</strong> ' + escapeHTML(info.short_id) + '</div>';
      if (info.fingerprint) detailsHTML += '<div><strong>Fingerprint:</strong> ' + escapeHTML(info.fingerprint) + '</div>';
      if (info.remark) detailsHTML += '<div><strong>Remark:</strong> ' + escapeHTML(info.remark) + '</div>';
      detailsHTML += '</div>';
      detailsDiv.innerHTML = detailsHTML;

      // Generate QR code
      var qrContainer = document.getElementById('xui-qr-container');
      if (qrContainer) {
        qrContainer.innerHTML = '';
        var qr = generateQR(data.link);
        if (qr) {
          qrContainer.appendChild(qr);
        } else {
          qrContainer.innerHTML = '<p class="placeholder">QR code generation failed.</p>';
        }
      }

      showToast('Share link generated', 'success');
    }).catch(function(err) {
      showToast('Failed to generate share link: ' + err.message, 'error');
    });
  };

  window.copyShareLink = function() {
    var linkInput = document.getElementById('xui-share-link');
    if (!linkInput) return;
    linkInput.select();
    try {
      document.execCommand('copy');
      showToast('Copied to clipboard', 'success');
    } catch (e) {
      showToast('Copy failed — select and copy manually', 'warning');
    }
  };

  // Pre-fill share link form from client list
  window.loadShareLinkForClient = function(uuid) {
    var inboundSel = document.getElementById('xui-share-inbound');
    var clientSel = document.getElementById('xui-share-client');
    var inboundTag = val('xui-inbound-select');

    if (inboundTag && inboundSel) inboundSel.value = inboundTag;
    if (clientSel) clientSel.value = uuid;

    // Scroll to share section
    var shareSection = document.getElementById('xui-share-section');
    if (shareSection) shareSection.scrollIntoView({ behavior: 'smooth' });
  };

  // =====================
  // QR Code Generator (pure JS, no dependencies)
  // Implements QR Code Model 2, Version 1-10, byte mode, error correction L
  // Based on the QR Code specification (ISO/IEC 18004).
  // Minimal implementation sufficient for share links.
  // =====================

  // QR code is rendered as an SVG <svg> element.
  // We use a compact implementation supporting up to version 10
  // (enough for typical VLESS share links which are <100 chars).

  function generateQR(text) {
    try {
      var qr = QRCode_generate(text);
      if (!qr) return null;
      return renderQRSVG(qr.modules, qr.size);
    } catch (e) {
      console.error('QR generation error:', e);
      return null;
    }
  }

  // --- QR Code core (adapted minimal implementation) ---

  // Galois field tables for Reed-Solomon
  var QR_GF_EXP = new Array(512);
  var QR_GF_LOG = new Array(256);
  (function() {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      QR_GF_EXP[i] = x;
      QR_GF_LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11D;
    }
    QR_GF_EXP[255] = QR_GF_EXP[0];
    for (var i = 256; i < 512; i++) {
      QR_GF_EXP[i] = QR_GF_EXP[i - 255];
    }
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return QR_GF_EXP[QR_GF_LOG[a] + QR_GF_LOG[b]];
  }

  function gfPolyMul(poly1, poly2) {
    var result = new Array(poly1.length + poly2.length - 1).fill(0);
    for (var i = 0; i < poly1.length; i++) {
      for (var j = 0; j < poly2.length; j++) {
        result[i + j] ^= gfMul(poly1[i], poly2[j]);
      }
    }
    return result;
  }

  function gfPolyDiv(dividend, divisor) {
    var result = dividend.slice();
    for (var i = 0; i < result.length - divisor.length + 1; i++) {
      var coef = result[i];
      if (coef === 0) continue;
      for (var j = 1; j < divisor.length; j++) {
        result[i + j] ^= gfMul(divisor[j], coef);
      }
    }
    return result.slice(0, dividend.length);
  }

  function rsGeneratorPoly(degree) {
    var poly = [1];
    for (var i = 0; i < degree; i++) {
      poly = gfPolyMul(poly, [1, QR_GF_EXP[i]]);
    }
    return poly;
  }

  function rsEncode(data, ecLen) {
    var generator = rsGeneratorPoly(ecLen);
    var padded = data.concat(new Array(ecLen).fill(0));
    var remainder = gfPolyDiv(padded, generator);
    return remainder.slice(data.length);
  }

  // QR Code error correction levels: L=1, M=0, Q=3, H=2
  // We use level L (low, 7% recovery) for maximum capacity.

  // Version capacity for byte mode, error level L
  // Format: [totalCodewords, ecCodewordsPerBlock, numBlocksGroup1, dataCodewordsPerBlockGroup1, numBlocksGroup2, dataCodewordsPerBlockGroup2]
  var QR_VERSIONS_L = [
    null, // version 0 (unused)
    [26, 7, 1, 19, 0, 0],     [44, 10, 1, 34, 0, 0],    [70, 15, 1, 55, 0, 0],
    [100, 20, 1, 80, 0, 0],    [134, 26, 1, 108, 0, 0],  [172, 18, 2, 68, 0, 0],
    [196, 20, 2, 78, 0, 0],    [242, 24, 2, 97, 0, 0],   [292, 30, 2, 116, 0, 0],
    [346, 18, 2, 68, 2, 69],   // version 10
  ];

  function selectVersion(dataLen) {
    // byte mode: 4-bit mode indicator + length bits + data
    // version 1-9: 8-bit length, version 10+: 16-bit length
    for (var v = 1; v <= 10; v++) {
      var versionInfo = QR_VERSIONS_L[v];
      var totalDataCodewords = versionInfo[2] * versionInfo[3] + versionInfo[4] * versionInfo[5];
      var lengthBits = v < 10 ? 8 : 16;
      var requiredBits = 4 + lengthBits + dataLen * 8 + 4; // mode + length + data + terminator
      var requiredBytes = Math.ceil(requiredBits / 8);
      if (requiredBytes <= totalDataCodewords) {
        return v;
      }
    }
    return null; // too large
  }

  // QR format info for error level L
  // Format info pattern: data bits (5) + EC bits (10), masked with 0x5412
  var QR_FORMAT_INFO_L = [
    0x77c4, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976,
    0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0,
    0x77c4, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976
  ];

  function getFormatInfoBits(version) {
    // For level L, format info = 0 (data=0 for L), EC bits computed
    // Pre-computed: level L, mask 0 = 0x77c4
    // We use mask pattern 0
    return QR_FORMAT_INFO_L[0]; // level L, mask 0
  }

  // Alignment pattern positions (for versions 2+)
  // Version 1 has no alignment patterns
  var QR_ALIGN_POS = [
    null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
    [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]
  ];

  function QRCode_generate(text) {
    var dataBytes = [];
    // UTF-8 encode
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (c < 0x80) {
        dataBytes.push(c);
      } else if (c < 0x800) {
        dataBytes.push(0xC0 | (c >> 6));
        dataBytes.push(0x80 | (c & 0x3F));
      } else if (c < 0x10000) {
        dataBytes.push(0xE0 | (c >> 12));
        dataBytes.push(0x80 | ((c >> 6) & 0x3F));
        dataBytes.push(0x80 | (c & 0x3F));
      }
    }

    var version = selectVersion(dataBytes.length);
    if (!version) return null;

    var versionInfo = QR_VERSIONS_L[version];
    var totalCodewords = versionInfo[0];
    var ecCodewords = versionInfo[1];
    var numBlocksG1 = versionInfo[2];
    var dataCWperBlockG1 = versionInfo[3];
    var numBlocksG2 = versionInfo[4];
    var dataCWperBlockG2 = versionInfo[5];
    var totalDataCodewords = numBlocksG1 * dataCWperBlockG1 + numBlocksG2 * dataCWperBlockG2;
    var totalBlocks = numBlocksG1 + numBlocksG2;

    // Build bit stream
    var lengthBits = version < 10 ? 8 : 16;
    var bits = [];

    // Mode indicator (byte mode = 0100)
    pushBits(bits, 0b0100, 4);

    // Character count
    pushBits(bits, dataBytes.length, lengthBits);

    // Data
    for (var i = 0; i < dataBytes.length; i++) {
      pushBits(bits, dataBytes[i], 8);
    }

    // Terminator (up to 4 zero bits)
    var totalDataBits = totalDataCodewords * 8;
    while (bits.length < totalDataBits && bits.length < totalDataBits - 4) {
      bits.push(0);
    }
    // Pad remaining bits to byte boundary
    while (bits.length % 8 !== 0) bits.push(0);

    // Pad bytes
    var padBytes = [0xEC, 0x11];
    var byteIdx = 0;
    while (bits.length < totalDataBits) {
      pushBits(bits, padBytes[byteIdx % 2], 8);
      byteIdx++;
    }

    // Convert bits to codewords
    var allCodewords = [];
    for (var i = 0; i < bits.length; i += 8) {
      var byte = 0;
      for (var b = 0; b < 8; b++) {
        byte = (byte << 1) | bits[i + b];
      }
      allCodewords.push(byte);
    }

    // Split into blocks and add EC
    var dataBlocks = [];
    var ecBlocks = [];
    var idx = 0;

    for (var i = 0; i < numBlocksG1; i++) {
      var block = allCodewords.slice(idx, idx + dataCWperBlockG1);
      idx += dataCWperBlockG1;
      dataBlocks.push(block);
      ecBlocks.push(rsEncode(block, ecCodewords));
    }
    for (var i = 0; i < numBlocksG2; i++) {
      var block = allCodewords.slice(idx, idx + dataCWperBlockG2);
      idx += dataCWperBlockG2;
      dataBlocks.push(block);
      ecBlocks.push(rsEncode(block, ecCodewords));
    }

    // Interleave
    var finalCodewords = [];
    var maxDataLen = Math.max(dataCWperBlockG1, dataCWperBlockG2);
    for (var i = 0; i < maxDataLen; i++) {
      for (var b = 0; b < totalBlocks; b++) {
        if (i < dataBlocks[b].length) {
          finalCodewords.push(dataBlocks[b][i]);
        }
      }
    }
    for (var i = 0; i < ecCodewords; i++) {
      for (var b = 0; b < totalBlocks; b++) {
        finalCodewords.push(ecBlocks[b][i]);
      }
    }

    // Build module matrix
    var size = 17 + 4 * version;
    var modules = createMatrix(size, false);
    var reserved = createMatrix(size, false); // tracks function pattern positions

    // Place function patterns
    placeFinderPatterns(modules, reserved, size);
    placeAlignmentPatterns(modules, reserved, version, size);
    placeTimingPatterns(modules, reserved, size);
    reserveFormatAreas(reserved, size);

    // Place data bits
    placeDataBits(modules, reserved, finalCodewords, size);

    // Apply mask (pattern 0: (row + col) % 2 == 0)
    applyMask(modules, reserved, size, 0);

    // Place format info
    placeFormatInfo(modules, size, getFormatInfoBits(version));

    // Place version info (version 7+)
    if (version >= 7) {
      placeVersionInfo(modules, size, version);
    }

    return { modules: modules, size: size };
  }

  function createMatrix(size, val) {
    var m = [];
    for (var i = 0; i < size; i++) {
      m.push(new Array(size).fill(val));
    }
    return m;
  }

  function pushBits(arr, value, length) {
    for (var i = length - 1; i >= 0; i--) {
      arr.push((value >> i) & 1);
    }
  }

  function placeFinderPatterns(modules, reserved, size) {
    var positions = [[0, 0], [size - 7, 0], [0, size - 7]];
    positions.forEach(function(pos) {
      var r = pos[1], c = pos[0];
      for (var dr = 0; dr < 7; dr++) {
        for (var dc = 0; dc < 7; dc++) {
          reserved[r + dr][c + dc] = true;
          var isBorder = (dr === 0 || dr === 6 || dc === 0 || dc === 6);
          var isInner = (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4);
          modules[r + dr][c + dc] = isBorder || isInner;
        }
      }
    });
  }

  function placeAlignmentPatterns(modules, reserved, version, size) {
    var positions = QR_ALIGN_POS[version];
    if (!positions) return;
    for (var i = 0; i < positions.length; i++) {
      for (var j = 0; j < positions.length; j++) {
        var r = positions[i];
        var c = positions[j];
        // Skip if in finder pattern area
        if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue;
        for (var dr = -2; dr <= 2; dr++) {
          for (var dc = -2; dc <= 2; dc++) {
            reserved[r + dr][c + dc] = true;
            var dist = Math.abs(dr) + Math.abs(dc);
            modules[r + dr][c + dc] = (dist === 1) ? false : (dist !== 2);
          }
        }
      }
    }
  }

  function placeTimingPatterns(modules, reserved, size) {
    for (var i = 8; i < size - 8; i++) {
      if (!reserved[6][i]) {
        modules[6][i] = (i % 2 === 0);
        reserved[6][i] = true;
      }
      if (!reserved[i][6]) {
        modules[i][6] = (i % 2 === 0);
        reserved[i][6] = true;
      }
    }
  }

  function reserveFormatAreas(reserved, size) {
    // Reserve around top-left finder
    for (var i = 0; i < 9; i++) {
      reserved[8][i] = true;
      reserved[i][8] = true;
    }
    // Top-right
    for (var i = 0; i < 8; i++) {
      reserved[8][size - 1 - i] = true;
    }
    // Bottom-left
    for (var i = 0; i < 8; i++) {
      reserved[size - 1 - i][8] = true;
    }
    // Always set the dark module
    reserved[size - 8][8] = true;
  }

  function placeDataBits(modules, reserved, codewords, size) {
    var bitIdx = 0;
    var totalBits = codewords.length * 8;
    var upward = true;
    var col = size - 1;

    while (col > 0) {
      if (col === 6) col--; // skip timing column
      for (var i = 0; i < size; i++) {
        var row = upward ? (size - 1 - i) : i;
        for (var c = 0; c < 2; c++) {
          var actualCol = col - c;
          if (!reserved[row][actualCol] && bitIdx < totalBits) {
            var byteIdx = Math.floor(bitIdx / 8);
            var bitInByte = 7 - (bitIdx % 8);
            var bit = (codewords[byteIdx] >> bitInByte) & 1;
            modules[row][actualCol] = bit === 1;
            bitIdx++;
          }
        }
      }
      col -= 2;
      upward = !upward;
    }
  }

  function applyMask(modules, reserved, size, patternId) {
    for (var r = 0; r < size; r++) {
      for (var c = 0; c < size; c++) {
        if (reserved[r][c]) continue;
        var mask = false;
        if (patternId === 0) mask = ((r + c) % 2 === 0);
        if (mask) modules[r][c] = !modules[r][c];
      }
    }
  }

  function placeFormatInfo(modules, size, formatBits) {
    // Place in 15-bit format info areas
    for (var i = 0; i < 15; i++) {
      var bit = ((formatBits >> i) & 1) === 1;
      // Around top-left
      if (i < 6) {
        modules[8][i] = bit;
        modules[i][8] = bit;
      } else if (i < 8) {
        modules[8][i + 1] = bit;
        modules[i + 1][8] = bit;
      } else if (i < 9) {
        modules[7][8] = bit;
        modules[8][8] = bit;
        modules[8][7] = bit;
      } else {
        modules[14 - i][8] = bit;
        modules[8][size - 15 + i] = bit;
      }
    }
    // Also set dark module
    modules[size - 8][8] = true;
  }

  function placeVersionInfo(modules, size, version) {
    // 18-bit version info
    var versionBits = 0;
    var data = version << 12;
    var remainder = data;
    for (var i = 0; i < 12; i++) {
      if ((remainder & (1 << 11)) !== 0) {
        remainder ^= 0x1F25;
      }
      remainder <<= 1;
    }
    versionBits = (data | (remainder >> 12)) & 0x1FFFF;

    for (var i = 0; i < 18; i++) {
      var bit = ((versionBits >> i) & 1) === 1;
      var r = Math.floor(i / 3);
      var c = i % 3;
      // Top-right version area
      modules[r][size - 11 + c] = bit;
      // Bottom-left version area
      modules[size - 11 + c][r] = bit;
    }
  }

  function renderQRSVG(modules, size) {
    var cellSize = 4; // px per module
    var margin = 4; // quiet zone
    var totalSize = (size + margin * 2) * cellSize;
    var dark = '#000';
    var light = '#fff';

    var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + totalSize + '" height="' + totalSize + '" viewBox="0 0 ' + totalSize + ' ' + totalSize + '">';
    svg += '<rect width="' + totalSize + '" height="' + totalSize + '" fill="' + light + '"/>';

    for (var r = 0; r < size; r++) {
      for (var c = 0; c < size; c++) {
        if (modules[r][c]) {
          var x = (c + margin) * cellSize;
          var y = (r + margin) * cellSize;
          svg += '<rect x="' + x + '" y="' + y + '" width="' + cellSize + '" height="' + cellSize + '" fill="' + dark + '"/>';
        }
      }
    }

    svg += '</svg>';
    var div = document.createElement('div');
    div.innerHTML = svg;
    return div.firstChild;
  }

  // =====================
  // Init
  // =====================

  document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('xui-stats-section')) {
      loadInboundOptions();
    }
  });

})();
