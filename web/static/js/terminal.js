// MeshDesk Terminal — xterm.js + WebSocket bridge
(function() {
  'use strict';

  const container = document.getElementById('terminal-container');
  if (!container) return;

  const peerID = container.getAttribute('data-peer');
  if (!peerID) {
    console.error('[Terminal] No peer ID specified');
    return;
  }

  // Create terminal
  const term = new Terminal({
    cols: 80,
    rows: 24,
    cursorBlink: true,
    fontSize: 14,
    fontFamily: 'Menlo, Monaco, "Courier New", monospace',
    theme: {
      background: '#000000',
      foreground: '#e0e0e0',
      cursor: '#ffffff'
    }
  });

  // Load addons
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  const webLinksAddon = new WebLinksAddon.WebLinksAddon();
  term.loadAddon(webLinksAddon);
  const searchAddon = new SearchAddon.SearchAddon();
  term.loadAddon(searchAddon);

  term.open(container);
  fitAddon.fit();

  // State
  let ws = null;
  let connected = false;
  const statusEl = document.getElementById('term-status');

  function setStatus(state, msg) {
    if (!statusEl) return;
    statusEl.className = 'term-status ' + state;
    statusEl.textContent = '● ' + (msg || state.charAt(0).toUpperCase() + state.slice(1));
  }

  function getWsURL() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return proto + '//' + location.host + '/ws/terminal?node=' + encodeURIComponent(peerID) +
      '&cols=' + term.cols + '&rows=' + term.rows;
  }

  function connect() {
    setStatus('connecting', 'Connecting…');
    if (ws) {
      try { ws.close(); } catch(e) {}
    }

    ws = new WebSocket(getWsURL());

    ws.onopen = function() {
      connected = true;
      setStatus('connected');
      term.focus();
    };

    ws.onmessage = function(e) {
      let msg;
      try {
        msg = JSON.parse(e.data);
      } catch(err) {
        return;
      }

      switch (msg.type) {
        case 'output':
          try {
            const data = atob(msg.data);
            term.write(data);
          } catch(err) {
            console.error('[Terminal] decode output error:', err);
          }
          break;
        case 'connected':
          // Session established, fit terminal
          if (msg.data) {
            try {
              const cd = JSON.parse(msg.data);
              if (cd.cols && cd.rows) {
                term.resize(cd.cols, cd.rows);
                fitAddon.fit();
              }
            } catch(err) {}
          }
          break;
        case 'status':
          try {
            const sd = JSON.parse(msg.data);
            if (sd.status === 'disconnected' || sd.status === 'error') {
              setStatus(sd.status, sd.message || sd.status);
              connected = false;
            } else {
              setStatus(sd.status, sd.message);
            }
          } catch(err) {
            setStatus('connected', msg.data);
          }
          break;
        case 'error':
          setStatus('error', msg.data || 'Error');
          connected = false;
          break;
        case 'clipboard_out':
          try {
            const clipData = atob(msg.data);
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(clipData).catch(function(){});
            }
          } catch(err) {}
          break;
      }
    };

    ws.onerror = function() {
      setStatus('error', 'WebSocket error');
    };

    ws.onclose = function() {
      connected = false;
      setStatus('disconnected');
    };

    // Send terminal input
    term.onData(function(data) {
      if (connected && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data: btoa(data) }));
      }
    });

    // Send resize on window resize
    let resizeTimer = null;
    window.addEventListener('resize', function() {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function() {
        fitAddon.fit();
        if (connected && ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: 'resize',
            data: JSON.stringify({ cols: term.cols, rows: term.rows })
          }));
        }
      }, 100);
    });
  }

  // Paste button
  const pasteBtn = document.getElementById('term-paste');
  if (pasteBtn) {
    pasteBtn.addEventListener('click', async function() {
      try {
        const text = await navigator.clipboard.readText();
        if (text && connected && ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'clipboard', data: btoa(text) }));
        }
      } catch(err) {
        // Fallback: prompt the user
        const text = prompt('Paste text:');
        if (text && connected && ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'clipboard', data: btoa(text) }));
        }
      }
    });
  }

  // Fit button
  const fitBtn = document.getElementById('term-fit');
  if (fitBtn) {
    fitBtn.addEventListener('click', function() {
      fitAddon.fit();
      if (connected && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          type: 'resize',
          data: JSON.stringify({ cols: term.cols, rows: term.rows })
        }));
      }
    });
  }

  // Clear button
  const clearBtn = document.getElementById('term-clear');
  if (clearBtn) {
    clearBtn.addEventListener('click', function() {
      term.clear();
    });
  }

  // Reconnect button
  const reconnectBtn = document.getElementById('term-reconnect');
  if (reconnectBtn) {
    reconnectBtn.addEventListener('click', function() {
      term.clear();
      connect();
    });
  }

  // Cleanup on page unload
  window.addEventListener('beforeunload', function() {
    if (ws) {
      try {
        ws.send(JSON.stringify({ type: 'close' }));
        ws.close();
      } catch(e) {}
    }
  });

  // Start connection
  connect();
})();
