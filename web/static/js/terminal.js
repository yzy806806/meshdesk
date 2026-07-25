// MeshDesk Terminal — xterm.js + WebSocket bridge
// Enhanced with design-system-matched theme, connection spinner,
// disconnected overlay, and focus-state tracking.
(function() {
  'use strict';

  const container = document.getElementById('terminal-container');
  if (!container) return;

  const peerID = container.getAttribute('data-peer');
  if (!peerID) {
    console.error('[Terminal] No peer ID specified');
    return;
  }

  // Design-system-matched terminal theme (dark, consistent with app.css)
  var termTheme = {
    background: '#0d1117',
    foreground: '#e6edf3',
    cursor: '#58a6ff',
    cursorAccent: '#0d1117',
    selectionBackground: 'rgba(88, 166, 255, 0.25)',
    black: '#484f58',
    red: '#ff7b72',
    green: '#3fb950',
    yellow: '#d29922',
    blue: '#58a6ff',
    magenta: '#bc8cff',
    cyan: '#39c5cf',
    white: '#b1bac4',
    brightBlack: '#6e7681',
    brightRed: '#ffa198',
    brightGreen: '#56d364',
    brightYellow: '#e3b341',
    brightBlue: '#79b8ff',
    brightMagenta: '#d2a8ff',
    brightCyan: '#56d4dd',
    brightWhite: '#f0f6fc'
  };

  // Create terminal with design-system-matched settings
  var term = new Terminal({
    cols: 80,
    rows: 24,
    cursorBlink: true,
    fontSize: 14,
    fontFamily: '"SF Mono", "Fira Code", "JetBrains Mono", Menlo, Consolas, monospace',
    theme: termTheme,
    allowProposedApi: true,
    scrollback: 5000,
    tabStopWidth: 8
  });

  // Load addons
  var fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  var webLinksAddon = new WebLinksAddon.WebLinksAddon();
  term.loadAddon(webLinksAddon);
  var searchAddon = new SearchAddon.SearchAddon();
  term.loadAddon(searchAddon);

  term.open(container);
  fitAddon.fit();

  // State
  var ws = null;
  var connected = false;
  var reconnectAttempts = 0;
  var maxReconnectAttempts = 5;
  var reconnectDelay = 2000;
  var reconnectTimer = null;
  var statusEl = document.getElementById('term-status');
  var viewEl = container.closest('.terminal-view');
  var overlayEl = null;

  // Create disconnected overlay element
  function createOverlay(message, showReconnect) {
    removeOverlay();
    overlayEl = document.createElement('div');
    overlayEl.className = 'term-disconnected-overlay';

    var content = document.createElement('div');
    content.className = 'term-overlay-content';

    var p = document.createElement('p');
    p.textContent = message;
    content.appendChild(p);

    if (showReconnect) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = '↻ Reconnect';
      btn.addEventListener('click', function() {
        removeOverlay();
        term.clear();
        connect();
      });
      content.appendChild(btn);
    }

    overlayEl.appendChild(content);
    container.parentElement.appendChild(overlayEl);
  }

  function removeOverlay() {
    if (overlayEl && overlayEl.parentNode) {
      overlayEl.parentNode.removeChild(overlayEl);
      overlayEl = null;
    }
  }

  function setStatus(state, msg) {
    if (!statusEl) return;
    statusEl.className = 'term-status ' + state;
    // Build inner HTML with spinner for connecting state
    if (state === 'connecting') {
      var spinner = document.createElement('span');
      spinner.className = 'term-spinner';
      statusEl.innerHTML = '';
      statusEl.appendChild(spinner);
      statusEl.appendChild(document.createTextNode(' ' + (msg || 'Connecting...')));
    } else {
      statusEl.textContent = '\u25cf ' + (msg || state.charAt(0).toUpperCase() + state.slice(1));
    }
  }

  function getWsURL() {
    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    return proto + '//' + location.host + '/ws/terminal?node=' + encodeURIComponent(peerID) +
      '&cols=' + term.cols + '&rows=' + term.rows;
  }

  function connect() {
    setStatus('connecting', 'Connecting...');
    removeOverlay();
    if (ws) {
      try { ws.close(); } catch(e) {}
    }

    ws = new WebSocket(getWsURL());

    ws.onopen = function() {
      connected = true;
      reconnectAttempts = 0;
      reconnectDelay = 2000;
      setStatus('connected');
      term.focus();
    };

    ws.onmessage = function(e) {
      var msg;
      try {
        msg = JSON.parse(e.data);
      } catch(err) {
        return;
      }

      switch (msg.type) {
        case 'output':
          try {
            var data = atob(msg.data);
            term.write(data);
          } catch(err) {
            console.error('[Terminal] decode output error:', err);
          }
          break;
        case 'connected':
          if (msg.data) {
            try {
              var cd = JSON.parse(msg.data);
              if (cd.cols && cd.rows) {
                term.resize(cd.cols, cd.rows);
                fitAddon.fit();
              }
            } catch(err) {}
          }
          break;
        case 'status':
          try {
            var sd = JSON.parse(msg.data);
            if (sd.status === 'disconnected' || sd.status === 'error') {
              setStatus(sd.status, sd.message || sd.status);
              connected = false;
              if (sd.status === 'error') {
                createOverlay(sd.message || 'Connection error', true);
              }
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
          createOverlay(msg.data || 'Terminal error', true);
          break;
        case 'clipboard_out':
          try {
            var clipData = atob(msg.data);
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

      // Auto-reconnect with backoff
      if (reconnectAttempts < maxReconnectAttempts) {
        reconnectAttempts++;
        setStatus('connecting', 'Reconnecting (' + reconnectAttempts + '/' + maxReconnectAttempts + ')...');
        reconnectTimer = setTimeout(function() {
          connect();
        }, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 1.5, 10000);
      } else {
        createOverlay('Connection lost. Max reconnection attempts reached.', true);
      }
    };

    // Send terminal input
    term.onData(function(data) {
      if (connected && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data: btoa(data) }));
      }
    });

    // Send resize on window resize
    var resizeTimer = null;
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

  // Track focus state for visual indicator
  container.addEventListener('focusin', function() {
    if (viewEl) viewEl.classList.add('is-focused');
  });
  container.addEventListener('focusout', function() {
    if (viewEl) viewEl.classList.remove('is-focused');
  });
  container.addEventListener('click', function() {
    term.focus();
  });

  // Paste button
  var pasteBtn = document.getElementById('term-paste');
  if (pasteBtn) {
    pasteBtn.addEventListener('click', async function() {
      try {
        var text = await navigator.clipboard.readText();
        if (text && connected && ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'clipboard', data: btoa(text) }));
        }
      } catch(err) {
        var fallbackText = prompt('Paste text:');
        if (fallbackText && connected && ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'clipboard', data: btoa(fallbackText) }));
        }
      }
    });
  }

  // Fit button
  var fitBtn = document.getElementById('term-fit');
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
  var clearBtn = document.getElementById('term-clear');
  if (clearBtn) {
    clearBtn.addEventListener('click', function() {
      term.clear();
    });
  }

  // Reconnect button
  var reconnectBtn = document.getElementById('term-reconnect');
  if (reconnectBtn) {
    reconnectBtn.addEventListener('click', function() {
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      reconnectAttempts = 0;
      reconnectDelay = 2000;
      removeOverlay();
      term.clear();
      connect();
    });
  }

  // Keyboard shortcuts
  container.addEventListener('keydown', function(e) {
    // Ctrl+Shift+V to paste
    if (e.ctrlKey && e.shiftKey && (e.key === 'V' || e.key === 'v')) {
      e.preventDefault();
      if (pasteBtn) pasteBtn.click();
      return;
    }
    // Ctrl+Shift+F to fit
    if (e.ctrlKey && e.shiftKey && (e.key === 'F' || e.key === 'f')) {
      e.preventDefault();
      if (fitBtn) fitBtn.click();
      return;
    }
    // Ctrl+L to clear
    if (e.ctrlKey && (e.key === 'L' || e.key === 'l')) {
      e.preventDefault();
      term.clear();
      return;
    }
    // Ctrl+Shift+R to reconnect
    if (e.ctrlKey && e.shiftKey && (e.key === 'R' || e.key === 'r')) {
      e.preventDefault();
      if (reconnectBtn) reconnectBtn.click();
      return;
    }
  });

  // Cleanup on page unload
  window.addEventListener('beforeunload', function() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
    }
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
