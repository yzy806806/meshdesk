# MeshDesk Frontend Documentation

**Last updated:** 2026-07-25
**Applies to:** MeshDesk web UI served by `--web` flag

## Overview

The MeshDesk frontend combines **server-rendered Go templates**, **htmx** for partial page updates, **Server-Sent Events (SSE)** for live dashboard metrics, and **xterm.js + WebSocket** for the web terminal. All assets are compiled into the binary via `go:embed` — zero external HTTP requests at runtime.

### Key numbers

| Metric | Value |
|--------|-------|
| Templates | 8 (layout, dashboard, node_detail, terminal, files, services, peers, login) |
| CSS files | 4 (pico.min.css, xterm.css, app.css, terminal.css) |
| Design tokens | 65 CSS custom properties in app.css |
| app.css size | 1,244 lines |
| terminal.css size | 113 lines |
| JS files | 7 (htmx.min.js, xterm.js + 3 addons, terminal.js, dashboard.js) |
| HTTP routes | 19 |

## Architecture

```
Browser                          MeshDesk Binary
┌─────────────┐                  ┌─────────────────────────────┐
│ HTML page   │─── HTTP GET ───▶│ Go html/template             │
│ (initial)   │                  │ (server-rendered,           │
│             │                  │  embedded via go:embed)     │
│             │                  │                             │
│ htmx        │─── htmx req ───▶│ Partial re-render            │
│ (updates)   │                  │ (HTML fragments)            │
│             │                  │                             │
│ EventSource │─── SSE ────────▶│ /api/events                  │
│ (metrics)   │                  │ (1s push of JSON metrics)   │
│             │                  │                             │
│ xterm.js    │─── WebSocket ──▶│ /ws/terminal                 │
│ (terminal)  │                  │ (xterm ↔ PTY bridge)        │
└─────────────┘                  └─────────────────────────────┘
```

### Decision: Zero-build pipeline

There is **no npm, no webpack, no node_modules**. All CSS, JS, and templates are embedded in the binary via Go's `go:embed`. This keeps deployment simple: one statically-linked binary with no runtime dependencies beyond the Linux kernel.

## File Structure

```
web/
├── embed.go                          # go:embed directives (no Go logic)
├── static/
│   ├── css/
│   │   ├── pico.min.css              # Base CSS framework (dark theme, ~25KB)
│   │   ├── xterm.css                 # xterm.js vendor styles
│   │   ├── app.css                   # MeshDesk design system (1,244 lines)
│   │   └── terminal.css              # Terminal-specific styles (113 lines)
│   ├── js/
│   │   ├── htmx.min.js               # htmx for partial updates (~14KB)
│   │   ├── xterm.js                  # xterm.js terminal emulator (~500KB)
│   │   ├── xterm-addon-fit.js        # Auto-fit to container
│   │   ├── xterm-addon-search.js     # In-terminal search
│   │   ├── xterm-addon-web-links.js  # Clickable URLs
│   │   ├── terminal.js               # WebSocket bridge + UX logic (364 lines)
│   │   └── dashboard.js              # SSE live metrics handler (120 lines)
│   └── img/                          # Static images (reserved)
└── templates/
    ├── layout.html                   # Base template: nav, head, skip-link
    ├── dashboard.html                # Node grid + SSE partial
    ├── node_detail.html              # Single-node metrics detail
    ├── terminal.html                 # xterm.js shell
    ├── files.html                    # File upload + list
    ├── services.html                 # Service start/stop/restart
    ├── peers.html                    # Peer table + capability display
    └── login.html                    # Authentication form
```

The Go server code lives in `internal/web/` (server.go, handlers.go). The `web/` directory at the project root contains zero Go logic — only assets consumed via `go:embed`.

## Design System

The design system is defined in `web/static/css/app.css` and documented fully in `docs/DESIGN.md`. Here are the essentials:

### Color Palette (GitHub-inspired dark theme)

| Token | Value | Use |
|-------|-------|-----|
| `--md-primary` | `#58a6ff` | Links, buttons, focus rings |
| `--md-success` | `#3fb950` | Healthy status, active state |
| `--md-warning` | `#d29922` | Elevated metrics |
| `--md-danger` | `#f85149` | Errors, critical status |
| `--md-bg` | `#0d1117` | Page background |
| `--md-surface` | `#161b22` | Card backgrounds |
| `--md-border` | `#30363d` | Borders |

### Typography Scale

| Token | Size | Element |
|-------|------|---------|
| `--md-text-xs` | 0.70rem | Labels, badges, table headers |
| `--md-text-sm` | 0.80rem | Body text, form labels |
| `--md-text-base` | 0.90rem | Default content |
| `--md-text-lg` | 1.10rem | Card headings (h4) |
| `--md-text-xl` | 1.30rem | Section headings (h3) |
| `--md-text-2xl` | 1.60rem | Page titles (h2) |
| `--md-text-3xl` | 2.00rem | Big metric numbers |

### Spacing (4px base)

`--md-space-1` (4px) through `--md-space-16` (64px) in 9 stops. Standard card padding is `--md-space-5` (20px).

### When to use which token

- **Never** hardcode colors, spacing, or font sizes in templates — reference tokens
- Use `--md-primary-muted` (12% opacity) for subtle primary backgrounds
- Use `--md-surface-raised` (`#1c2129`) for hover states on dark surfaces
- All metric bars use color classes: green ≤74%, yellow 75–89%, red ≥90%

## Templates

Every template wraps its content in `{{define "content"}}` and is rendered inside `layout.html`.

### layout.html

The base template provides:
- `<head>` with charset, viewport, theme-color, and three CSS includes (pico, xterm, app)
- Skip-to-content link for accessibility
- Top navigation bar: Dashboard, Nodes, Peers, Files, Services + logout
- `{{block "head"}}` and `{{block "scripts"}}` slots for page-specific resources
- `{{block "content"}}` slot for page body
- Current page tracking via `ActivePage` + `aria-current`

### Template rendering

The Go server (`internal/web/server.go`) uses a per-page template clone strategy:
1. Parse `layout.html` once
2. For each page template, clone the layout and parse the page into it
3. On request: execute `layout` template with page data

This avoids the "last template wins" problem with `{{define "content"}}` blocks.

```go
// Server-side:
s.renderPage(w, "dashboard.html", data)

// Template hierarchy:
// layout.html → {{block "content"}} → dashboard.html → {{define "content"}}
```

## Page Data

All templates receive `PageData` as their base:

```go
type PageData struct {
    Title      string  // browser tab title
    ActivePage string  // highlights current nav item
    Username   string  // logged-in user
}
```

Each page adds its own data struct with page-specific fields.

## Routes

### Page routes (auth required)

| Route | Template | Description |
|-------|----------|-------------|
| `GET /` | dashboard.html | Node grid with live SSE metrics |
| `GET /nodes` | dashboard.html (shared) | Full node list |
| `GET /nodes/<id>` | node_detail.html | Single node metrics |
| `GET /terminal?node=<id>` | terminal.html | Web terminal to node |
| `GET /files` | files.html | File upload + transfer |
| `GET /services` | services.html | Service management |
| `GET /peers` | peers.html | Peer table |
| `GET /login` | login.html | Login form |
| `GET /logout` | — | Clear session, redirect |

### API routes (auth required, return JSON or HTML fragments)

| Route | Returns | Used by |
|-------|---------|---------|
| `GET /api/events` | SSE stream | dashboard.js |
| `GET /api/dashboard/partial` | HTML fragment | htmx auto-refresh |
| `POST /api/files/upload` | HTML | files.html form |
| `GET /api/files/list` | HTML table | files.html |
| `GET /api/services/list` | HTML table | services.html |
| `POST /api/services/start` | text | services.html buttons |
| `POST /api/services/stop` | text | services.html buttons |
| `POST /api/services/restart` | text | services.html buttons |

### WebSocket route

| Route | Description |
|-------|-------------|
| `GET /ws/terminal` | xterm.js ↔ PTY bridge (auth via session cookie) |

### Static assets (no auth)

| Prefix | Source |
|--------|--------|
| `/static/` | `web/static/` via `http.FS(webembed.Static())` |

## Authentication

- **Session-based**: cookie `meshdesk_session` with 24-hour expiry, HttpOnly, SameSite=Strict
- **Credentials**: bcrypt-hashed passwords in `config.yaml` → `auth.web_users`
- **First-run mode**: if no web users are configured, all routes are open (no login required)
- **Auth flow**: `authMiddleware` redirects unauthenticated requests to `/login`; `requireAuth` returns `HX-Redirect` header for htmx requests

## Live Metrics (SSE)

The dashboard uses a **dual-refresh** strategy:

1. **SSE stream** (`/api/events`): pushes JSON metric snapshots every 1 second
2. **htmx partial** (`/api/dashboard/partial`): triggered by `sse:metrics` event, replaces the node grid HTML

```javascript
// dashboard.html:
hx-get="/api/dashboard/partial"
hx-trigger="sse:metrics"
hx-swap="innerHTML"

// dashboard.js:
eventSource.addEventListener('metrics', function(e) {
    updateNodeCards(JSON.parse(e.data));  // instant bar animation
});
```

The SSE hub (`SSEHub` in server.go) maintains connection channels. Broadcasts are non-blocking — if a client's buffer is full, the event is dropped (no backpressure).

## Web Terminal (xterm.js)

The terminal implementation lives across three files:

| File | Role |
|------|------|
| `terminal.html` | Toolbar (status, controls), container div with `data-peer` attribute |
| `terminal.js` | xterm.js init, WebSocket connect/reconnect, clipboard, resize, keyboard shortcuts |
| `terminal.css` | Container styling, scrollbars, spinner, disconnected overlay, focus ring |

### Features

- **Auto-reconnect**: 5-attempt exponential backoff (2s to 10s) when WebSocket drops
- **Disconnected overlay**: blurred overlay with Reconnect button, not a silent frozen terminal
- **Connection status**: colored dot (green=connected, yellow=connecting, gray=disconnected, red=error)
- **Clipboard**: paste button + keyboard shortcut (Ctrl+Shift+V)
- **Resize**: Fit-to-window (Ctrl+Shift+F) propagates SIGWINCH to remote PTY
- **Clear**: Clear screen (Ctrl+L)
- **xterm.js addons**: fit, web-links (clickable URLs), search (Ctrl+Shift+F)
- **Design-matched theme**: xterm colors derived from the same design tokens as app.css

### Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+Shift+V | Paste clipboard |
| Ctrl+Shift+F | Fit terminal to window |
| Ctrl+L | Clear screen |
| Ctrl+Shift+R | Reconnect |

## Accessibility

Implemented across all templates:

- **Skip link**: `<a href="#main-content" class="skip-link">Skip to content</a>` — first focusable element
- **ARIA labels**: navigation (`role="navigation"`, `aria-label`), terminal controls, regions, live regions
- **Focus-visible**: keyboard focus indicators on all interactive elements
- **Reduced motion**: `@media (prefers-reduced-motion: reduce)` disables animations and transitions
- **Semantic HTML**: proper heading hierarchy (h2 → h3 → h4), `<main>`, `<nav>`, `<article>`, `<header>`/`<footer>` in cards
- **Color independence**: status is conveyed by text labels (not color alone); metric bars have `role="progressbar"` with `aria-valuenow`

## Responsive Design

Three breakpoints:

| Breakpoint | Behavior |
|------------|----------|
| **≥1025px** | Full layout: multi-column grid, full nav bar, side-by-side forms |
| **769–1024px** | Tablet: nav wraps, 2-column card grid, stacked forms |
| **≤768px** | Mobile: single-column cards, stacked metrics, horizontal-scroll tables, compact nav |

Key responsive CSS classes:
- `.grid`: auto-fill grid with 320px minimum column width
- `.table-wrap`: horizontal scroll container for tables
- `.form-inline`: wraps to stacked on mobile via flex-wrap

## Animations

| Animation | Trigger | Duration | Effect |
|-----------|---------|----------|--------|
| Bar fill | SSE metric update | 600ms | Spring overshoot (cubic-bezier) on width change |
| Metric flash | SSE metric change | 600ms | Blue highlight flash |
| Card hover | Mouse enter | 200ms | Border highlight + shadow deepen |
| Card mount | First render | 350ms | Fade up 4px |
| Button down | Active state | Instant | Scale to 0.98 |
| Toast appearance | Service action | 300ms | Fade in → auto-dismiss (4s) |
| Focus ring | Focus | 120ms | 3px primary-muted glow |
| Spinner | Connecting | Continuous | Rotating border animation |
| Reduced motion | `prefers-reduced-motion` | — | All animations/transitions disabled |

## Empty States

Every data-driven view has an empty state:

| View | Empty state text | Styling |
|------|-----------------|---------|
| Dashboard | "No nodes reporting metrics yet. Check back shortly." | Centered italic, dashed border |
| File list | "No uploaded files." | Centered italic |
| Service list | "No services found." | Centered italic |
| Tables (empty) | "(placeholder text)" | No border, centered |

## Toast Notifications

The services page uses a lightweight inline toast system (no library dependency):

```javascript
showToast(message, type)  // type: 'success', 'error', 'warning', 'info'
```

Toasts appear at the top-right, auto-dismiss after 4 seconds, and stack vertically. The toast container is created on first use.

## How to Add a New Page

1. **Create template** in `web/templates/newpage.html`:
   ```html
   {{define "head"}}
   <!-- optional: page-specific CSS/JS -->
   {{end}}
   {{define "content"}}
   <h2>Page Title</h2>
   <!-- your content here -->
   {{end}}
   {{define "scripts"}}
   <!-- optional: page-specific scripts -->
   {{end}}
   ```

2. **Register in server.go**: add to `pageNames` slice and `registerRoutes` method

3. **Register route** in `registerRoutes()`:
   ```go
   mux.HandleFunc("/newpage", s.requireAuth(s.handleNewPage))
   ```

4. **Add handler** in `handlers.go`:
   ```go
   func (s *Server) handleNewPage(w http.ResponseWriter, r *http.Request) {
       data := struct {
           PageData
           // page-specific fields
       }{
           PageData: PageData{Title: "New Page", ActivePage: "newpage"},
       }
       s.renderPage(w, "newpage.html", data)
   }
   ```

5. **Add nav link** in `layout.html`

6. **Style with existing tokens** — never add inline styles or new color values. Use `app.css` classes.

## Constraints

- **No JS build pipeline.** All JavaScript is served as static files. Keep scripts self-contained with no module imports.
- **No external CDN.** Every asset is embedded in the binary. If you need a library, vendor it into `web/static/js/` or `web/static/css/`.
- **Design tokens only.** Colors, spacing, typography must reference CSS custom properties. No one-off values.
- **Test at breakpoints.** Verify new pages at 768px and 480px.
- **Accessibility required.** Every interactive element needs a label, every dynamic region needs `aria-live`, every data display needs a non-visual fallback.

## Related Documents

- `docs/DESIGN.md` — Full design system specification (all tokens, component patterns, animation principles)
- `docs/ARCHITECTURE.md` (Decision D) — Why Go templates + htmx + embedded assets
- `README.md` — User-facing feature overview and configuration
