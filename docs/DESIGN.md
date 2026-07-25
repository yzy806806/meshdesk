# MeshDesk Design System

A dark-themed design system for the MeshDesk web frontend, built on Pico.css foundations. This document defines the visual language — color, typography, spacing, and component patterns — and serves as a reference for contributors and future iterations.

## Philosophy

MeshDesk is a server management dashboard. The UI prioritizes:

- **Clarity** — system metrics are immediately scannable; status is unambiguous.
- **Depth** — a dark palette with layered surfaces creates visual hierarchy without bright distractions.
- **Restraint** — the UI gets out of the way. Animations are subtle. Colors have purpose.
- **Consistency** — every component draws from the same token set; no one-off values.

## Design Tokens

All visual properties are defined as CSS custom properties in `web/static/css/app.css`. Tokens are the single source of truth — templates should never hardcode colors or sizes.

### Color Palette

| Token | Value | Purpose |
|-------|-------|---------|
| `--md-primary` | `#58a6ff` | Primary actions, links, focus rings |
| `--md-primary-hover` | `#79b8ff` | Hover state for primary elements |
| `--md-primary-muted` | `rgba(88,166,255,0.12)` | Subtle primary backgrounds |
| `--md-success` | `#3fb950` | Healthy status, positive indicators |
| `--md-warning` | `#d29922` | Elevated metrics, warnings |
| `--md-danger` | `#f85149` | Critical status, errors |
| `--md-bg` | `#0d1117` | Page background |
| `--md-surface` | `#161b22` | Card backgrounds |
| `--md-surface-raised` | `#1c2129` | Hovered rows, elevated surfaces |
| `--md-surface-overlay` | `#21262d` | Code blocks, input backgrounds |
| `--md-border` | `#30363d` | Strong borders |
| `--md-border-muted` | `#21262d` | Subtle dividers |

### Text Scale

| Token | Size | Usage |
|-------|------|-------|
| `--md-text-xs` | 0.70rem | Labels, badges, table headers |
| `--md-text-sm` | 0.80rem | Body text, form labels, metrics |
| `--md-text-base` | 0.90rem | Default content |
| `--md-text-lg` | 1.10rem | Card headings (h4) |
| `--md-text-xl` | 1.30rem | Section headings (h3) |
| `--md-text-2xl` | 1.60rem | Page titles (h2) |
| `--md-text-3xl` | 2.00rem | Big metric numbers |

### Spacing Scale (4px base)

```
--md-space-1:    4px    (micro gaps)
--md-space-2:    8px    (inline padding, small gaps)
--md-space-3:   12px    (cell padding, card internal)
--md-space-4:   16px    (standard padding)
--md-space-5:   20px    (card padding)
--md-space-6:   24px    (section margins)
--md-space-8:   32px    (large section gaps)
--md-space-10:  40px    (hero spacing)
--md-space-12:  48px
--md-space-16:  64px
```

### Border Radius

| Token | Value | Usage |
|-------|-------|-------|
| `--md-radius-sm` | 4px | Badges, code blocks |
| `--md-radius-md` | 6px | Buttons, inputs |
| `--md-radius-lg` | 8px | Cards, containers |
| `--md-radius-xl` | 12px | Modals (reserved) |

### Shadows

| Token | Usage |
|-------|-------|
| `--md-shadow-sm` | Default card elevation |
| `--md-shadow-md` | Card hover |
| `--md-shadow-lg` | Dropdowns, menus (reserved) |

### Transitions

| Token | Duration | Usage |
|-------|----------|-------|
| `--md-transition-fast` | 120ms ease | Hover color changes, focus rings |
| `--md-transition-normal` | 200ms ease | Card hover, border transitions |
| `--md-transition-slow` | 350ms ease | Page transitions (reserved) |

## Typography

### Font Family

- **UI text**: `-apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif`
- **Code/metrics**: `"SF Mono", "Fira Code", "JetBrains Mono", Menlo, Consolas, monospace`

### Hierarchy

1. **Page titles** (h2) — 1.60rem, semibold, used once per page
2. **Section headers** (h3) — 1.30rem, semibold, used to group content
3. **Card headings** (h4) — 1.10rem, medium
4. **Metric labels** — 0.70rem, uppercase, muted color
5. **Body text** — 0.80rem–0.90rem, runs at 1.5 line-height

### Guidelines

- Labels are uppercase (`letter-spacing: 0.05em`) for scannability
- Monospace is used for all numeric metrics, peer IDs, and code
- Page titles use subtle negative letter-spacing (`-0.02em`)

## Component Patterns

### Navigation Bar

- Sticky at top, 3.25rem height
- Semi-transparent with backdrop blur
- Brand name left, nav links center, logout right
- Active page link: primary color on muted primary background
- Mobile: wraps to multi-line

### Cards (article)

- Dark surface with 1px border, subtle shadow
- Hover: border highlights to primary tint, shadow deepens
- Header: title left, metadata right (monospace, small)
- Footer: actions left, secondary info right, separated by a hairline
- Empty state: dashed border, centered italic text

### Dashboard Node Cards

- Auto-fill grid, 320px minimum column width
- 2-column metrics grid inside each card
- CPU/Memory bars: 5px height, spring-animated on SSE updates
- Green (≤74%), yellow (75–89%), red (≥90%)
- Flash animation on metric update

### Big Metrics (Node Detail)

- Centered block with 2.00rem bold number
- Context line below in muted secondary text
- Per-core CPU bars: tight flex grid of 14px bars

### Tables

- Compact: 0.80rem body, 0.70rem uppercase headers
- Row hover: subtle background highlight
- Separated by muted border lines
- Empty state: centered italic, no border

### Forms

- Dark surface inputs with 1px border
- Focus ring: 3px primary-muted glow
- Inline forms: flex row, wraps on mobile
- Error blocks: danger-muted background with left accent border

### Buttons

- Refined over Pico defaults: consistent padding, border-radius, transitions
- Primary: blue background, white text
- Small variant: 0.70rem, 1.75rem min-height
- Active state: subtle scale-down (0.98)
- Terminal toolbar buttons: transparent background, border on hover

### Terminal

- Toolbar: dark surface, rounded top corners
- Status indicator: colored dot + label (green/yellow/gray/red)
- Container: pure black background, fills remaining viewport height
- Minimum height: 400px

### Login Page

- Centered card, max 380px
- Brand heading with subtitle
- Error block: danger accent on muted background

### Empty States

- Dashed border, centered, italic, muted color
- Inside tables: no border, centered

## Animation Principles

1. **Fast, not flashy.** 120ms for micro-interactions (hover, focus).
2. **Spring for metrics.** Bar width changes use a cubic-bezier overshoot for a "live" feel.
3. **Flash on update.** SSE-driven metric updates trigger a 0.6s blue flash.
4. **Fade on mount.** New cards fade up 4px on first render.
5. **Button press.** Subtle 0.98 scale on active.

## Responsive Strategy

| Breakpoint | Behavior |
|------------|----------|
| **768px** | Nav wraps, single-column cards, stacked forms, smaller tables |
| **480px** | Single-column metrics grid, smaller big-numbers, compact nav links |

## File Structure

```
web/
├── static/
│   ├── css/
│   │   ├── pico.min.css     # Base framework (Pico.css dark theme)
│   │   ├── xterm.css         # xterm.js terminal styles
│   │   └── app.css           # MeshDesk design system + components
│   ├── js/
│   │   ├── htmx.min.js       # HTMX for partial updates
│   │   ├── dashboard.js      # SSE live metrics
│   │   ├── terminal.js       # xterm.js + WebSocket bridge
│   │   └── xterm*.js         # xterm.js + addons
│   └── img/                  # Static images (reserved)
└── templates/
    ├── layout.html           # Base layout (nav, head, scripts)
    ├── dashboard.html        # Node grid + SSE
    ├── node_detail.html      # Single node metrics + history
    ├── peers.html            # Peer table + capability grants
    ├── files.html            # File upload + transfer
    ├── services.html         # Service management
    ├── terminal.html         # Web SSH terminal
    └── login.html            # Authentication
```

## Adding New Pages

1. Create the template in `web/templates/`, wrapping content in `{{define "content"}}`.
2. Use existing CSS classes — do not add inline styles.
3. If a new component pattern is needed, add it to `app.css` under the appropriate section.
4. Reference only design tokens for colors, spacing, and typography.
5. Test at 768px and 480px breakpoints.

## Changelog

- **2026-07-25** — Initial design system: 60+ CSS custom properties, component polish, responsive refinements.