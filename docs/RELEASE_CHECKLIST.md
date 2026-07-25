# MeshDesk Release Checklist

**Purpose:** Standard operating procedure for cutting a MeshDesk GitHub release.
Every release follows these steps in order. Apply this to each feature batch that lands
on `main`.

---

## Pre-flight

Before starting, verify the feature batch is fully merged:

```bash
# Ensure you're on main and up-to-date
git checkout main
git pull --rebase origin main

# Verify the feature commits are present
git log --oneline -10
```

---

## Step 1: Git push to `origin/main`

Push the merged feature batch to the public repository.

```bash
git push origin main
```

- [ ] Push confirmed — verify with `git log origin/main --oneline -3`

> **Check:** The two most recent commits should be the topology backend + frontend
> (or whichever feature batch triggered this release). No unmerged branches.

---

## Step 2: Update README features section

Add the new feature under the `## Features` heading in `README.md`.

For the **3D Topology Visualization** batch, add after "Service Management" and
before "Installation":

```markdown
### Network Topology

- **3D force-directed graph** of all mesh nodes (Three.js r128 + OrbitControls)
- Real-time updates via Server-Sent Events (`/api/topology/events`)
- REST snapshot endpoint (`/api/topology`) for polling clients
- Circuit particle animation along active proxy paths
- Performance adaptation — reduces particle count when FPS drops below 30
- Color-coded node roles: Entry (#58a6ff), Relay (#d29922), Exit (#3fb950), Dashboard (#bc8cff)
- Mock-data fallback when no live peers are connected
```

- [ ] README feature section updated and committed
- [ ] Comparison table at top (`### Why not just use Nezha + EasyTier?`) updated if the
      new feature adds a differentiating row (network topology row already exists as
      "Network topology view | ❌ | ✅ (CLI only) | ✅ (Web UI)" — verify it's accurate)

---

## Step 3: Update relevant `docs/`

Review and refresh every doc that references changed areas.

### 3.1 Mandatory updates

| Document | Action |
|----------|--------|
| `docs/3D_TOPOLOGY_DESIGN.md` | Verify design doc reflects what was actually built. Update any outdated API surfaces, data structures, or architecture decisions. |
| `docs/FRONTEND.md` | Verify route count, template list, token inventory, and static asset inventory are current. The topology page adds 1 route (`/topology`), 1 template (`topology.html`), 1 new JS file, and 1 new CSS file. |
| `docs/ARCHITECTURE.md` | Add topology subsystem to the architecture overview if not already present. |

### 3.2 Conditional updates (check each)

| Document | Condition | Action |
|----------|-----------|--------|
| `docs/DESIGN.md` | If topology changed any core design decisions | Add decision record |
| `AGENTS.md` | If the kanban summary mentions topology tasks | Verify completion status is reflected |
| `THREAT_MODEL.md` | If topology endpoints expose new attack surface | Audit and update if needed |

### 3.3 Verification

```bash
# Audit docs for stale references to old behavior
grep -rn "TODO\|FIXME\|XXX\|deprecated\|not yet implemented" docs/
```

- [ ] All mandatory docs updated
- [ ] Conditional docs reviewed, updated if needed
- [ ] No stale TODO/FIXME references left in docs/

---

## Step 4: `gh release create` with changelog

### 4.1 Write the changelog

Create release notes in a temporary file:

```bash
cat > /tmp/meshdesk-release-notes.md << 'RELEASE_EOF'
# MeshDesk v0.1.0

Initial release with the following features:

## Features

### Network Topology (new)
- 3D force-directed graph of all mesh nodes (Three.js r128)
- Real-time SSE updates and REST snapshot API
- Circuit particle animation along proxy paths
- Color-coded node roles and mock-data fallback

### Core Platform
- Mesh VPN via WireGuard (wireguard-go + gVisor netstack)
- Web dashboard with real-time metrics (CPU, memory, disk, network)
- xterm.js Web Terminal (multi-tab, multi-server)
- File transfer over the mesh VPN
- Systemd service management
- TOTP 2FA with step-up authentication
- Encrypted TOTP secret persistence at rest
- Proxy transport: bounded chunking with random padding, circuit setup via ECDH
- Transport obfuscation: padded mode and WebSocket mode
- Dashboard security alerting for auth denials and suspicious activity

**Full Changelog:** https://github.com/yzy806806/meshdesk/commits/main
RELEASE_EOF
```

> **Adjust the version number** based on the release — see Step 5.

### 4.2 Create the GitHub release

```bash
# For a new project (first release):
gh release create v0.1.0 \
  --title "MeshDesk v0.1.0" \
  --notes-file /tmp/meshdesk-release-notes.md \
  --target main

# For a subsequent release:
gh release create v0.2.0 \
  --title "MeshDesk v0.2.0 — 3D Topology Visualization" \
  --notes-file /tmp/meshdesk-release-notes.md \
  --target main \
  --generate-notes
```

> Use `--generate-notes` for incremental releases — it auto-generates a
> change summary from merged PRs and prepends it to your notes.

### 4.3 Verify

```bash
gh release view v0.1.0
```

- [ ] Release notes written and reviewed
- [ ] `gh release create` succeeded
- [ ] Release visible at `https://github.com/yzy806806/meshdesk/releases`

---

## Step 5: Version bump in source

### 5.1 Add a version string to the binary

MeshDesk currently has no version baked into the binary. Add it:

1. **Create `internal/version/version.go`:**

```go
// Package version provides the MeshDesk version string, injected at build time.
package version

// Version is set at build time via -ldflags "-X github.com/yzy806806/meshdesk/internal/version.Version=v0.1.0".
// If unset, it defaults to "dev".
var Version = "dev"
```

2. **Wire it into `cmd/meshdesk/main.go`:**

Add a `--version` flag that prints the version and exits:

```go
// Add import: "github.com/yzy806806/meshdesk/internal/version"

// Add flag:
var showVersion bool
flag.BoolVar(&showVersion, "version", false, "print version and exit")

// Handle early in main():
if showVersion {
    fmt.Println("meshdesk", version.Version)
    os.Exit(0)
}
```

3. **Update the build command in README.md:**

```bash
go build -ldflags "-s -w -X github.com/yzy806806/meshdesk/internal/version.Version=v0.1.0" -o meshdesk ./cmd/meshdesk/
```

4. **Bump the version forward** after release:

```bash
# After releasing v0.1.0, the source should reflect the next dev version:
# Set Version = "v0.2.0-dev" in internal/version/version.go
```

### 5.2 Commit and push

```bash
git add internal/version/ cmd/meshdesk/main.go README.md
git commit -m "chore: add version string infrastructure (v0.1.0)"
git push origin main
```

- [ ] `internal/version/version.go` created
- [ ] `--version` flag wired in `cmd/meshdesk/main.go`
- [ ] README build command updated with ldflags
- [ ] Version bumped to next-dev after release
- [ ] Committed and pushed

---

## Post-release

### Verify binary reports correct version

```bash
go build -ldflags "-s -w -X github.com/yzy806806/meshdesk/internal/version.Version=v0.1.0" -o /tmp/meshdesk ./cmd/meshdesk/
/tmp/meshdesk --version
# Expected: meshdesk v0.1.0
```

### Update the release tag if needed

If you forgot something minor (typo in release notes, wrong title):

```bash
gh release edit v0.1.0 --title "Corrected Title"
```

Do **not** move the tag to a different commit — tags are immutable for consumers.
Create a patch release (v0.1.1) instead.

---

## Checklist summary

- [ ] **Step 1:** `git push origin main` — feature batch pushed
- [ ] **Step 2:** README features section updated
- [ ] **Step 3:** Relevant docs refreshed, no stale references
- [ ] **Step 4:** `gh release create` with changelog
- [ ] **Step 5:** Version string added to binary + bumped forward
- [ ] **Post-release:** Binary reports correct version

---

## 3D Topology release notes (first application)

This checklist's first application targets the **3D Topology Visualization**
feature batch, composed of:

| Commit | Author | Summary |
|--------|--------|---------|
| `10518da` | topology backend | REST `/api/topology` + SSE `/api/topology/events`, 41 new tests |
| `6cd230a` | topology frontend | Three.js r128 3D graph, `/topology` page, circuit animation |

**Suggested version:** `v0.1.0` — this is MeshDesk's first public release.
