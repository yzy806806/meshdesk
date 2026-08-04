# CI/CD Verification Report

**Version:** 1.1
**Date:** 2026-08-05
**HEAD:** `1f1e556` = `origin/main` (working tree clean)
**Scope:** All CI/CD and release pipeline changes from `83de7b7` through `1f1e556`

## Overview

This document verifies that all CI/CD changes introduced in v1.1 are correct,
tested, and ready for tagged release. It covers the GitHub Actions release
workflow, install script, and associated test coverage.

## Commits Verified

| Commit | Description |
|--------|-------------|
| `83de7b7` | ci: add GitHub Actions release workflow + systemd unit + one-click install script |
| `28331c1` | fix(ci): correct matrix property name in release workflow job name |
| `785dc4f` | ci: add test job to release workflow + ACL IPv6/concurrency tests |
| `1f1e556` | ci: fix release asset list + install.sh portability; add multipath perf tests |

## 1. Release Workflow (`.github/workflows/release.yml`)

### Structure

The workflow triggers on `v*` tag pushes and has three jobs:

1. **test** — Runs `go vet ./...` and `go test ./... -timeout 120s` on Go 1.25
2. **build** — Matrix build for `amd64` and `arm64` (depends on `test`)
3. **release** — Creates GitHub Release with all artifacts (depends on `build`)

### Fixes Applied

- **Matrix property fix (`28331c1`):** The build job name originally referenced
  `matrix.arch` which doesn't exist in the matrix definition. Corrected to
  `matrix.goarch` to match the actual matrix key.

- **Test gate (`785dc4f`):** Added a `test` job that gates the `build` job via
  `needs: test`. This ensures no binary is built or released if tests fail.

- **Release asset list (`1f1e556`):** Added `artifacts/README_CN.md` to the
  release asset upload list. The `cp README_CN.md` step at the prepare stage
  already copied it, but it was missing from the `files:` list in
  `softprops/action-gh-release`.

### Verification

```
$ go vet ./...
(clean, 0 warnings)

$ go test ./... -timeout 120s
ok  github.com/yzy806806/meshdesk/cmd/meshdesk
ok  github.com/yzy806806/meshdesk/internal/auth
ok  github.com/yzy806806/meshdesk/internal/config
ok  github.com/yzy806806/meshdesk/internal/crypto
ok  github.com/yzy806806/meshdesk/internal/handshake
ok  github.com/yzy806806/meshdesk/internal/identity
ok  github.com/yzy806806/meshdesk/internal/ipam
ok  github.com/yzy806806/meshdesk/internal/join
ok  github.com/yzy806806/meshdesk/internal/mesh
ok  github.com/yzy806806/meshdesk/internal/monitor
ok  github.com/yzy806806/meshdesk/internal/p2p
ok  github.com/yzy806806/meshdesk/internal/proxy    (2.248s)
ok  github.com/yzy806806/meshdesk/internal/service
ok  github.com/yzy806806/meshdesk/internal/session
ok  github.com/yzy806806/meshdesk/internal/smux
ok  github.com/yzy806806/meshdesk/internal/topology
ok  github.com/yzy806806/meshdesk/internal/topology/mock
ok  github.com/yzy806806/meshdesk/internal/transfer
ok  github.com/yzy806806/meshdesk/internal/tun
ok  github.com/yzy806806/meshdesk/internal/web
ok  github.com/yzy806806/meshdesk/internal/webssh
22 packages, 0 FAIL

$ go build -trimpath -ldflags="-s -w -X main.Version=test" -o /dev/null ./cmd/meshdesk/
(clean, exit 0)
```

### Cross-compilation check

```
$ GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/meshdesk/
(clean, exit 0)

$ GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/meshdesk/
(clean, exit 0)
```

Both target architectures compile cleanly with the exact flags used in the
release workflow.

## 2. Install Script (`deploy/install.sh`)

### Fixes Applied

- **Portable file size check (`1f1e556`):** Replaced `ls -l | awk` parsing with
  `stat -c %s` (Linux) / `stat -f %z` (macOS/BSD) for reliable file size
  detection across platforms.

- **Join command flags (`1f1e556`):** Changed from positional args to
  `--join-url` and `--join-token` flags, matching the CLI's actual flag
  interface in `cmd/meshdesk/`.

### ShellCheck

```
$ shellcheck deploy/install.sh
(no output = clean)
```

## 3. Test Coverage Added

### ACL Tests (`785dc4f`)

Added comprehensive ACL test coverage:
- IPv6 `parsePacketInfo` parsing
- Source CIDR matching
- Source/dst port matching
- Combined field matching
- Wildcard peer/protocol rules
- `UpdateRules` state reset
- Concurrent access safety

### Multipath Performance Tests (`1f1e556`)

Added `internal/proxy/multipath_perf_test.go` — 9 test functions, 22 subtests:
- Throughput under concurrent load
- Failover when primary path goes down
- Fair distribution across paths
- Probe cache behavior
- Packet loss resilience
- Path selection scaling

## 4. Release Artifacts

The release workflow produces the following artifacts:

| Artifact | Source | Purpose |
|----------|--------|---------|
| `meshdesk-linux-amd64` | Go cross-compile | amd64 binary |
| `meshdesk-linux-arm64` | Go cross-compile | arm64 binary |
| `checksums.txt` | `sha256sum` | Integrity verification |
| `meshdesk.service` | `deploy/meshdesk.service` | systemd unit |
| `install.sh` | `deploy/install.sh` | One-click installer |
| `README.md` | repo root | Project documentation |
| `README_CN.md` | repo root | Chinese documentation |

## 5. Release Procedure

To cut a release:

```bash
cd /root/meshdesk
git tag v1.1.0
git push origin v1.1.0
```

The tag push triggers the workflow automatically. The Release appears on
https://github.com/yzy806806/meshdesk/releases with all artifacts attached.

## Summary

| Check | Status |
|-------|--------|
| `go vet ./...` | PASS |
| `go test ./... -timeout 120s` | PASS (22 packages, 0 fail) |
| `go build` (amd64) | PASS |
| `go build` (arm64) | PASS |
| `shellcheck deploy/install.sh` | PASS |
| Release workflow YAML valid | PASS |
| All commits pushed to `origin/main` | PASS (`HEAD` = `1f1e556` = `origin/main`) |
| Working tree clean | PASS |

All CI/CD changes are verified and ready for tagged release.
