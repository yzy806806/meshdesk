package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestVersionInfoFormat verifies that versionInfo() produces the expected
// output format with all five fields: version, commit, build time, go
// version, and platform.
func TestVersionInfoFormat(t *testing.T) {
	// Save and restore original build vars.
	origVersion := Version
	origCommit := Commit
	origBuildTime := BuildTime
	defer func() {
		Version = origVersion
		Commit = origCommit
		BuildTime = origBuildTime
	}()

	// Set test values.
	Version = "v1.2.0"
	Commit = "abc123def"
	BuildTime = "2026-08-05T20:00:00Z"

	output := versionInfo()
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")

	if len(lines) != 5 {
		t.Fatalf("expected 5 lines of output, got %d: %q", len(lines), output)
	}

	// Line 0: meshdesk <version>
	if lines[0] != "meshdesk v1.2.0" {
		t.Errorf("line 0: expected %q, got %q", "meshdesk v1.2.0", lines[0])
	}

	// Line 1: commit
	if lines[1] != "  commit:     abc123def" {
		t.Errorf("line 1: expected %q, got %q", "  commit:     abc123def", lines[1])
	}

	// Line 2: build time
	if lines[2] != "  build time: 2026-08-05T20:00:00Z" {
		t.Errorf("line 2: expected %q, got %q", "  build time: 2026-08-05T20:00:00Z", lines[2])
	}

	// Line 3: go version — must contain the runtime Go version.
	expectedGoVersion := "  go version: " + runtime.Version()
	if lines[3] != expectedGoVersion {
		t.Errorf("line 3: expected %q, got %q", expectedGoVersion, lines[3])
	}

	// Line 4: platform — must match GOOS/GOARCH.
	expectedPlatform := "  platform:   " + runtime.GOOS + "/" + runtime.GOARCH
	if lines[4] != expectedPlatform {
		t.Errorf("line 4: expected %q, got %q", expectedPlatform, lines[4])
	}
}

// TestVersionInfoDefaults verifies that versionInfo() works correctly
// with the default build-time values (dev/unknown) used when the binary
// is built without -ldflags injection.
func TestVersionInfoDefaults(t *testing.T) {
	origVersion := Version
	origCommit := Commit
	origBuildTime := BuildTime
	defer func() {
		Version = origVersion
		Commit = origCommit
		BuildTime = origBuildTime
	}()

	Version = "dev"
	Commit = "unknown"
	BuildTime = "unknown"

	output := versionInfo()
	if !strings.Contains(output, "meshdesk dev") {
		t.Errorf("expected output to contain %q, got %q", "meshdesk dev", output)
	}
	if !strings.Contains(output, "unknown") {
		t.Errorf("expected output to contain %q for commit/buildtime, got %q", "unknown", output)
	}
	if !strings.Contains(output, runtime.Version()) {
		t.Errorf("expected output to contain go version %q, got %q", runtime.Version(), output)
	}
	if !strings.Contains(output, runtime.GOOS+"/"+runtime.GOARCH) {
		t.Errorf("expected output to contain platform %q, got %q", runtime.GOOS+"/"+runtime.GOARCH, output)
	}
}
