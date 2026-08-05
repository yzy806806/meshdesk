package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeVersionInfo(t *testing.T) {
	tests := []struct {
		name  string
		input VersionInfo
		want  VersionInfo
	}{
		{
			name:  "all empty defaults",
			input: VersionInfo{},
			want:  VersionInfo{Version: "dev", Commit: "unknown", BuildTime: "unknown"},
		},
		{
			name:  "partial fill",
			input: VersionInfo{Version: "v1.2.0"},
			want:  VersionInfo{Version: "v1.2.0", Commit: "unknown", BuildTime: "unknown"},
		},
		{
			name:  "all filled",
			input: VersionInfo{Version: "v1.2.0", Commit: "abc123", BuildTime: "2026-08-05T12:00:00Z"},
			want:  VersionInfo{Version: "v1.2.0", Commit: "abc123", BuildTime: "2026-08-05T12:00:00Z"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeVersionInfo(tt.input)
			if got != tt.want {
				t.Errorf("normalizeVersionInfo() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestHandleVersion(t *testing.T) {
	srv, err := New(Deps{
		VersionInfo: VersionInfo{
			Version:   "v1.2.0",
			Commit:    "abc1234",
			BuildTime: "2026-08-05T12:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rec := httptest.NewRecorder()
	srv.handleVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var info VersionInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if info.Version != "v1.2.0" {
		t.Errorf("Version = %q, want %q", info.Version, "v1.2.0")
	}
	if info.Commit != "abc1234" {
		t.Errorf("Commit = %q, want %q", info.Commit, "abc1234")
	}
	if info.BuildTime != "2026-08-05T12:00:00Z" {
		t.Errorf("BuildTime = %q, want %q", info.BuildTime, "2026-08-05T12:00:00Z")
	}
}

func TestHandleVersionDefaults(t *testing.T) {
	// When no VersionInfo is provided, defaults should be applied.
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rec := httptest.NewRecorder()
	srv.handleVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var info VersionInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if info.Version != "dev" {
		t.Errorf("Version = %q, want %q", info.Version, "dev")
	}
	if info.Commit != "unknown" {
		t.Errorf("Commit = %q, want %q", info.Commit, "unknown")
	}
	if info.BuildTime != "unknown" {
		t.Errorf("BuildTime = %q, want %q", info.BuildTime, "unknown")
	}
}
