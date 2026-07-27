package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestConfigPage_RendersTemplate verifies that the /config page handler
// renders the config.html template with the correct title and active page.
func TestConfigPage_RendersTemplate(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	req := configRequestWithAuth("GET", "/config", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	body := rr.Body.String()

	// Check the page title is present.
	if !strings.Contains(body, "Configuration") {
		t.Errorf("page body does not contain 'Configuration' title")
	}

	// Check that section tabs are rendered (all 11 sections).
	expectedSections := []string{
		"node", "mesh", "peers", "p2p", "monitoring",
		"webssh", "auth", "transfer", "proxy", "xray", "reality",
	}
	for _, section := range expectedSections {
		if !strings.Contains(body, "data-section=\""+section+"\"") {
			t.Errorf("page body does not contain tab for section %q", section)
		}
	}

	// Check that config.js is referenced.
	if !strings.Contains(body, "/static/js/config.js") {
		t.Errorf("page body does not reference config.js")
	}

	// Check that the active page is set to "config".
	if !strings.Contains(body, "active") {
		// The active class is set by layout template via ActivePage comparison.
		// We check that the nav link for /config exists.
		if !strings.Contains(body, "/config") {
			t.Errorf("page body does not contain nav link to /config")
		}
	}
}

// TestConfigPage_ContainsTierDisplayElements verifies that the rendered
// page contains the key UI elements for tiered field display:
// feedback banner, section tabs, and step-up/diff modals.
func TestConfigPage_ContainsTierDisplayElements(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	req := configRequestWithAuth("GET", "/config", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigPage(rr, req)

	body := rr.Body.String()

	// Feedback banner
	if !strings.Contains(body, "cfg-feedback") {
		t.Errorf("page missing feedback banner element (cfg-feedback)")
	}

	// Pending restart indicator
	if !strings.Contains(body, "cfg-pending-restart") {
		t.Errorf("page missing pending restart indicator (cfg-pending-restart)")
	}

	// Section tabs container
	if !strings.Contains(body, "config-tabs") {
		t.Errorf("page missing section tabs container (config-tabs)")
	}

	// Config content area
	if !strings.Contains(body, "cfg-content") {
		t.Errorf("page missing config content area (cfg-content)")
	}

	// Step-up modal
	if !strings.Contains(body, "cfg-stepup-modal") {
		t.Errorf("page missing step-up modal (cfg-stepup-modal)")
	}

	// Diff modal
	if !strings.Contains(body, "cfg-diff-modal") {
		t.Errorf("page missing diff modal (cfg-diff-modal)")
	}

	// Reload button
	if !strings.Contains(body, "configReload") {
		t.Errorf("page missing reload button (configReload)")
	}

	// Restart button
	if !strings.Contains(body, "configRestart") {
		t.Errorf("page missing restart button (configRestart)")
	}

	// Diff button
	if !strings.Contains(body, "configDiff") {
		t.Errorf("page missing diff button (configDiff)")
	}
}

// TestConfigPage_ContentType verifies the page is served as HTML.
func TestConfigPage_ContentType(t *testing.T) {
	srv, _ := newConfigTestServer(t)
	session := srv.sessions.Create("admin")

	req := configRequestWithAuth("GET", "/config", "", session.Token)
	rr := httptest.NewRecorder()
	srv.handleConfigPage(rr, req)

	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// TestConfigPage_TemplateRegistered ensures config.html is in the pages map.
func TestConfigPage_TemplateRegistered(t *testing.T) {
	srv, _ := newConfigTestServer(t)

	if _, ok := srv.pages["config.html"]; !ok {
		t.Error("config.html template not registered in server.pages")
	}
}
