package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAlertsPage_RendersTemplate verifies that the /alerts page handler
// renders the alerts.html template with the correct title and active page.
func TestAlertsPage_RendersTemplate(t *testing.T) {
	srv := newTestServer(t)
	session := srv.sessions.Create("admin")

	req := httptest.NewRequest("GET", "/alerts", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()
	srv.handleAlertsPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	body := rr.Body.String()

	// Check the page title is present.
	if !strings.Contains(body, "Security Alerts") {
		t.Errorf("page body does not contain 'Security Alerts' title")
	}

	// Check that the alerts table is rendered.
	if !strings.Contains(body, "alerts-table") {
		t.Errorf("page body does not contain alerts table")
	}

	// Check that alerts.js is referenced.
	if !strings.Contains(body, "/static/js/alerts.js") {
		t.Errorf("page body does not reference alerts.js")
	}

	// Check that the nav link for /alerts exists.
	if !strings.Contains(body, "/alerts") {
		t.Errorf("page body does not contain nav link to /alerts")
	}

	// Check filter elements are present.
	if !strings.Contains(body, "alerts-filter-severity") {
		t.Errorf("page body does not contain severity filter")
	}
	if !strings.Contains(body, "alerts-filter-dismissed") {
		t.Errorf("page body does not contain dismissed filter")
	}
	if !strings.Contains(body, "alerts-filter-search") {
		t.Errorf("page body does not contain search filter")
	}
}

// TestAlertsPage_TemplateRegistered verifies that alerts.html is registered
// in the server's pages map.
func TestAlertsPage_TemplateRegistered(t *testing.T) {
	srv := newTestServer(t)
	if _, ok := srv.pages["alerts.html"]; !ok {
		t.Error("alerts.html template not registered in server.pages")
	}
}

// TestDashboard_ContainsAlertBar verifies that the dashboard page includes
// the alert notification bar div.
func TestDashboard_ContainsAlertBar(t *testing.T) {
	srv := newTestServer(t)
	session := srv.sessions.Create("admin")

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()
	srv.handleDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	body := rr.Body.String()

	// Check that the alert bar div is present.
	if !strings.Contains(body, "alert-bar") {
		t.Errorf("dashboard page does not contain alert-bar div")
	}

	// Check that alerts.js is loaded on the dashboard.
	if !strings.Contains(body, "/static/js/alerts.js") {
		t.Errorf("dashboard page does not reference alerts.js")
	}
}

// TestAlertsPage_NavLinkActive verifies that the /alerts nav link is present
// in the layout and marked active when on the alerts page.
func TestAlertsPage_NavLinkActive(t *testing.T) {
	srv := newTestServer(t)
	session := srv.sessions.Create("admin")

	req := httptest.NewRequest("GET", "/alerts", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()
	srv.handleAlertsPage(rr, req)

	body := rr.Body.String()

	// The nav link should exist and be marked active.
	if !strings.Contains(body, `href="/alerts"`) {
		t.Errorf("page body does not contain /alerts nav link")
	}
	if !strings.Contains(body, `class="active"`) {
		t.Errorf("alerts nav link is not marked active on alerts page")
	}
}
