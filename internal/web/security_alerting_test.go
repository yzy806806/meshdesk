package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/auth"
	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/proxy"
)

// TestHandleAuthDenial verifies that auth denials are converted to alerts.
func TestHandleAuthDenial(t *testing.T) {
	store := NewAlertStore()

	// Simulate a no_capability denial.
	store.HandleAuthDenial(auth.AuthResult{
		Allowed:    false,
		Reason:     "no_capability",
		Capability: auth.CapSSHProxy,
		Resource:   "",
		SourcePeer: "peer-abc123",
		SourceIP:   "10.0.0.1:12345",
		Timestamp:  time.Now(),
	})

	if store.Count() != 1 {
		t.Fatalf("expected 1 alert, got %d", store.Count())
	}

	alerts := store.List()
	if alerts[0].Type != "capability_denied" {
		t.Errorf("expected type 'capability_denied', got '%s'", alerts[0].Type)
	}
	if alerts[0].Severity != AlertWarning {
		t.Errorf("expected severity warning for no_capability, got %s", alerts[0].Severity)
	}
	if alerts[0].Username != "peer-abc123" {
		t.Errorf("expected username 'peer-abc123', got '%s'", alerts[0].Username)
	}
	if alerts[0].SourceIP != "10.0.0.1:12345" {
		t.Errorf("expected source IP '10.0.0.1:12345', got '%s'", alerts[0].SourceIP)
	}
}

// TestHandleAuthDenial_RevokedIsCritical verifies that revoked-peer denials
// are classified as critical.
func TestHandleAuthDenial_RevokedIsCritical(t *testing.T) {
	store := NewAlertStore()

	store.HandleAuthDenial(auth.AuthResult{
		Allowed:    false,
		Reason:     "revoked",
		Capability: auth.CapSSHProxy,
		SourcePeer: "peer-revoked",
		Timestamp:  time.Now(),
	})

	if store.Count() != 1 {
		t.Fatalf("expected 1 alert, got %d", store.Count())
	}

	alerts := store.List()
	if alerts[0].Severity != AlertCritical {
		t.Errorf("expected severity critical for revoked peer, got %s", alerts[0].Severity)
	}
}

// TestHandlePeerJoin verifies that mesh peer joins generate alerts.
func TestHandlePeerJoin(t *testing.T) {
	store := NewAlertStore()

	store.HandlePeerJoin(&mesh.PeerEntry{
		ID:         "peer-def456",
		Endpoint:   "1.2.3.4:51820",
		AllowedIPs: []string{"10.10.1.2/32"},
	})

	if store.Count() != 1 {
		t.Fatalf("expected 1 alert, got %d", store.Count())
	}

	alerts := store.List()
	if alerts[0].Type != "node_join" {
		t.Errorf("expected type 'node_join', got '%s'", alerts[0].Type)
	}
	if alerts[0].Severity != AlertInfo {
		t.Errorf("expected severity info for node join, got %s", alerts[0].Severity)
	}
	if alerts[0].Username != "peer-def456" {
		t.Errorf("expected username 'peer-def456', got '%s'", alerts[0].Username)
	}
	if alerts[0].Description == "" {
		t.Error("description should not be empty")
	}
}

// TestHandlePeerLeave verifies that mesh peer leaves generate alerts.
func TestHandlePeerLeave(t *testing.T) {
	store := NewAlertStore()

	store.HandlePeerLeave("peer-xyz789")

	if store.Count() != 1 {
		t.Fatalf("expected 1 alert, got %d", store.Count())
	}

	alerts := store.List()
	if alerts[0].Type != "node_leave" {
		t.Errorf("expected type 'node_leave', got '%s'", alerts[0].Type)
	}
	if alerts[0].Severity != AlertInfo {
		t.Errorf("expected severity info for node leave, got %s", alerts[0].Severity)
	}
}

// TestHandleProxySecurityEvent verifies that proxy security events
// are converted to alerts.
func TestHandleProxySecurityEvent(t *testing.T) {
	store := NewAlertStore()

	store.HandleProxySecurityEvent(proxy.SecurityEvent{
		Type:        proxy.SecEventExitPortDenied,
		Description: "port 443 not allowed",
		CircuitID:   "aabbccdd",
		TargetAddr:  "1.2.3.4:443",
	})

	if store.Count() != 1 {
		t.Fatalf("expected 1 alert, got %d", store.Count())
	}

	alerts := store.List()
	if alerts[0].Type != string(proxy.SecEventExitPortDenied) {
		t.Errorf("expected type '%s', got '%s'", proxy.SecEventExitPortDenied, alerts[0].Type)
	}
	if alerts[0].Severity != AlertWarning {
		t.Errorf("expected severity warning, got %s", alerts[0].Severity)
	}
	if alerts[0].Username != "aabbccdd" {
		t.Errorf("expected circuit ID as username, got '%s'", alerts[0].Username)
	}
}

// TestFullAlertingIntegration wires all subsystems to the AlertStore
// and verifies that events from each subsystem appear in the alerts list.
func TestFullAlertingIntegration(t *testing.T) {
	// Create an AlertStore.
	store := NewAlertStore()

	// Create a CapabilityEngine with a deny callback wired to the store.
	audit := auth.NewAuditLogger(nil)
	cfg := config.Default()
	cfg.Peers = []config.PeerConfig{{
		PublicKey:    "peer-test",
		Capabilities: []string{auth.CapSSHProxy},
	}}
	engine := auth.NewCapabilityEngine(cfg, audit)
	engine.SetDenyCallback(store.HandleAuthDenial)

	// Create a RoutingTable with join/leave callbacks wired to the store.
	rt := mesh.NewRoutingTable()
	rt.SetJoinCallback(store.HandlePeerJoin)
	rt.SetLeaveCallback(store.HandlePeerLeave)

	// Create a SecurityEventSink with callback wired to the store.
	secSink := proxy.NewSecurityEventSink()
	secSink.SetCallback(store.HandleProxySecurityEvent)

	// 1. Trigger a capability denial.
	engine.Authorize("peer-test", auth.CapFileTransfer, "/etc/passwd")

	// 2. Trigger a peer join.
	rt.AddPeer(&mesh.PeerEntry{
		ID:         "peer-new",
		Endpoint:   "2.3.4.5:51820",
		AllowedIPs: []string{"10.10.5.5/32"},
	})

	// 3. Trigger a proxy security event.
	secSink.Report(proxy.SecurityEvent{
		Type:        proxy.SecEventRelayCircuitNotFound,
		Description: "relay: circuit not found",
		CircuitID:   "ff00ff00",
	})

	// 4. Trigger a peer leave.
	rt.RemovePeer("peer-new")

	// Verify all 4 alerts were generated.
	alerts := store.List()
	if len(alerts) != 4 {
		t.Fatalf("expected 4 alerts, got %d", len(alerts))
	}

	// Verify each alert type is present.
	types := make(map[string]bool)
	for _, a := range alerts {
		types[a.Type] = true
	}

	expectedTypes := []string{
		"capability_denied",
		"node_join",
		"relay_circuit_not_found", // string(proxy.SecEventRelayCircuitNotFound)
		"node_leave",
	}

	for _, expected := range expectedTypes {
		if !types[expected] {
			t.Errorf("expected alert type '%s' not found", expected)
		}
	}
}

// TestAlertStore_DedupWithAuthDenials verifies that rapid duplicate auth
// denials are deduplicated by the alert store's 60-second window.
func TestAlertStore_DedupWithAuthDenials(t *testing.T) {
	store := NewAlertStore()

	// Same denial twice within 60s → should be deduped.
	result := auth.AuthResult{
		Allowed:    false,
		Reason:     "no_capability",
		Capability: auth.CapSSHProxy,
		SourcePeer: "peer-dup",
		Resource:   "",
	}

	store.HandleAuthDenial(result)
	store.HandleAuthDenial(result)

	if store.Count() != 1 {
		t.Errorf("expected 1 alert after dedup, got %d", store.Count())
	}

	// Different capability → not deduped.
	result.Capability = auth.CapFileTransfer
	store.HandleAuthDenial(result)

	if store.Count() != 2 {
		t.Errorf("expected 2 alerts (different capability), got %d", store.Count())
	}
}

// TestHTTP_AlertsListWithExternalEvents verifies the /api/alerts endpoint
// returns alerts generated by external subsystem events.
func TestHTTP_AlertsListWithExternalEvents(t *testing.T) {
	srv := new2FATestServer(t)
	session := srv.sessions.Create("admin")

	// Generate alerts from various subsystems via the adapter methods.
	srv.alertStore.HandleAuthDenial(auth.AuthResult{
		Allowed:    false,
		Reason:     "revoked",
		Capability: auth.CapSSHProxy,
		SourcePeer: "peer-revoked",
	})

	srv.alertStore.HandlePeerJoin(&mesh.PeerEntry{
		ID:       "peer-new-node",
		Endpoint: "1.2.3.4:51820",
	})

	srv.alertStore.HandleProxySecurityEvent(proxy.SecurityEvent{
		Type:        proxy.SecEventExitPortDenied,
		Description: "port 443 denied",
		CircuitID:   "deadbeef",
	})

	req := httptest.NewRequest("GET", "/api/alerts", nil)
	req.AddCookie(&http.Cookie{Name: "meshdesk_session", Value: session.Token})
	rr := httptest.NewRecorder()
	srv.handleAlertsList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var alerts []map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &alerts); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}

	if len(alerts) < 3 {
		t.Fatalf("expected at least 3 alerts, got %d", len(alerts))
	}

	// Verify each expected type is present.
	types := make(map[string]bool)
	for _, a := range alerts {
		if t, ok := a["type"].(string); ok {
			types[t] = true
		}
	}

	for _, expected := range []string{"capability_denied", "node_join", "exit_port_denied"} {
		if !types[expected] {
			t.Errorf("expected alert type '%s' in response", expected)
		}
	}

	// Verify the revoked-peer denial is critical.
	for _, a := range alerts {
		if a["type"] == "capability_denied" {
			if a["severity"] != string(AlertCritical) {
				t.Errorf("expected capability_denied to be critical (revoked), got %v", a["severity"])
			}
		}
	}
}
