package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/yzy806806/meshdesk/internal/xray"
)

// --- x-ui Page Tests ---

// TestXuiPageNotConfigured verifies the x-ui page renders the
// "not configured" panel when xrayManager is nil.
func TestXuiPageNotConfigured(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/xui", nil)
	rr := httptest.NewRecorder()
	srv.handleXuiPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if want := "xray-core Not Configured"; !contains(body, want) {
		t.Errorf("expected %q in body when xray is nil", want)
	}
}

// TestXuiPageConfigured verifies the x-ui page renders the panel
// when xrayManager is available.
func TestXuiPageConfigured(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{}

	req := httptest.NewRequest(http.MethodGet, "/xui", nil)
	rr := httptest.NewRecorder()
	srv.handleXuiPage(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if want := "Traffic Statistics"; !contains(body, want) {
		t.Errorf("expected %q in body", want)
	}
	if want := "Client Management"; !contains(body, want) {
		t.Errorf("expected %q in body", want)
	}
	if want := "Share Link"; !contains(body, want) {
		t.Errorf("expected %q in body", want)
	}
}

// TestXuiPageNavActive verifies the nav bar includes x-ui link.
func TestXuiPageNavActive(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{}

	req := httptest.NewRequest(http.MethodGet, "/xui", nil)
	rr := httptest.NewRecorder()
	srv.handleXuiPage(rr, req)

	body := rr.Body.String()
	if want := `/xui`; !contains(body, want) {
		t.Errorf("expected nav link %q in body", want)
	}
}

// --- Client Management API Tests ---

// TestAddClient verifies adding a VLESS client to an inbound.
func TestAddClient(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{
		inbounds: []*xray.InboundConfig{
			{
				Tag:      "test-inbound",
				Protocol: "vless-reality",
				Port:     443,
				VLESSClients: []xray.VLESSClient{
					{ID: "existing-uuid", Flow: "xtls-rprx-vision"},
				},
			},
		},
	}

	reqBody, _ := json.Marshal(addClientRequest{
		InboundTag: "test-inbound",
		UUID:       "new-client-uuid",
		Flow:       "xtls-rprx-vision",
		Email:      "user@test.com",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/xray/inbound/client", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	srv.handleAddClient(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusCreated)
	}

	var resp clientResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.UUID != "new-client-uuid" {
		t.Errorf("UUID: got %q, want %q", resp.UUID, "new-client-uuid")
	}
	if resp.Email != "user@test.com" {
		t.Errorf("Email: got %q, want %q", resp.Email, "user@test.com")
	}
}

// TestAddClientAutoUUID verifies that a client UUID is auto-generated
// when not provided.
func TestAddClientAutoUUID(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{
		inbounds: []*xray.InboundConfig{
			{Tag: "test-inbound", Protocol: "vless-reality", Port: 443},
		},
	}

	reqBody, _ := json.Marshal(addClientRequest{
		InboundTag: "test-inbound",
		// UUID intentionally empty
	})

	req := httptest.NewRequest(http.MethodPost, "/api/xray/inbound/client", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	srv.handleAddClient(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusCreated)
	}

	var resp clientResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.UUID == "" {
		t.Error("expected auto-generated UUID, got empty")
	}
}

// TestListClients verifies listing clients on an inbound.
func TestListClients(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{
		inbounds: []*xray.InboundConfig{
			{
				Tag:      "test-inbound",
				Protocol: "vless-reality",
				Port:     443,
				VLESSClients: []xray.VLESSClient{
					{ID: "uuid-1", Flow: "xtls-rprx-vision", Email: "user1@test.com"},
					{ID: "uuid-2", Flow: "", Email: "user2@test.com"},
				},
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/inbound/client?tag=test-inbound", nil)
	rr := httptest.NewRecorder()
	srv.handleListClients(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp["count"].(float64) != 2 {
		t.Errorf("count: got %v, want 2", resp["count"])
	}
}

// TestRemoveClient verifies removing a VLESS client.
func TestRemoveClient(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{
		inbounds: []*xray.InboundConfig{
			{
				Tag:      "test-inbound",
				Protocol: "vless-reality",
				Port:     443,
				VLESSClients: []xray.VLESSClient{
					{ID: "uuid-to-remove", Flow: "xtls-rprx-vision"},
					{ID: "uuid-to-keep", Flow: "xtls-rprx-vision"},
				},
			},
		},
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/xray/inbound/client?tag=test-inbound&uuid=uuid-to-remove", nil)
	rr := httptest.NewRecorder()
	srv.handleRemoveClient(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify client is gone
	clients, _ := srv.xrayManager.GetClients("test-inbound")
	if len(clients) != 1 {
		t.Errorf("expected 1 client after removal, got %d", len(clients))
	}
	if clients[0].ID != "uuid-to-keep" {
		t.Errorf("remaining client: got %q, want %q", clients[0].ID, "uuid-to-keep")
	}
}

// TestAddClientInboundNotFound verifies error when inbound doesn't exist.
func TestAddClientInboundNotFound(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{}

	reqBody, _ := json.Marshal(addClientRequest{
		InboundTag: "nonexistent",
		UUID:       "some-uuid",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/xray/inbound/client", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	srv.handleAddClient(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// --- Share Link API Tests ---

// TestShareLinkGeneration verifies generating a VLESS share link.
func TestShareLinkGeneration(t *testing.T) {
	// Generate a valid key pair
	priv, pub, err := xray.GenerateX25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{
		inbounds: []*xray.InboundConfig{
			{
				Tag:         "reality-inbound",
				Protocol:    "vless-reality",
				Port:        443,
				Security:    "reality",
				Dest:        "www.microsoft.com:443",
				ServerNames: []string{"www.microsoft.com"},
				PrivateKey:  priv,
				ShortIds:    []string{"0123456789abcdef"},
				VLESSClients: []xray.VLESSClient{
					{ID: "test-uuid-1234", Flow: "xtls-rprx-vision", Email: "user@test.com"},
				},
			},
		},
	}

	reqBody, _ := json.Marshal(shareLinkRequest{
		InboundTag:    "reality-inbound",
		ClientUUID:    "test-uuid-1234",
		ServerAddress: "203.0.113.1",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/xray/share", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	srv.handleXrayShare(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusOK)
	}

	var resp shareLinkResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Link == "" {
		t.Error("expected non-empty share link")
	}

	if !contains(resp.Link, "vless://test-uuid-1234@203.0.113.1:443") {
		t.Errorf("link doesn't contain expected prefix: %s", resp.Link)
	}

	if !contains(resp.Link, "security=reality") {
		t.Errorf("link doesn't contain security=reality: %s", resp.Link)
	}

	if !contains(resp.Link, "pbk=") {
		t.Errorf("link doesn't contain pbk (public key): %s", resp.Link)
	}

	// Verify the public key matches (URL-encoded in the link)
	if !contains(resp.Link, url.QueryEscape(pub)) {
		t.Errorf("link doesn't contain expected public key %q (encoded %q): %s", pub, url.QueryEscape(pub), resp.Link)
	}

	// Verify info struct
	if resp.Info == nil {
		t.Fatal("expected non-nil info")
	}
	if resp.Info.UUID != "test-uuid-1234" {
		t.Errorf("info UUID: got %q, want %q", resp.Info.UUID, "test-uuid-1234")
	}
	if resp.Info.Address != "203.0.113.1" {
		t.Errorf("info address: got %q, want %q", resp.Info.Address, "203.0.113.1")
	}
	if resp.Info.Port != 443 {
		t.Errorf("info port: got %d, want 443", resp.Info.Port)
	}
}

// TestShareLinkInboundNotFound verifies error when inbound doesn't exist.
func TestShareLinkInboundNotFound(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{}

	reqBody, _ := json.Marshal(shareLinkRequest{
		InboundTag:    "nonexistent",
		ClientUUID:    "some-uuid",
		ServerAddress: "1.2.3.4",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/xray/share", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	srv.handleXrayShare(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// TestShareLinkClientNotFound verifies error when client doesn't exist.
func TestShareLinkClientNotFound(t *testing.T) {
	priv, _, _ := xray.GenerateX25519Key()

	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{
		inbounds: []*xray.InboundConfig{
			{
				Tag:         "test-inbound",
				Protocol:    "vless-reality",
				Port:        443,
				Security:    "reality",
				PrivateKey:  priv,
				ServerNames: []string{"example.com"},
				ShortIds:    []string{"abc"},
				VLESSClients: []xray.VLESSClient{
					{ID: "real-uuid", Flow: "xtls-rprx-vision"},
				},
			},
		},
	}

	reqBody, _ := json.Marshal(shareLinkRequest{
		InboundTag:    "test-inbound",
		ClientUUID:    "wrong-uuid",
		ServerAddress: "1.2.3.4",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/xray/share", bytes.NewReader(reqBody))
	rr := httptest.NewRecorder()
	srv.handleXrayShare(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// --- Stats Handler Tests ---

// TestStatsHandlerNotRunning verifies that stats endpoint returns 503
// when xray is not running.
func TestStatsHandlerNotRunning(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}
	srv.xrayManager = &mockXrayManager{}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/stats", nil)
	rr := httptest.NewRecorder()
	srv.handleXrayStats(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}

// TestStatsHandlerNoManager verifies that stats endpoint returns 503
// when xrayManager is nil.
func TestStatsHandlerNoManager(t *testing.T) {
	srv, err := New(Deps{})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/xray/stats", nil)
	rr := httptest.NewRecorder()
	srv.handleXrayStats(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
}
