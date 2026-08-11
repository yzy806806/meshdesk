package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/join"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
)

// ─────────────────────────────────────────────────────────────────────────────
// End-to-end wiring test: main.go single-port deployment
//
// This file verifies the exact wiring that cmd/meshdesk/main.go performs for
// the v1.2 single-port onboarding feature (commits 89a10ce + 89e4081):
//
//	joinServer := join.NewJoinServer(cfg)
//	webServer.SetJoinHandler(joinServer.Handler())          // main.go:1233-1235
//	httpLn := muxTransport.HTTPListener()                   // main.go:1242
//	webServer.ServeWithListener(httpLn)                     // main.go:1243
//
// A real TCP client dials the shared demux port and sends a POST /api/join
// request. The bytes travel:
//
//	TCP dial → MuxTransport.handleMuxConn 1-byte peek ('P' for POST)
//	→ httpCh → muxHTTPListener.Accept → http.Server.Serve
//	→ web mux (registerRoutes) → join handler (SetJoinHandler)
//
// and the full two-step join protocol (challenge issuance → Ed25519 signature
// verification → config bundle) completes over that path. This is the
// regression guard for the post-vote commits: if either the join handler is
// not mounted on the web mux or the web server is not served on the demux
// HTTP listener, POST /api/join is unreachable through the mesh port.
//
// The join wire messages used here are byte-identical to what the production
// JoinClient (internal/join/client.go) sends: the same JoinRequest JSON in
// step 1 (token + joiner_pubkey) and step 2 (challenge + challenge_response),
// parsed with the same JoinResponse struct. Only the transport differs — the
// requests are driven through the demux port instead of net/http's default
// dialer, because JoinClient does not expose transport injection.
// ─────────────────────────────────────────────────────────────────────────────

// newMuxJoinHarness replicates the main.go wiring for a shared node:
// a real MuxTransport (bound to an ephemeral 127.0.0.1 port), a real join
// server wired into the web server via SetJoinHandler, and the web server
// served on the demux HTTPListener via ServeWithListener.
//
// It returns the harness plus the transport for byte-level traffic checks
// and a TCP dial function for the mesh port. The harness mirrors main.go's
// join server construction (identity, secret, challenge-response, bundle).
func newMuxJoinHarness(t *testing.T) (*joinMuxHarness, *mesh.MuxTransport, func() (net.Conn, error)) {
	t.Helper()

	// 1. MuxTransport on an ephemeral port — mirrors main.go's shared node.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	mt, err := mesh.NewMuxTransport(mesh.MuxTransportConfig{
		TCPListener:   tcpLn,
		BindAddr:      "127.0.0.1",
		UDPPort:       0,
		AdvertiseAddr: "127.0.0.1",
	})
	if err != nil {
		tcpLn.Close()
		t.Fatalf("NewMuxTransport: %v", err)
	}
	t.Cleanup(func() { _ = mt.Shutdown() })

	addr := tcpLn.Addr().String()
	dial := func() (net.Conn, error) {
		return net.Dial("tcp", addr)
	}

	// 2. Join server — mirrors main.go:1007-1061 (join.NewJoinServer with
	// ServerIdentity from the node, secret, bootstrap endpoint, collectors).
	serverID, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	secret := []byte("mux-join-wiring-secret")
	joinSrv := join.NewJoinServer(join.ServerConfig{
		Secret:            secret,
		ServerIdentity:    serverID,
		BootstrapEndpoint: addr, // mesh endpoint for the bundle
		GossipPort:        7946,
		RealityPublicKey:  "aabbccdd00112233445566778899aabb",
		RealityShortID:    "0102030405060708",
		RealityServerName: "reality.example.com",
		Collectors:        []string{"collector-1", "collector-2"},
		TokenLifetime:     30 * time.Minute,
	})
	joinSrv.SetKnownPeersFunc(func() []join.PeerInfo {
		return []join.PeerInfo{
			{PublicKey: "peer-existing-1", Hostname: "node-veteran", Role: "agent"},
			{PublicKey: "peer-existing-2", Hostname: "node-relay", Role: "relay"},
		}
	})

	// 3. Web server — mirrors main.go:1065-1235 (web.New + SetJoinHandler).
	cfg := config.Default()
	cfg.Node.WebAddr = "127.0.0.1:0"
	cfg.Auth.WebUsers = nil // first-run setup mode: no session required
	webSrv, err := New(Deps{
		Config:       cfg,
		MonitorStore: monitor.NewStore(),
	})
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	webSrv.SetJoinHandler(joinSrv.Handler())

	// 4. Serve the web server on the demux HTTP listener — main.go:1241-1247.
	httpLn := mt.HTTPListener()
	if err := webSrv.ServeWithListener(httpLn); err != nil {
		t.Fatalf("ServeWithListener: %v", err)
	}
	t.Cleanup(webSrv.Stop)

	return &joinMuxHarness{joinSrv: joinSrv, serverID: serverID, secret: secret, addr: addr}, mt, dial
}

// joinMuxHarness holds the server-side state needed by the tests.
type joinMuxHarness struct {
	joinSrv  *join.JoinServer
	serverID *identity.Identity
	secret   []byte
	addr     string
}

// TestMuxJoinWiring_POSTApiJoinReachableThroughDemuxPort is the headline
// end-to-end test for the main.go single-port wiring. It drives the full
// two-step challenge-response join protocol — the exact wire messages the
// production JoinClient sends — with every HTTP request entering via the
// shared demux port (POST /api/join) and being served by the web mux's
// join handler.
func TestMuxJoinWiring_POSTApiJoinReachableThroughDemuxPort(t *testing.T) {
	h, _, dial := newMuxJoinHarness(t)

	token, err := join.GenerateToken(h.secret, h.serverID.PublicKey, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	joiner, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	bundle, err := completeJoinThroughDemux(t, dial, token, joiner, "mux-join-node")
	if err != nil {
		t.Fatalf("two-step join through demux port failed: %v", err)
	}
	if bundle == nil {
		t.Fatal("bundle is nil")
	}
	if bundle.BootstrapPublicKey != h.serverID.PublicKey {
		t.Errorf("BootstrapPublicKey = %q, want %q", bundle.BootstrapPublicKey, h.serverID.PublicKey)
	}
	if bundle.BootstrapEndpoint != h.addr {
		t.Errorf("BootstrapEndpoint = %q, want %q", bundle.BootstrapEndpoint, h.addr)
	}
	if len(bundle.Collectors) != 2 {
		t.Errorf("Collectors = %v, want 2 collectors", bundle.Collectors)
	}
	if len(bundle.KnownPeers) != 2 {
		t.Errorf("KnownPeers = %v, want 2 known peers", bundle.KnownPeers)
	}
	t.Logf("full two-step join completed through demux port (bundle for %s)", bundle.BootstrapPublicKey[:8])
}

// TestMuxJoinWiring_DashboardAndJoinShareDemuxPort verifies that the demux
// HTTP listener serves BOTH the Dashboard (web mux) and the join endpoint —
// the single-port deployment contract. The Dashboard path is auth-exempt in
// first-run setup mode (no web users configured), so a GET / returns 200
// HTML, and POST /api/join is served by the join handler.
func TestMuxJoinWiring_DashboardAndJoinShareDemuxPort(t *testing.T) {
	h, _, dial := newMuxJoinHarness(t)

	// GET / — Dashboard through the demux port.
	resp, err := rawHTTP(dial, "GET", "/", nil)
	if err != nil {
		t.Fatalf("GET / through demux port: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200 (body=%q)", resp.StatusCode, string(body))
	}
	if !bytes.Contains(body, []byte("Mesh Overview")) {
		t.Errorf("GET / body missing dashboard marker 'Mesh Overview': %q", string(body))
	}

	// POST /api/join — join endpoint through the same demux port.
	token, err := join.GenerateToken(h.secret, h.serverID.PublicKey, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	joiner, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	joinResp := doRawJoinStep1(t, dial, token, joiner, "second-join-node")
	if !joinResp.Success || joinResp.Challenge == "" {
		t.Fatalf("POST /api/join through demux port failed: %+v", joinResp)
	}
	t.Log("dashboard + join both served on the shared demux port")
}

// TestMuxJoinWiring_MethodNotAllowedOnJoin verifies the join handler's own
// HTTP semantics survive the mux wiring: GET /api/join must be rejected with
// 405 (the handler only accepts POST), proving the request really reached
// the join handler rather than being swallowed by a catch-all route.
func TestMuxJoinWiring_MethodNotAllowedOnJoin(t *testing.T) {
	_, _, dial := newMuxJoinHarness(t)

	resp, err := rawHTTP(dial, "GET", "/api/join", nil)
	if err != nil {
		t.Fatalf("GET /api/join through demux port: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/join status = %d, want 405 (body=%q)", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "method not allowed") {
		t.Errorf("GET /api/join body = %q, want 'method not allowed'", string(body))
	}
}

// TestMuxJoinWiring_ReplayProtectionThroughDemux verifies that the join
// handler's replay protection works through the demux path: a token used for
// the full two-step join cannot be used again (401). This guards the token
// validation + challenge-response logic that main.go relies on.
func TestMuxJoinWiring_ReplayProtectionThroughDemux(t *testing.T) {
	h, _, dial := newMuxJoinHarness(t)

	token, err := join.GenerateToken(h.secret, h.serverID.PublicKey, 5*time.Minute)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	joiner, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// First join: must succeed.
	first := doRawJoinStep1(t, dial, token, joiner, "replay-node")
	if !first.Success || first.Challenge == "" {
		t.Fatalf("first join step 1 failed: %+v", first)
	}

	// Same token again: the replay cache must reject it (401 Unauthorized).
	replayBody, _ := json.Marshal(join.JoinRequest{
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  "replay-node",
	})
	resp, err := rawHTTP(dial, "POST", "/api/join", replayBody)
	if err != nil {
		t.Fatalf("replay POST /api/join: %v", err)
	}
	replayRespBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401 (body=%q)", resp.StatusCode, string(replayRespBody))
	}
	var jr join.JoinResponse
	if err := json.Unmarshal(replayRespBody, &jr); err != nil {
		t.Fatalf("parse replay response: %v", err)
	}
	if jr.Success {
		t.Error("replay response has Success=true — token was accepted twice")
	}
	if !strings.Contains(jr.Error, "already used") {
		t.Errorf("replay error = %q, want 'already used'", jr.Error)
	}
}

// TestMuxJoinWiring_NonJoinTrafficStillDemuxesToMeshCh verifies that serving
// the web server on HTTPListener() does not break the OTHER demux paths:
// traffic that is not HTTP (the 0x4D mesh-internal marker, 'M') still routes
// to MeshListener, not to the web server. This guards against a regression


// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// completeJoinThroughDemux performs the full two-step join protocol — the
// exact wire messages the production JoinClient sends — with every POST
// entering through the demux port:
//
//	step 1: POST /api/join {token, joiner_pubkey, joiner_hostname} → challenge
//	step 2: POST /api/join {…, challenge, challenge_response: ed25519 sig} → bundle
func completeJoinThroughDemux(t *testing.T, dial func() (net.Conn, error), token string, joiner *identity.Identity, hostname string) (*join.ConfigBundle, error) {
	t.Helper()

	// Step 1: request challenge.
	step1 := doRawJoinStep1(t, dial, token, joiner, hostname)
	if step1.Challenge == "" {
		return nil, fmt.Errorf("join: server did not return a challenge")
	}

	// Step 2: sign challenge and request bundle.
	sig, err := joiner.Sign([]byte(step1.Challenge))
	if err != nil {
		return nil, err
	}
	reqBody, err := json.Marshal(join.JoinRequest{
		Token:             token,
		JoinerPublicKey:   joiner.PublicKey,
		JoinerHostname:    hostname,
		Challenge:         step1.Challenge,
		ChallengeResponse: sig,
	})
	if err != nil {
		return nil, err
	}
	resp, err := rawHTTP(dial, "POST", "/api/join", reqBody)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var jr join.JoinResponse
	if err := json.Unmarshal(body, &jr); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &joinStepError{status: resp.StatusCode, body: string(body)}
	}
	if !jr.Success || jr.Bundle == nil {
		return nil, fmt.Errorf("join: response missing config bundle (status=%d)", resp.StatusCode)
	}
	return jr.Bundle, nil
}

// joinStepError is a small error type carrying the HTTP status of a failed
// join step, so callers can distinguish "not 200" from "protocol error".
type joinStepError struct {
	status int
	body   string
}

func (e *joinStepError) Error() string {
	return "join step: status " + http.StatusText(e.status) + " (" + e.body + ")"
}

// doRawJoinStep1 performs step 1 of the join protocol (challenge issuance)
// through the demux port and returns the parsed response.
func doRawJoinStep1(t *testing.T, dial func() (net.Conn, error), token string, joiner *identity.Identity, hostname string) join.JoinResponse {
	t.Helper()
	reqBody, err := json.Marshal(join.JoinRequest{
		Token:           token,
		JoinerPublicKey: joiner.PublicKey,
		JoinerHostname:  hostname,
	})
	if err != nil {
		t.Fatalf("marshal join request: %v", err)
	}
	resp, err := rawHTTP(dial, "POST", "/api/join", reqBody)
	if err != nil {
		t.Fatalf("POST /api/join: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var jr join.JoinResponse
	if err := json.Unmarshal(body, &jr); err != nil {
		t.Fatalf("parse join response (status=%d): %v (body=%q)", resp.StatusCode, err, string(body))
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/join status = %d, want 200 (body=%q)", resp.StatusCode, string(body))
	}
	return jr
}

// rawHTTP performs an HTTP request through the demux port and returns the
// response with the body fully buffered (the underlying connection is
// closed once the body is read). Connection: close is set so the server
// closes after the response and the read terminates.
func rawHTTP(dial func() (net.Conn, error), method, path string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://meshdesk.test"+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Connection", "close")

	client := &http.Client{Transport: &demuxPortTransport{dial: dial}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// Fully buffer the body so the caller can close the connection
	// deterministically (avoids leaked TCP conns in the test suite).
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return resp, nil
}

// demuxPortTransport is an http.RoundTripper that dials the shared demux
// port directly for every request, bypassing net/http's default transport.
// Each request therefore enters the mesh port and is demuxed to the HTTP
// listener — the same path a remote joiner's TCP connection takes.
type demuxPortTransport struct {
	dial func() (net.Conn, error)
}

func (t *demuxPortTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	conn, err := t.dial()
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body = &connReadCloser{conn: conn, rc: resp.Body}
	return resp, nil
}

type connReadCloser struct {
	conn net.Conn
	rc   io.ReadCloser
}

func (c *connReadCloser) Read(p []byte) (int, error) { return c.rc.Read(p) }
func (c *connReadCloser) Close() error {
	c.rc.Close()
	return c.conn.Close()
}
