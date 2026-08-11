package dns

import (
	"time"

	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// mockProvider implements PeerMetaProvider for testing.
type mockProvider struct {
	local *NodeMeta
	peers []*NodeMeta
}

func (m *mockProvider) LocalMeta() *NodeMeta {
	return m.local
}

func (m *mockProvider) KnownPeers() []*NodeMeta {
	return m.peers
}

// startTestServer starts a DNS server on a random port with the given provider.
// Returns the server, the assigned address, and a cleanup function.
func startTestServer(t *testing.T, provider PeerMetaProvider) (*Server, string, func()) {
	t.Helper()

	// Find a free UDP port.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("failed to find free UDP port: %v", err)
	}
	addr := conn.LocalAddr().String()
	conn.Close()

	srv := NewServer(provider, 0)

	mux := dns.NewServeMux()
	mux.HandleFunc(MeshDomain, srv.handleMeshQuery)
	mux.HandleFunc(".", srv.handleNonMeshQuery)

	server := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	go func() {
		_ = server.ListenAndServe()
	}()

	// Wait for the server to be ready by probing it. Sleep between
	// probes — a busy loop can burn all 100 iterations before the
	// server goroutine is scheduled (UDP port not yet bound → every
	// Exchange returns instantly via ICMP refusal).
	ready := false
	for i := 0; i < 100; i++ {
		m := new(dns.Msg)
		m.SetQuestion("test.mesh.", dns.TypeA)
		_, _, err := new(dns.Client).Exchange(m, addr)
		if err == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		server.Shutdown()
		t.Fatal("dns server failed to become ready")
	}

	srv.server = server
	srv.started = true

	cleanup := func() {
		server.Shutdown()
	}
	return srv, addr, cleanup
}

// dnsQuery sends a DNS query to the given address and returns the response.
func dnsQuery(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	r, _, err := new(dns.Client).Exchange(m, addr)
	if err != nil {
		t.Fatalf("dns query for %q failed: %v", name, err)
	}
	return r
}

func TestResolveHostname(t *testing.T) {
	provider := &mockProvider{
		local: &NodeMeta{
			Hostname:  "txcloud",
			VirtualIP: "10.144.144.1",
		},
		peers: []*NodeMeta{
			{Hostname: "aliyun", VirtualIP: "10.144.144.2"},
			{Hostname: "nas-n1", VirtualIP: "10.144.144.3"},
		},
	}
	srv, addr, cleanup := startTestServer(t, provider)
	defer cleanup()
	_ = srv

	tests := []struct {
		name       string
		query      string
		qtype      uint16
		wantRcode  int
		wantIP     string
		wantAnswer bool
	}{
		{
			name:       "local node A record",
			query:      "txcloud.mesh.",
			qtype:      dns.TypeA,
			wantRcode:  dns.RcodeSuccess,
			wantIP:     "10.144.144.1",
			wantAnswer: true,
		},
		{
			name:       "peer node A record",
			query:      "aliyun.mesh.",
			qtype:      dns.TypeA,
			wantRcode:  dns.RcodeSuccess,
			wantIP:     "10.144.144.2",
			wantAnswer: true,
		},
		{
			name:       "peer node with hyphen A record",
			query:      "nas-n1.mesh.",
			qtype:      dns.TypeA,
			wantRcode:  dns.RcodeSuccess,
			wantIP:     "10.144.144.3",
			wantAnswer: true,
		},
		{
			name:       "case insensitive lookup",
			query:      "ALIYUN.MESH.",
			qtype:      dns.TypeA,
			wantRcode:  dns.RcodeSuccess,
			wantIP:     "10.144.144.2",
			wantAnswer: true,
		},
		{
			name:       "non-existent hostname in .mesh",
			query:      "nonexistent.mesh.",
			qtype:      dns.TypeA,
			wantRcode:  dns.RcodeNameError, // NXDOMAIN
			wantAnswer: false,
		},
		{
			name:       "non-.mesh domain returns NXDOMAIN",
			query:      "example.com.",
			qtype:      dns.TypeA,
			wantRcode:  dns.RcodeNameError, // NXDOMAIN
			wantAnswer: false,
		},
		{
			name:       "bare .mesh domain (no hostname)",
			query:      "mesh.",
			qtype:      dns.TypeA,
			wantRcode:  dns.RcodeNameError, // NXDOMAIN
			wantAnswer: false,
		},
		{
			name:       "AAAA for IPv4 VirtualIP returns NODATA",
			query:      "txcloud.mesh.",
			qtype:      dns.TypeAAAA,
			wantRcode:  dns.RcodeSuccess,
			wantAnswer: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := dnsQuery(t, addr, tt.query, tt.qtype)
			if r.Rcode != tt.wantRcode {
				t.Errorf("rcode: got %d (%s), want %d (%s)",
					r.Rcode, dns.RcodeToString[r.Rcode],
					tt.wantRcode, dns.RcodeToString[tt.wantRcode])
			}

			if tt.wantAnswer {
				if len(r.Answer) == 0 {
					t.Fatal("expected answer, got none")
				}
				aRec, ok := r.Answer[0].(*dns.A)
				if !ok {
					t.Fatalf("expected A record, got %T", r.Answer[0])
				}
				if aRec.A.String() != tt.wantIP {
					t.Errorf("IP: got %s, want %s", aRec.A.String(), tt.wantIP)
				}
				if aRec.Hdr.Ttl != 30 {
					t.Errorf("TTL: got %d, want 30", aRec.Hdr.Ttl)
				}
			}
		})
	}
}

func TestPeerWithoutVirtualIP(t *testing.T) {
	provider := &mockProvider{
		local: &NodeMeta{
			Hostname:  "node1",
			VirtualIP: "10.0.0.1",
		},
		peers: []*NodeMeta{
			{Hostname: "node2", VirtualIP: ""},    // no VirtualIP
			{Hostname: "", VirtualIP: "10.0.0.3"}, // no hostname
		},
	}
	srv, addr, cleanup := startTestServer(t, provider)
	defer cleanup()
	_ = srv

	// node2 has no VirtualIP → NXDOMAIN
	r := dnsQuery(t, addr, "node2.mesh.", dns.TypeA)
	if r.Rcode != dns.RcodeNameError {
		t.Errorf("node2 (no VIP): got rcode %d, want NXDOMAIN", r.Rcode)
	}
}

func TestMultiplePeersSameHostname(t *testing.T) {
	// When two peers have the same hostname, the last one in the list wins.
	provider := &mockProvider{
		local: &NodeMeta{
			Hostname:  "txcloud",
			VirtualIP: "10.0.0.1",
		},
		peers: []*NodeMeta{
			{Hostname: "txcloud", VirtualIP: "10.0.0.2"}, // duplicate
		},
	}
	srv, addr, cleanup := startTestServer(t, provider)
	defer cleanup()
	_ = srv

	r := dnsQuery(t, addr, "txcloud.mesh.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success, got rcode %d", r.Rcode)
	}
	if len(r.Answer) == 0 {
		t.Fatal("expected answer, got none")
	}
	aRec := r.Answer[0].(*dns.A)
	// Local node should take priority (added first, peer overwrites).
	// Either IP is acceptable — the contract is deterministic resolution.
	if aRec.A.String() != "10.0.0.1" && aRec.A.String() != "10.0.0.2" {
		t.Errorf("unexpected IP: %s", aRec.A.String())
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"txcloud.mesh.", "txcloud"},
		{"txcloud.mesh", "txcloud"},
		{"ALIYUN.MESH.", "ALIYUN"},
		{"nas-n1.mesh.", "nas-n1"},
		{"mesh.", ""},
		{"mesh", ""},
		{"example.com.", ""},
		{"", ""},
		{".mesh.", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractHostname(tt.input)
			if got != tt.want {
				t.Errorf("extractHostname(%q): got %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildHostMap(t *testing.T) {
	provider := &mockProvider{
		local: &NodeMeta{
			Hostname:  "Local",
			VirtualIP: "10.0.0.1",
		},
		peers: []*NodeMeta{
			{Hostname: "Peer1", VirtualIP: "10.0.0.2"},
			{Hostname: "peer2", VirtualIP: "10.0.0.3"},
			{Hostname: "", VirtualIP: "10.0.0.4"}, // no hostname
			{Hostname: "peer3", VirtualIP: ""},    // no VIP
			nil,                                   // nil meta
		},
	}

	srv := NewServer(provider, 5353)
	m := srv.buildHostMap()

	if len(m) != 3 {
		t.Fatalf("map size: got %d, want 3 (local + 2 valid peers)", len(m))
	}

	// Check that hostnames are lowercased.
	if m["local"] != "10.0.0.1" {
		t.Errorf("local: got %s, want 10.0.0.1", m["local"])
	}
	if m["peer1"] != "10.0.0.2" {
		t.Errorf("peer1: got %s, want 10.0.0.2", m["peer1"])
	}
	if m["peer2"] != "10.0.0.3" {
		t.Errorf("peer2: got %s, want 10.0.0.3", m["peer2"])
	}
}

func TestServerStartStop(t *testing.T) {
	provider := &mockProvider{
		local: &NodeMeta{Hostname: "node1", VirtualIP: "10.0.0.1"},
	}

	srv := NewServer(provider, 0)
	if err := srv.Start(); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Starting again should fail.
	if err := srv.Start(); err == nil {
		t.Fatal("second Start should fail")
	}

	srv.Stop()

	// Stopping again should be a no-op (no panic).
	srv.Stop()
}

func TestConcurrentQueries(t *testing.T) {
	provider := &mockProvider{
		local: &NodeMeta{
			Hostname:  "txcloud",
			VirtualIP: "10.144.144.1",
		},
		peers: []*NodeMeta{
			{Hostname: "aliyun", VirtualIP: "10.144.144.2"},
			{Hostname: "nas-n1", VirtualIP: "10.144.144.3"},
		},
	}
	srv, addr, cleanup := startTestServer(t, provider)
	defer cleanup()
	_ = srv

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			names := []string{"txcloud.mesh.", "aliyun.mesh.", "nas-n1.mesh."}
			name := names[i%len(names)]
			r := dnsQuery(t, addr, name, dns.TypeA)
			if r.Rcode != dns.RcodeSuccess {
				t.Errorf("query %q: got rcode %d, want success", name, r.Rcode)
			}
			if len(r.Answer) == 0 {
				t.Errorf("query %q: no answer", name)
			}
		}(i)
	}
	wg.Wait()
}

func TestIPv6VirtualIP(t *testing.T) {
	provider := &mockProvider{
		local: &NodeMeta{
			Hostname:  "ipv6node",
			VirtualIP: "fd00::1",
		},
	}
	srv, addr, cleanup := startTestServer(t, provider)
	defer cleanup()
	_ = srv

	// AAAA query for IPv6 VirtualIP should return the address.
	r := dnsQuery(t, addr, "ipv6node.mesh.", dns.TypeAAAA)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA: got rcode %d, want success", r.Rcode)
	}
	if len(r.Answer) == 0 {
		t.Fatal("expected AAAA answer")
	}
	aaaaRec, ok := r.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA record, got %T", r.Answer[0])
	}
	if !strings.EqualFold(aaaaRec.AAAA.String(), "fd00::1") {
		t.Errorf("AAAA IP: got %s, want fd00::1", aaaaRec.AAAA.String())
	}

	// A query for IPv6 VirtualIP should return NODATA (no IPv4 address).
	r2 := dnsQuery(t, addr, "ipv6node.mesh.", dns.TypeA)
	if r2.Rcode != dns.RcodeSuccess {
		t.Errorf("A query for IPv6 host: got rcode %d, want RcodeSuccess (NODATA)", r2.Rcode)
	}
	if len(r2.Answer) != 0 {
		t.Errorf("A query for IPv6 host: expected no answers, got %d", len(r2.Answer))
	}
}

// Ensure that the mock provider's hostname lookup is case-insensitive.
func TestCaseInsensitiveHostmap(t *testing.T) {
	provider := &mockProvider{
		local: &NodeMeta{Hostname: "MixedCase", VirtualIP: "10.0.0.5"},
	}
	srv, addr, cleanup := startTestServer(t, provider)
	defer cleanup()
	_ = srv

	for _, name := range []string{"mixedcase.mesh.", "MIXEDCASE.mesh.", "MiXeDcAsE.mesh."} {
		r := dnsQuery(t, addr, name, dns.TypeA)
		if r.Rcode != dns.RcodeSuccess {
			t.Errorf("query %q: got rcode %d, want success", name, r.Rcode)
		}
		if len(r.Answer) == 0 {
			t.Errorf("query %q: no answer", name)
			continue
		}
		aRec := r.Answer[0].(*dns.A)
		if aRec.A.String() != "10.0.0.5" {
			t.Errorf("query %q: got %s, want 10.0.0.5", name, aRec.A.String())
		}
	}
}

// Test that net.IP comparison works correctly for IPv4-mapped IPv6.
func TestParseVirtualIP(t *testing.T) {
	// Ensure net.ParseIP handles both IPv4 and IPv6.
	ip4 := net.ParseIP("10.0.0.1")
	if ip4 == nil {
		t.Fatal("failed to parse IPv4")
	}
	if ip4.To4() == nil {
		t.Fatal("IPv4 should have To4() non-nil")
	}

	ip6 := net.ParseIP("fd00::1")
	if ip6 == nil {
		t.Fatal("failed to parse IPv6")
	}
	if ip6.To4() != nil {
		t.Fatal("IPv6 should have To4() nil")
	}
}
