// Package dns implements a lightweight DNS server for the MeshDesk mesh.
//
// The server listens on a UDP port and resolves queries for names in the
// ".mesh" domain to VirtualIP addresses. The hostname→VirtualIP mapping
// is sourced from the gossip layer's peer metadata (NodeMeta.Hostname +
// NodeMeta.VirtualIP), which is synchronized across all mesh nodes via
// the memberlist gossip protocol.
//
// Supported query types:
//   - A:    <hostname>.mesh → VirtualIP (IPv4)
//   - AAAA: <hostname>.mesh → VirtualIP (IPv6, if available)
//
// Queries for names outside the .mesh domain return NXDOMAIN.
// Queries for .mesh names with no matching peer return NXDOMAIN.
// The server also resolves the local node's hostname to its own VirtualIP.
package dns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// MeshDomain is the DNS suffix served by the mesh DNS server.
const MeshDomain = "mesh."

// PeerMetaProvider is the interface used to query the gossip layer for
// peer metadata. It returns the local node's metadata and all known
// peer metadata. The DNS server uses this to build the hostname→VirtualIP
// mapping.
type PeerMetaProvider interface {
	// LocalMeta returns the local node's NodeMeta (hostname, VirtualIP, etc).
	LocalMeta() *NodeMeta

	// KnownPeers returns metadata for all peers known via gossip.
	KnownPeers() []*NodeMeta
}

// NodeMeta is the metadata used by the DNS server. It is a subset of
// p2p.NodeMeta, containing only the fields needed for DNS resolution.
// This avoids an import cycle (dns package cannot import p2p directly).
type NodeMeta struct {
	Hostname  string
	VirtualIP string
}

// Server is the lightweight mesh DNS server.
type Server struct {
	provider PeerMetaProvider
	port     int
	server   *dns.Server
	mu       sync.Mutex
	started  bool
	stopCh   chan struct{}
	// upstream is an optional recursive resolver ("ip:port") for
	// non-.mesh queries. Empty = NXDOMAIN for everything outside .mesh.
	upstream string
}

// SetUpstream enables recursive forwarding for non-.mesh queries.
func (s *Server) SetUpstream(upstream string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstream = upstream
}

// NewServer creates a new mesh DNS server.
// The provider supplies peer metadata (hostname → VirtualIP) from the
// gossip layer. The port is the UDP port to listen on.
func NewServer(provider PeerMetaProvider, port int) *Server {
	return &Server{
		provider: provider,
		port:     port,
		stopCh:   make(chan struct{}),
	}
}

// Start begins listening for DNS queries on the configured UDP port.
// It returns an error if the server is already started or if binding fails.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("dns server already started")
	}
	s.mu.Unlock()

	mux := dns.NewServeMux()
	mux.HandleFunc(MeshDomain, s.handleMeshQuery)
	// Catch-all for non-.mesh queries → NXDOMAIN.
	mux.HandleFunc(".", s.handleNonMeshQuery)

	addr := fmt.Sprintf(":%d", s.port)
	s.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	// Start the server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.ListenAndServe()
	}()

	// Wait for either a successful start or an error.
	// We use a short timeout via Shutdown to detect binding failures.
	// miekg/dns doesn't have a "ready" channel, so we check the error
	// channel after a brief moment.
	select {
	case err := <-errCh:
		return fmt.Errorf("dns server failed to start on %s: %w", addr, err)
	case <-time.After(100 * time.Millisecond):
		// Server appears to be starting (no immediate error).
		// Give it a moment to bind.
	}

	s.mu.Lock()
	s.started = true
	s.mu.Unlock()

	log.Printf("[dns] server listening on %s (UDP, serving .mesh domain)", addr)
	return nil
}

// Stop gracefully shuts down the DNS server.
func (s *Server) Stop() {
	s.mu.Lock()
	if !s.started || s.server == nil {
		s.mu.Unlock()
		return
	}
	s.started = false
	s.mu.Unlock()

	if err := s.server.Shutdown(); err != nil {
		log.Printf("[dns] shutdown error: %v", err)
	}
}

// handleMeshQuery handles DNS queries for names in the .mesh domain.
// It extracts the hostname (the first label before .mesh), looks it up
// in the gossip peer metadata, and returns an A record with the VirtualIP.
func (s *Server) handleMeshQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	name := strings.ToLower(q.Name)

	switch q.Qtype {
	case dns.TypeA:
		ip := s.resolveHostname(name)
		if ip == nil {
			m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			break
		}
		// Only return A records for IPv4 addresses.
		if ip.To4() == nil {
			// IPv6 address — no A record, return NODATA.
			m.SetRcode(r, dns.RcodeSuccess)
			m.Ns = append(m.Ns, s.soaRecord(q.Name))
			break
		}
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			A: ip.To4(),
		}
		m.Answer = append(m.Answer, rr)

	case dns.TypeAAAA:
		ip := s.resolveHostname(name)
		if ip == nil {
			m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
			break
		}
		// Only return AAAA if the VirtualIP is IPv6.
		if ip.To4() != nil {
			// IPv4 address — no AAAA record, return NODATA.
			m.SetRcode(r, dns.RcodeSuccess)
			m.Ns = append(m.Ns, s.soaRecord(q.Name))
			break
		}
		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    30,
			},
			AAAA: ip,
		}
		m.Answer = append(m.Answer, rr)

	default:
		// For other query types, return NXDOMAIN with SOA.
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = append(m.Ns, s.soaRecord(q.Name))
	}

	w.WriteMsg(m)
}

// handleNonMeshQuery handles names outside .mesh. If recursive
// forwarding is enabled (Upstream != ""), the query is forwarded to the
// upstream resolver; otherwise NXDOMAIN is returned.
func (s *Server) handleNonMeshQuery(w dns.ResponseWriter, r *dns.Msg) {
	if s.upstream != "" {
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionDesired = true
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(r, s.upstream)
		if err != nil {
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		w.WriteMsg(resp)
		return
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
	w.WriteMsg(m)
}

// resolveHostname extracts the hostname from a .mesh DNS name and looks
// it up in the gossip peer metadata. Returns nil if not found.
//
// The name is expected to be in the form "<hostname>.mesh." (FQDN with
// trailing dot). The hostname is case-insensitive.
func (s *Server) resolveHostname(fqdn string) net.IP {
	hostname := extractHostname(fqdn)
	if hostname == "" {
		return nil
	}

	// Build the hostname → VirtualIP map from gossip metadata.
	entries := s.buildHostMap()

	ipStr, ok := entries[strings.ToLower(hostname)]
	if !ok {
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	// Return the IPv4 representation if it's an IPv4 address.
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// buildHostMap builds a map of lowercase hostname → VirtualIP from the
// gossip layer's peer metadata (including the local node).
func (s *Server) buildHostMap() map[string]string {
	entries := make(map[string]string)

	// Add local node.
	if meta := s.provider.LocalMeta(); meta != nil {
		if meta.Hostname != "" && meta.VirtualIP != "" {
			entries[strings.ToLower(meta.Hostname)] = meta.VirtualIP
		}
	}

	// Add all known peers.
	for _, meta := range s.provider.KnownPeers() {
		if meta == nil {
			continue
		}
		if meta.Hostname != "" && meta.VirtualIP != "" {
			entries[strings.ToLower(meta.Hostname)] = meta.VirtualIP
		}
	}

	return entries
}

// extractHostname extracts the hostname label from a .mesh FQDN.
// Input: "my-node.mesh." → Output: "my-node"
// Input: "my-node.mesh"  → Output: "my-node"
// Input: "MY-NODE.MESH." → Output: "MY-NODE"
// Returns empty string if the name is not a valid .mesh name.
func extractHostname(fqdn string) string {
	name := strings.TrimSuffix(fqdn, ".")
	if !strings.HasSuffix(strings.ToLower(name), ".mesh") {
		return ""
	}
	hostname := name[:len(name)-len(".mesh")]
	if hostname == "" {
		return ""
	}
	return hostname
}

// soaRecord creates a minimal SOA record for the .mesh zone.
func (s *Server) soaRecord(name string) dns.RR {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   MeshDomain,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns:      "ns.mesh.",
		Mbox:    "admin.mesh.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
}
