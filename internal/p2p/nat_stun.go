package p2p

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/pion/stun/v3"
)

// NatType classifies a node's NAT behavior for traversal decisions.
// Values follow the naming from P2P_NETWORKING_SPEC.md §3.5.
type NatType string

const (
	NatTypeNone           NatType = "none"            // public IP, no NAT
	NatTypeFullCone       NatType = "full_cone"       // full-cone NAT (endpoint-independent)
	NatTypeRestricted     NatType = "restricted"      // restricted-cone NAT
	NatTypePortRestricted NatType = "port_restricted" // port-restricted-cone NAT
	NatTypeSymmetric      NatType = "symmetric"       // symmetric NAT (different mapped port per dest)
	NatTypeUnknown        NatType = "unknown"         // STUN failed or inconclusive
)

// EndpointDiscovery holds the result of a STUN discovery query.
type EndpointDiscovery struct {
	// MappedAddress is the server-reflexive (public) address discovered
	// via STUN, in "host:port" format.
	MappedAddress string

	// NatType is the classified NAT type.
	NatType NatType

	// Server is the STUN server that responded.
	Server string

	// LocalAddr is the local socket address used for the STUN query.
	LocalAddr string

	// NatMapping describes the mapping behavior (endpoint-independent /
	// endpoint-dependent) discovered by probing multiple destinations.
	NatMapping string
}

// StunClient queries STUN servers to discover the node's public endpoint
// and classify NAT type. It implements §3.5 of the P2P networking spec.
//
// The client queries each configured STUN server in order and uses the
// first successful response. For NAT classification, it queries two
// servers and compares the mapped addresses:
//   - If both return the same mapped address → full_cone (or restricted)
//   - If different mapped ports → symmetric NAT
//   - If only one responds → unknown (conservative fallback)
type StunClient struct {
	servers []string
	timeout time.Duration
}

// NewStunClient creates a STUN client with the given server list.
// If servers is empty, default public STUN servers are used.
func NewStunClient(servers []string, timeout time.Duration) *StunClient {
	if len(servers) == 0 {
		servers = []string{
			"stun.l.google.com:19302",
			"stun.cloudflare.com:3478",
		}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &StunClient{
		servers: servers,
		timeout: timeout,
	}
}

// Discover queries STUN servers to find the node's public endpoint.
// Discover performs NAT discovery and type classification (T0.4).
//
// Mapping-behavior probe: one UDP socket sends Binding Requests to
// MULTIPLE distinct STUN targets. If the NAT maps the same local
// (IP,port) to the same public port regardless of destination, the
// mapping is endpoint-independent (full-cone/restricted candidates).
// Different mapped ports per destination ⇒ endpoint-dependent mapping
// (symmetric or port-restricted behavior).
func (sc *StunClient) Discover() (*EndpointDiscovery, error) {
	if len(sc.servers) == 0 {
		return nil, fmt.Errorf("no STUN servers configured")
	}

	// Open ONE socket and query all servers through it.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("stun: listen: %w", err)
	}
	defer conn.Close()

	var results []*EndpointDiscovery
	for _, srv := range sc.servers {
		d, err := sc.queryServerConn(conn, srv)
		if err == nil && d != nil {
			results = append(results, d)
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("all STUN servers unreachable")
	}

	first := results[0]
	natType := NatTypeUnknown
	if len(results) >= 2 {
		// Same local socket → compare mapped ports across destinations.
		mappedPorts := make(map[int]bool)
		for _, r := range results {
			if _, p, err := net.SplitHostPort(r.MappedAddress); err == nil {
				if port, err2 := strconv.Atoi(p); err2 == nil {
					mappedPorts[port] = true
				}
			}
		}
		if len(mappedPorts) == 1 {
			// Same mapped port for all destinations: endpoint-independent
			// mapping. Not symmetric (symmetric maps different ports per
			// destination). Distinguish full-cone vs restricted requires
			// an RFC5780 filtering probe (CHANGE-REQUEST) which most
			// public STUN servers don't support — classify as restricted
			// (conservative) unless we can prove otherwise.
			natType = NatTypeRestricted
		} else {
			// Different mapped ports per destination → endpoint-dependent
			// mapping (symmetric behavior).
			natType = NatTypeSymmetric
		}
	}

	// No NAT (public IP, local == mapped).
	if first.LocalAddr == first.MappedAddress {
		natType = NatTypeNone
	}

	first.NatType = natType
	first.NatMapping = classifyMapping(results)
	return first, nil
}

// classifyMapping returns a human-readable mapping-behavior label.
func classifyMapping(results []*EndpointDiscovery) string {
	if len(results) < 2 {
		return "unknown"
	}
	ports := make(map[int]bool)
	for _, r := range results {
		if _, p, err := net.SplitHostPort(r.MappedAddress); err == nil {
			if port, err2 := strconv.Atoi(p); err2 == nil {
				ports[port] = true
			}
		}
	}
	if len(ports) == 1 {
		return "endpoint-independent"
	}
	return "endpoint-dependent"
}

// queryServerConn sends a Binding Request through the given socket to
// the server and returns the mapped address.
func (sc *StunClient) queryServerConn(conn *net.UDPConn, serverAddr string) (*EndpointDiscovery, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", serverAddr, err)
	}

	conn.SetDeadline(time.Now().Add(sc.timeout))

	msg, err := stun.Build(stun.BindingRequest, stun.TransactionID)
	if err != nil {
		return nil, fmt.Errorf("build STUN request: %w", err)
	}
	if _, err := conn.WriteToUDP(msg.Raw, udpAddr); err != nil {
		return nil, fmt.Errorf("write STUN request: %w", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read STUN response: %w", err)
	}

	var resp stun.Message
	if err := stun.Decode(buf[:n], &resp); err != nil {
		return nil, fmt.Errorf("decode STUN response: %w", err)
	}

	var xorAddr stun.XORMappedAddress
	var mappedAddr stun.MappedAddress
	var publicAddr string
	if err := xorAddr.GetFrom(&resp); err == nil {
		publicAddr = fmt.Sprintf("%s:%d", xorAddr.IP, xorAddr.Port)
	} else if err := mappedAddr.GetFrom(&resp); err == nil {
		publicAddr = fmt.Sprintf("%s:%d", mappedAddr.IP, mappedAddr.Port)
	} else {
		return nil, fmt.Errorf("no mapped address in STUN response from %s", serverAddr)
	}

	localAddr := conn.LocalAddr().String()
	return &EndpointDiscovery{
		Server:        serverAddr,
		LocalAddr:     localAddr,
		MappedAddress: publicAddr,
		NatType:       NatTypeUnknown,
	}, nil
}

// queryServer sends a STUN Binding Request to the given server and
// returns the mapped address (server-reflexive endpoint).
func (sc *StunClient) queryServer(serverAddr string) (*EndpointDiscovery, error) {
	// Resolve the server address.
	udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", serverAddr, err)
	}

	// Open a UDP socket.
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", serverAddr, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(sc.timeout))

	// Build and send STUN Binding Request.
	msg, err := stun.Build(stun.BindingRequest, stun.TransactionID)
	if err != nil {
		return nil, fmt.Errorf("build STUN request: %w", err)
	}

	if _, err := conn.Write(msg.Raw); err != nil {
		return nil, fmt.Errorf("write STUN request: %w", err)
	}

	// Read response.
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read STUN response: %w", err)
	}

	// Parse STUN response.
	var resp stun.Message
	if err := stun.Decode(buf[:n], &resp); err != nil {
		return nil, fmt.Errorf("decode STUN response: %w", err)
	}

	// Extract XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS.
	var xorAddr stun.XORMappedAddress
	var mappedAddr stun.MappedAddress

	var publicAddr string
	if err := xorAddr.GetFrom(&resp); err == nil {
		publicAddr = fmt.Sprintf("%s:%d", xorAddr.IP, xorAddr.Port)
	} else if err := mappedAddr.GetFrom(&resp); err == nil {
		publicAddr = fmt.Sprintf("%s:%d", mappedAddr.IP, mappedAddr.Port)
	} else {
		return nil, fmt.Errorf("no mapped address in STUN response from %s", serverAddr)
	}

	localAddr := conn.LocalAddr().String()

	return &EndpointDiscovery{
		MappedAddress: publicAddr,
		Server:        serverAddr,
		LocalAddr:     localAddr,
	}, nil
}

// classifyNat determines the NAT type by comparing mapped addresses
// from two different STUN servers.
//
// Per RFC 5780:
//   - If both servers return the same mapped address (same IP:port),
//     the NAT is either full_cone or restricted (we conservatively
//     call it full_cone since hole-punching will work either way).
//   - If the mapped IP is the same but the port differs, the NAT is
//     symmetric (different mapping per destination).
func classifyNat(first, second *EndpointDiscovery) NatType {
	if first.MappedAddress == second.MappedAddress {
		return NatTypeFullCone
	}

	// Compare IPs — if same IP but different port → symmetric.
	firstHost, firstPort, _ := net.SplitHostPort(first.MappedAddress)
	secondHost, secondPort, _ := net.SplitHostPort(second.MappedAddress)

	if firstHost == secondHost && firstPort != secondPort {
		return NatTypeSymmetric
	}

	// Different IPs could mean a dual-stack NAT or carrier-grade NAT.
	// Conservative: treat as symmetric (hole-punching unlikely to work).
	if firstHost != secondHost {
		return NatTypeSymmetric
	}

	return NatTypeUnknown
}

// isPublicIP returns true if the given IP address is publicly routable
// (not in RFC 1918 private ranges or other reserved blocks).
func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check private/reserved ranges.
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsUnspecified() {
		return false // 0.0.0.0 or ::
	}

	if ip4 := ip.To4(); ip4 != nil {
		// RFC 1918 private ranges.
		switch {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		case ip4[0] == 169 && ip4[1] == 254:
			return false // link-local
		case ip4[0] == 127:
			return false // loopback
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return false // CGNAT range (RFC 6598)
		}
	}

	return true
}

// safeShortKey returns the first 8 characters of a key, or the full
// key if shorter. Used for logging without risking slice bounds panic.
func safeShortKey(key string) string {
	if len(key) > 8 {
		return key[:8]
	}
	return key
}

// CanHolePunch returns true if the NAT type supports UDP hole-punching.
// Symmetric NAT on both sides makes direct connection impossible.
func CanHolePunch(localNat, remoteNat NatType) bool {
	if localNat == NatTypeSymmetric && remoteNat == NatTypeSymmetric {
		return false // both symmetric → must use relay
	}
	if localNat == NatTypeNone || remoteNat == NatTypeNone {
		return true // public IP on either side → direct works
	}
	if localNat == NatTypeSymmetric || remoteNat == NatTypeSymmetric {
		// One side symmetric — hole-punch may work if the non-symmetric
		// side initiates. We attempt it and fall back to relay on failure.
		return true
	}
	return true // full_cone, restricted, port_restricted → hole-punch works
}
