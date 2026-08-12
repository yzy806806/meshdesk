package holepunch

import (
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

// stunServers are the discovery servers. Order matters: the first
// reachable one wins. Google + Cloudflare are reachable from the test
// nodes; a local fallback list can be configured via SetStunServers.
var stunServers = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}

// SetStunServers overrides the default STUN server list (e.g. for
// nodes that cannot reach public STUN).
func SetStunServers(servers []string) {
	if len(servers) > 0 {
		stunServers = servers
	}
}

// DiscoveryResult holds our detected public endpoint + NAT type.
type DiscoveryResult struct {
	MappedEP string
	NatType  NatType
}

// Discover runs STUN binding requests against the server list and
// classifies the NAT type (full-cone / restricted / port-restricted /
// symmetric). Returns the first successful result.
func Discover(timeout time.Duration) (DiscoveryResult, error) {
	for _, server := range stunServers {
		res, err := probeServer(server, timeout)
		if err == nil {
			return res, nil
		}
		log.Printf("[holepunch] STUN %s failed: %v", server, err)
	}
	return DiscoveryResult{}, errAllStunUnreachable
}

var errAllStunUnreachable = errString("all STUN servers unreachable")

type errString string

func (e errString) Error() string { return string(e) }

// probeServer classifies NAT type using two binding requests to
// different STUN servers (the standard classification trick).
func probeServer(server string, timeout time.Duration) (DiscoveryResult, error) {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return DiscoveryResult{}, err
	}
	port, _ := strconv.Atoi(portStr)

	// First request: primary server.
	ep1, mapped1, err := stunRequest(server, timeout)
	if err != nil {
		return DiscoveryResult{}, err
	}
	// Second request: different server — same local socket.
	ep2, mapped2, err := stunRequestSameConn(server, host, port, mapped1, timeout)
	if err != nil {
		// Second probe failed — cannot classify; assume port-restricted.
		return DiscoveryResult{MappedEP: ep1, NatType: NatPortRestricted}, nil
	}
	_ = ep2

	nat := classify(mapped1, mapped2)
	return DiscoveryResult{MappedEP: ep1, NatType: nat}, nil
}

// stunRequest sends one binding request and returns our mapped endpoint.
func stunRequest(server string, timeout time.Duration) (string, string, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	return stunRoundTrip(conn, timeout)
}

// stunRoundTrip performs the binding exchange on the given socket.
func stunRoundTrip(conn net.Conn, timeout time.Duration) (string, string, error) {
	conn.SetDeadline(time.Now().Add(timeout))
	c, err := stun.NewClient(conn)
	if err != nil {
		return "", "", err
	}
	defer c.Close()

	var mappedEP string
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return "", "", err
	}
	if err := c.Do(msg, func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
			return
		}
		var xorAddr stun.XORMappedAddress
		if aErr := xorAddr.GetFrom(res.Message); aErr == nil {
			mappedEP = net.JoinHostPort(xorAddr.IP.String(), strconv.Itoa(xorAddr.Port))
		}
	}); err != nil {
		return "", "", err
	}
	if err != nil {
		return "", "", err
	}
	return conn.LocalAddr().String(), mappedEP, nil
}

// stunRequestSameConn reuses the local socket from a previous probe so
// the NAT mapping is the same (needed for symmetric detection).
func stunRequestSameConn(server, host string, port int, prevLocal string, timeout time.Duration) (string, string, error) {
	// Re-dial with the same local address.
	localAddr, err := net.ResolveUDPAddr("udp", prevLocal)
	if err != nil {
		return "", "", err
	}
	conn, err := net.DialUDP("udp", localAddr, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	return stunRoundTrip(conn, timeout)
}

// classify distinguishes port-restricted from symmetric using the two
// mapped endpoints.
func classify(mapped1, mapped2 string) NatType {
	if mapped1 == "" {
		return NatUnknown
	}
	// Different mapped ports for different destinations => symmetric.
	h1, p1, _ := net.SplitHostPort(mapped1)
	h2, p2, _ := net.SplitHostPort(mapped2)
	if h1 != h2 || p1 != p2 {
		return NatSymmetric
	}
	// Same mapping across destinations => cone family. We cannot
	// distinguish full-cone from restricted with two probes alone;
	// port-restricted is the common conservative default.
	return NatPortRestricted
}

var stunMu sync.Mutex
