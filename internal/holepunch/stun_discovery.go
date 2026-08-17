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
	// EasySym marks a symmetric NAT with a predictable port increment
	// (NAT4E): EasyTier-style port prediction can punch through it.
	EasySym bool
	// Inc is the per-flow mapped-port increment direction: +1 if the
	// NAT assigns increasing ports, -1 if decreasing, 0 unknown.
	Inc int
}

// Discover runs STUN binding requests against the server list and
// classifies the NAT type (full-cone / restricted / port-restricted /
// symmetric). Returns the first successful result.
func Discover(timeout time.Duration) (DiscoveryResult, error) {
	return DiscoverFrom(0, timeout)
}

// DiscoverFrom is Discover with a fixed local source port (e.g. the
// mesh port). The mapped endpoint then corresponds to the same NAT
// mapping the TUN UDP path (DialTUNUDP from the mux socket) uses —
// hole-punching from this port makes the hole reusable by the data
// plane. port 0 = ephemeral.
func DiscoverFrom(port int, timeout time.Duration) (DiscoveryResult, error) {
	for _, server := range stunServers {
		res, err := probeServer(server, port, timeout)
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
func probeServer(server string, srcPort int, timeout time.Duration) (DiscoveryResult, error) {
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return DiscoveryResult{}, err
	}
	port, _ := strconv.Atoi(portStr)

	// First request: primary server, bound to srcPort if requested.
	_, mapped1, localPort, err := stunRequest(server, srcPort, timeout)
	if err != nil {
		return DiscoveryResult{}, err
	}
	// Second request: different server — same local socket/port.
	ep2, mapped2, err := stunRequestSameConn(server, host, port, localPort, timeout)
	if err != nil {
		// Second probe failed — cannot classify; assume port-restricted.
		return DiscoveryResult{MappedEP: mapped1, NatType: NatPortRestricted}, nil
	}
	_ = ep2

	// Third request: another destination (server 3) for EasySymmetric
	// increment detection — the mapped port sequence across
	// destinations reveals NAT4E (predictable increment).
	var nat NatType = classify(mapped1, mapped2)
	easySym, inc := false, 0
	{
		altServer := ""
		for _, srv := range stunServers {
			if srv != server {
				altServer = srv
				break
			}
		}
		if altServer != "" {
			ah, aportStr, _ := net.SplitHostPort(altServer)
			aport, _ := strconv.Atoi(aportStr)
			_, mapped3, err3 := stunRequestSameConn(altServer, ah, aport, localPort, timeout)
			if err3 == nil {
				nat, easySym, inc = classify3(mapped1, mapped2, mapped3)
			}
		}
	}
	return DiscoveryResult{MappedEP: mapped1, NatType: nat, EasySym: easySym, Inc: inc}, nil
}

// stunRequest sends one binding request and returns our mapped endpoint
// plus the local port used (for the second same-port probe).
func stunRequest(server string, srcPort int, timeout time.Duration) (string, string, int, error) {
	var local *net.UDPAddr
	if srcPort > 0 {
		local = &net.UDPAddr{Port: srcPort}
	}
	conn, err := net.DialUDP("udp", local, mustUDPAddr(server))
	if err != nil {
		return "", "", 0, err
	}
	defer conn.Close()
	la := conn.LocalAddr().(*net.UDPAddr)
	ep, mapped, err := stunRoundTrip(conn, timeout)
	return ep, mapped, la.Port, err
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

// stunRequestSameConn reuses the local port from the first probe so
// the NAT mapping is the same (needed for symmetric detection).
func stunRequestSameConn(server, host string, port, srcPort int, timeout time.Duration) (string, string, error) {
	var local *net.UDPAddr
	if srcPort > 0 {
		local = &net.UDPAddr{Port: srcPort}
	}
	conn, err := net.DialUDP("udp", local, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	return stunRoundTrip(conn, timeout)
}

// classify distinguishes port-restricted from symmetric using the two
// mapped endpoints; the third probe detects an EasySymmetric increment.
func classify3(mapped1, mapped2, mapped3 string) (NatType, bool, int) {
	nat := classify(mapped1, mapped2)
	if nat != NatSymmetric {
		return nat, false, 0
	}
	// Symmetric: check whether the per-destination port increments
	// predictably across two different destinations (NAT4E).
	_, p1, _ := net.SplitHostPort(mapped1)
	_, p2, _ := net.SplitHostPort(mapped2)
	_, p3, _ := net.SplitHostPort(mapped3)
	a, b, c := atoiSafe(p1), atoiSafe(p2), atoiSafe(p3)
	if a == 0 || b == 0 || c == 0 {
		return nat, false, 0
	}
	d1, d2 := b-a, c-b
	if d1 != 0 && d1 == d2 {
		inc := 1
		if d1 < 0 {
			inc = -1
		}
		return nat, true, inc
	}
	return nat, false, 0
}

func atoiSafe(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
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
