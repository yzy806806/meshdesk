package tun

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
)

// RouteManager manages kernel routing table entries for mesh subnet
// proxies. When a peer advertises subnet proxies (local CIDR subnets
// behind it), the RouteManager adds kernel routes directing traffic
// for those subnets through the TUN interface via the peer's VirtualIP.
//
// The RouteManager also maintains a reverse mapping (subnet → peer
// VirtualIP) that the TunForwarder uses to route non-mesh-subnet
// packets to the correct peer.
//
// All methods are safe for concurrent use.
type RouteManager struct {
	mu sync.Mutex

	// ifName is the TUN interface name (e.g. "mesh0") used in
	// `ip route add ... dev <ifName>` commands.
	ifName string

	// routes maps "peerPubKey" → set of advertised subnet CIDRs.
	// This is the authoritative state of what routes exist.
	routes map[string]map[string]bool // pubKey → CIDR set

	// subnetToPeer maps "CIDR" → peer VirtualIP (string form).
	// Used by the TunForwarder to look up the next-hop for a
	// destination IP that falls outside the mesh subnet.
	subnetToPeer map[string]string // CIDR → VirtualIP

	// subnetNets is the parsed *net.IPNet for each CIDR, used for
	// longest-prefix-match lookups.
	subnetNets map[string]*net.IPNet // CIDR → *net.IPNet

	// cmdRunner is the function used to execute `ip route` commands.
	// Defaults to execRouteCmd; overridable for testing.
	cmdRunner func(args ...string) error
}

// NewRouteManager creates a new RouteManager for the given TUN
// interface. The interface must already exist and be up.
func NewRouteManager(ifName string) *RouteManager {
	rm := &RouteManager{
		ifName:       ifName,
		routes:       make(map[string]map[string]bool),
		subnetToPeer: make(map[string]string),
		subnetNets:   make(map[string]*net.IPNet),
	}
	rm.cmdRunner = rm.execRouteCmd
	return rm
}

// AddPeerSubnets adds kernel routes for the given peer's advertised
// subnets. If the peer already had routes, old subnets that are no
// longer advertised are removed, and new ones are added.
//
// virtualIP is the peer's TUN VirtualIP (next-hop gateway).
// pubKey is the peer's public key (used as a stable identifier).
// subnets is the list of CIDR strings the peer advertises.
func (rm *RouteManager) AddPeerSubnets(pubKey, virtualIP string, subnets []string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	oldSubnets := rm.routes[pubKey]
	newSubnets := make(map[string]bool, len(subnets))

	for _, cidr := range subnets {
		// Validate the CIDR.
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[route-mgr] invalid CIDR %q from peer %s: %v", cidr, shortHex(pubKey), err)
			continue
		}
		newSubnets[cidr] = true

		// If this subnet was not previously routed, add it.
		if !oldSubnets[cidr] {
			// Check if another peer already claims this subnet.
			if existingGW, exists := rm.subnetToPeer[cidr]; exists && existingGW != virtualIP {
				// Conflict: another peer already routes this subnet.
				// Last writer wins — replace the old route.
				log.Printf("[route-mgr] subnet %s re-assigned from %s to %s (peer %s)",
					cidr, existingGW, virtualIP, shortHex(pubKey))
				rm.delKernelRoute(cidr)
			}

			rm.subnetToPeer[cidr] = virtualIP
			rm.subnetNets[cidr] = ipNet
			rm.addKernelRoute(cidr, virtualIP)
		}
	}

	// Remove old subnets that are no longer advertised.
	for cidr := range oldSubnets {
		if !newSubnets[cidr] {
			rm.delKernelRoute(cidr)
			delete(rm.subnetToPeer, cidr)
			delete(rm.subnetNets, cidr)
		}
	}

	rm.routes[pubKey] = newSubnets

	log.Printf("[route-mgr] peer %s: %d subnet proxies via %s",
		shortHex(pubKey), len(newSubnets), virtualIP)
}

// RemovePeerSubnets removes all kernel routes for the given peer.
// Called when a peer leaves the mesh or its TUN goes down.
func (rm *RouteManager) RemovePeerSubnets(pubKey string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	subnets, ok := rm.routes[pubKey]
	if !ok {
		return
	}

	for cidr := range subnets {
		rm.delKernelRoute(cidr)
		delete(rm.subnetToPeer, cidr)
		delete(rm.subnetNets, cidr)
	}

	delete(rm.routes, pubKey)

	log.Printf("[route-mgr] peer %s: removed %d subnet proxy routes",
		shortHex(pubKey), len(subnets))
}

// ResolveSubnetProxy performs a longest-prefix-match lookup for the
// given destination IP against all advertised subnet proxies.
// Returns the peer VirtualIP (next-hop gateway) and true if a match
// is found, empty string and false otherwise.
//
// This is used by the TunForwarder to route packets destined outside
// the mesh subnet (e.g. to 192.168.1.5) to the correct peer.
func (rm *RouteManager) ResolveSubnetProxy(dstIP net.IP) (string, bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var bestMatch string
	var bestPrefixLen int = -1

	for cidr, ipNet := range rm.subnetNets {
		if ipNet.Contains(dstIP) {
			ones, _ := ipNet.Mask.Size()
			if ones > bestPrefixLen {
				bestPrefixLen = ones
				bestMatch = rm.subnetToPeer[cidr]
			}
		}
	}

	if bestMatch == "" {
		return "", false
	}
	return bestMatch, true
}

// AllSubnetProxies returns a snapshot of all current subnet proxy
// mappings (CIDR → peer VirtualIP). Used for diagnostics and status.
func (rm *RouteManager) AllSubnetProxies() map[string]string {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	result := make(map[string]string, len(rm.subnetToPeer))
	for cidr, gw := range rm.subnetToPeer {
		result[cidr] = gw
	}
	return result
}

// RouteCount returns the total number of active subnet proxy routes.
func (rm *RouteManager) RouteCount() int {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return len(rm.subnetToPeer)
}

// addKernelRoute adds a kernel route: `ip route add <cidr> via <gw> dev <ifName>`.
func (rm *RouteManager) addKernelRoute(cidr, gateway string) {
	args := []string{"route", "add", cidr, "via", gateway, "dev", rm.ifName}
	if err := rm.cmdRunner(args...); err != nil {
		// "RTNETLINK answers: File exists" is non-fatal — the route
		// may already exist from a previous run. Log but don't fail.
		log.Printf("[route-mgr] ip route add %s via %s dev %s: %v (may already exist)",
			cidr, gateway, rm.ifName, err)
	} else {
		log.Printf("[route-mgr] added route: %s via %s dev %s", cidr, gateway, rm.ifName)
	}
}

// delKernelRoute removes a kernel route: `ip route del <cidr> dev <ifName>`.
func (rm *RouteManager) delKernelRoute(cidr string) {
	args := []string{"route", "del", cidr, "dev", rm.ifName}
	if err := rm.cmdRunner(args...); err != nil {
		// Non-fatal — route may have already been removed.
		log.Printf("[route-mgr] ip route del %s dev %s: %v (may not exist)",
			cidr, rm.ifName, err)
	} else {
		log.Printf("[route-mgr] removed route: %s dev %s", cidr, rm.ifName)
	}
}

// execRouteCmd executes the `ip` command with the given arguments.
func (rm *RouteManager) execRouteCmd(args ...string) error {
	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

// shortHex returns the first 16 characters of a hex string for logging.
func shortHex(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "..."
}
