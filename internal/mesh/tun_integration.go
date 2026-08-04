package mesh

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/ipam"
	"github.com/yzy806806/meshdesk/internal/tun"
)

// TUNIntegration holds the TUN-related subsystems for a MeshNode.
// When non-nil, the node has a TUN device, IPAM allocator, router,
// route manager, and forwarder active.
type TUNIntegration struct {
	// Device is the open TUN device.
	Device *tun.Device

	// Allocator is the IPAM deterministic allocator.
	Allocator *ipam.Allocator

	// Router is the VirtualIP → PublicKey routing table.
	Router *tun.Router

	// RouteManager manages kernel routing table entries for subnet proxies.
	RouteManager *tun.RouteManager

	// Forwarder is the TUN packet transceive loop.
	Forwarder *TunForwarder

	// VirtualIP is this node's assigned TUN IP.
	VirtualIP net.IP

	// IfName is the TUN interface name (e.g. "mesh0").
	IfName string
}

// setupTUN creates and configures the TUN device, IPAM allocator, router,
// route manager, and TUN forwarder. It is called from Start() when
// cfg.Mesh.TunEnabled is true.
//
// Steps:
//  1. Create TUN device (tun.Create)
//  2. Create IPAM Allocator, allocate VirtualIP using KnownPeers
//  3. Create Router, SetLocalIP
//  4. Create RouteManager for kernel route management
//  5. Create TunForwarder, Start()
//  6. Configure kernel interface: ip addr add, ip link set up, ip route add
func (n *MeshNode) setupTUN() error {
	cfg := n.cfg

	// Validate config.
	if cfg.Mesh.MeshCIDR == "" {
		return fmt.Errorf("tun: mesh_cidr is required when tun_enabled is true")
	}

	// Detect subnet conflicts BEFORE creating the TUN device.
	// This checks whether any existing interface (e.g., EasyTier's tun0)
	// has an IP in the same subnet as mesh_cidr. If so, the kernel routing
	// table would have competing routes for the same subnet.
	// We log a prominent warning but do NOT block startup — the route
	// metric 0 fix in configureTUNInterface should handle the conflict.
	conflicts := detectSubnetConflict(cfg.Mesh.MeshCIDR)
	if len(conflicts) > 0 {
		log.Printf("[mesh/tun] WARNING: mesh_cidr %s overlaps with existing interface(s): %s",
			cfg.Mesh.MeshCIDR, strings.Join(conflicts, ", "))
		log.Printf("[mesh/tun] WARNING: route metric 0 will be used to prioritize mesh0, but consider using a non-overlapping mesh_cidr to avoid ambiguity")
	}

	mtu := cfg.Mesh.TunMTU
	if mtu == 0 {
		mtu = config.DefaultTunMTU
	}

	ifName := cfg.Mesh.TunName
	if ifName == "" {
		ifName = "mesh0"
	}

	// Step 1: Create the TUN device.
	dev, err := tun.Create(tun.Config{
		Name:   ifName,
		MTU:    mtu,
		Subnet: cfg.Mesh.MeshCIDR,
	})
	if err != nil {
		return fmt.Errorf("tun: create device: %w", err)
	}

	log.Printf("[mesh/tun] created TUN device %s (subnet=%s, mtu=%d)",
		dev.Name(), cfg.Mesh.MeshCIDR, mtu)

	// Step 2: Create IPAM allocator.
	alloc, err := ipam.NewAllocator(cfg.Mesh.MeshCIDR)
	if err != nil {
		dev.Close()
		return fmt.Errorf("tun: create IPAM allocator: %w", err)
	}

	_, ipNet, err := net.ParseCIDR(cfg.Mesh.MeshCIDR)
	if err != nil {
		dev.Close()
		return fmt.Errorf("tun: invalid mesh_cidr %q: %w", cfg.Mesh.MeshCIDR, err)
	}

	// Allocate this node's VirtualIP.
	//
	// If static_virtual_ip is set in config, use it directly (after
	// validating it's within mesh_cidr). This bypasses IPAM entirely,
	// which is essential for testing, predictable IP assignment in
	// small clusters, and working around IPAM conflicts.
	//
	// Otherwise, use IPAM with known peer IPs for deterministic
	// allocation and conflict resolution.
	pubKey := n.identity.PublicKey
	var virtualIP net.IP
	if cfg.Mesh.StaticVirtualIP != "" {
		staticIP := net.ParseIP(cfg.Mesh.StaticVirtualIP)
		if staticIP == nil {
			dev.Close()
			return fmt.Errorf("tun: invalid static_virtual_ip %q: not a valid IP address", cfg.Mesh.StaticVirtualIP)
		}
		if !ipNet.Contains(staticIP) {
			dev.Close()
			return fmt.Errorf("tun: static_virtual_ip %s is outside mesh_cidr %s", staticIP, cfg.Mesh.MeshCIDR)
		}
		virtualIP = staticIP
		log.Printf("[mesh/tun] using static VirtualIP %s (bypassing IPAM)", virtualIP)
	} else {
		peerIPs := n.collectPeerVirtualIPs()
		hostCount := len(peerIPs) + 1

		virtualIP, err = alloc.AllocateWithPeers(pubKey, hostCount, peerIPs)
		if err != nil {
			dev.Close()
			return fmt.Errorf("tun: IPAM allocate: %w", err)
		}

		log.Printf("[mesh/tun] allocated VirtualIP %s (host_count=%d, peers=%d)",
			virtualIP, hostCount, len(peerIPs))
	}

	// Step 3: Create router and set local IP.
	router := tun.NewRouter(ipNet, pubKey)
	router.SetLocalIP(virtualIP)

	// Step 4: Create route manager for subnet proxy kernel routes.
	routeMgr := tun.NewRouteManager(dev.Name())

	// If this node has its own subnet proxies, we don't need to add
	// kernel routes for them (they're local). The route manager is
	// used for OTHER peers' subnet proxies.

	// Step 5: Create and start the TUN forwarder.
	fwdCfg := TunForwarderConfig{
		Device:       dev,
		Router:       router,
		MeshNode:     n,
		RouteManager: routeMgr,
	}

	fwd, err := NewTunForwarder(fwdCfg)
	if err != nil {
		dev.Close()
		return fmt.Errorf("tun: create forwarder: %w", err)
	}

	if err := fwd.Start(); err != nil {
		dev.Close()
		return fmt.Errorf("tun: start forwarder: %w", err)
	}

	// Step 6: Configure kernel interface.
	// ip addr add <virtualIP>/<prefix> dev <ifName>
	if err := configureTUNInterface(dev.Name(), virtualIP, ipNet, mtu); err != nil {
		log.Printf("[mesh/tun] warning: kernel interface configuration failed: %v (packets will still flow via TUN fd)", err)
	}

	// Store the integration.
	n.mu.Lock()
	n.tunIntegration = &TUNIntegration{
		Device:       dev,
		Allocator:    alloc,
		Router:       router,
		RouteManager: routeMgr,
		Forwarder:    fwd,
		VirtualIP:    virtualIP,
		IfName:       dev.Name(),
	}
	n.mu.Unlock()

	// Propagate VirtualIP and subnet proxies to the gossip layer
	// (via callbacks set by main.go). This must happen AFTER
	// tunIntegration is stored so that the callbacks can access it.
	n.SetTUNLocalVirtualIP(virtualIP.String())
	if len(cfg.Mesh.SubnetProxy) > 0 {
		n.SetTUNSubnetProxies(cfg.Mesh.SubnetProxy)
	}

	log.Printf("[mesh/tun] TUN integration complete (ifname=%s, virtualIP=%s)",
		dev.Name(), virtualIP)

	return nil
}

// teardownTUN shuts down the TUN integration: stops the forwarder,
// closes the TUN device, and removes kernel routes.
func (n *MeshNode) teardownTUN() {
	n.mu.Lock()
	ti := n.tunIntegration
	n.tunIntegration = nil
	n.mu.Unlock()

	if ti == nil {
		return
	}

	// Stop the forwarder (closes outbound streams and listener).
	ti.Forwarder.Stop()

	// Remove kernel routes for peer VirtualIPs.
	router := ti.Router
	for ipStr, pubKey := range router.AllRoutes() {
		if router.IsSelf(pubKey) {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip != nil {
			removeKernelRoute(ti.IfName, ip)
		}
	}

	// Remove subnet proxy routes.
	if ti.RouteManager != nil {
		for cidr := range ti.RouteManager.AllSubnetProxies() {
			exec.Command("ip", "route", "del", cidr, "dev", ti.IfName).Run()
		}
	}

	// Close the TUN device (destroys the kernel interface).
	ti.Device.Close()

	log.Printf("[mesh/tun] TUN integration torn down (ifname=%s)", ti.IfName)
}

// collectPeerVirtualIPs gathers the VirtualIPs of all known peers from
// the gossip layer. This is used by setupTUN for IPAM conflict resolution.
//
// Since MeshNode cannot import the p2p package (import cycle), this
// method uses a callback registered by main.go. When the callback is
// not set (e.g., in tests), an empty map is returned.
func (n *MeshNode) collectPeerVirtualIPs() map[string]net.IP {
	n.mu.RLock()
	cb := n.peerMetaProvider
	n.mu.RUnlock()

	if cb == nil {
		return nil
	}

	peers := cb()
	result := make(map[string]net.IP, len(peers))
	for pubKey, vipStr := range peers {
		ip := net.ParseIP(vipStr)
		if ip != nil {
			result[pubKey] = ip
		}
	}
	return result
}

// SetPeerMetaProvider registers a callback that returns the current
// set of known peer public keys → VirtualIP strings. This is called
// by main.go to bridge the gossip layer (p2p package) with the TUN
// IPAM allocator (mesh package), avoiding an import cycle.
func (n *MeshNode) SetPeerMetaProvider(cb func() map[string]string) {
	n.mu.Lock()
	n.peerMetaProvider = cb
	n.mu.Unlock()
}

// TUNIntegration_ returns the active TUN integration, or nil if TUN
// is not enabled. This is used by main.go to access the router and
// route manager for gossip event wiring.
func (n *MeshNode) TUNIntegration() *TUNIntegration {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.tunIntegration
}

// GetTUNVirtualIP returns this node's TUN VirtualIP, or nil if TUN is
// not enabled or VirtualIP not yet assigned. Thread-safe.
func (n *MeshNode) GetTUNVirtualIP() net.IP {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.tunIntegration == nil {
		return nil
	}
	return n.tunIntegration.VirtualIP
}

// ReallocateAfterGossip re-runs IPAM allocation now that peer
// VirtualIPs are known via gossip. If this node's IP conflicts with
// a peer's and this node should yield (smaller pubkey wins), it
// finds a new VirtualIP, updates the kernel interface, and returns
// the new IP. Returns the VirtualIP (new or unchanged) and whether
// a change was made.
//
// This is called by main.go after gossip has started and peer
// VirtualIPs have been synced, fixing the chicken-and-egg problem
// where setupTUN runs before gossip is active.
func (n *MeshNode) ReallocateAfterGossip(peerIPs map[string]net.IP) (net.IP, bool) {
	n.mu.Lock()
	ti := n.tunIntegration
	if ti == nil || ti.Allocator == nil {
		n.mu.Unlock()
		return nil, false
	}

	// If static_virtual_ip is set, never reallocate.
	if n.cfg.Mesh.StaticVirtualIP != "" {
		log.Printf("[mesh/tun] ReallocateAfterGossip: skipping (static_virtual_ip=%s)", n.cfg.Mesh.StaticVirtualIP)
		return ti.VirtualIP, false
	}

	pubKey := n.identity.PublicKey
	hostCount := len(peerIPs) + 1
	newIP, err := ti.Allocator.AllocateWithPeers(pubKey, hostCount, peerIPs)
	if err != nil {
		log.Printf("[mesh/tun] ReallocateAfterGossip: AllocateWithPeers failed: %v", err)
		return ti.VirtualIP, false
	}

	if ti.VirtualIP != nil && newIP.Equal(ti.VirtualIP) {
		return ti.VirtualIP, false // No change needed
	}

	oldIP := ti.VirtualIP
	log.Printf("[mesh/tun] IPAM re-allocated: %s → %s (conflict resolved)", oldIP, newIP)

	// Update Router local IP.
	ti.Router.SetLocalIP(newIP)
	ti.VirtualIP = newIP
	n.mu.Unlock()

	// Update kernel: remove old IP, add new IP (outside lock).
	if oldIP != nil {
		removeKernelAddr(ti.IfName, oldIP, ti.Allocator.Subnet())
	}
	addKernelAddr(ti.IfName, newIP, ti.Allocator.Subnet())

	// Re-broadcast the new VirtualIP.
	n.SetTUNLocalVirtualIP(newIP.String())

	return newIP, true
}

// AddPeerVirtualIPRoute adds a kernel route for a peer's VirtualIP:
// `ip route add <peerVirtualIP>/32 dev <tun_ifname>`.
// Called when a peer with a VirtualIP joins via gossip.
func (n *MeshNode) AddPeerVirtualIPRoute(peerPubKey string, virtualIP string) {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()

	if ti == nil {
		return
	}

	ip := net.ParseIP(virtualIP)
	if ip == nil {
		log.Printf("[mesh/tun] invalid VirtualIP %q from peer %s, skipping route", virtualIP, shortKey(peerPubKey))
		return
	}

	// Add to the routing table (used by the forwarder for packet dispatch).
	ti.Router.AddRoute(ip, peerPubKey)

	// Add kernel route: ip route add <ip>/32 dev <ifName>
	addKernelRoute(ti.IfName, ip)

	log.Printf("[mesh/tun] added peer route: %s/32 dev %s (peer %s)",
		virtualIP, ti.IfName, shortKey(peerPubKey))
}

// RemovePeerVirtualIPRoute removes the kernel route for a peer's VirtualIP:
// `ip route del <peerVirtualIP>/32 dev <tun_ifname>`.
// Called when a peer leaves via gossip.
func (n *MeshNode) RemovePeerVirtualIPRoute(peerPubKey string) {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()

	if ti == nil {
		return
	}

	// Remove from the routing table.
	ip, ok := ti.Router.RemoveRoute(peerPubKey)
	if !ok {
		return
	}

	// Remove kernel route.
	removeKernelRoute(ti.IfName, ip)

	log.Printf("[mesh/tun] removed peer route: %s/32 dev %s (peer %s)",
		ip, ti.IfName, shortKey(peerPubKey))
}

// AddPeerSubnetProxies adds kernel routes for a peer's advertised subnet
// proxies: `ip route add <subnet> via <peerVirtualIP> dev <tun_ifname>`.
// Called when a peer with SubnetProxies joins or updates via gossip.
func (n *MeshNode) AddPeerSubnetProxies(peerPubKey, virtualIP string, subnets []string) {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()

	if ti == nil {
		return
	}

	ti.RouteManager.AddPeerSubnets(peerPubKey, virtualIP, subnets)
}

// RemovePeerSubnetProxies removes all kernel routes for a peer's
// advertised subnet proxies. Called when a peer leaves via gossip.
func (n *MeshNode) RemovePeerSubnetProxies(peerPubKey string) {
	n.mu.RLock()
	ti := n.tunIntegration
	n.mu.RUnlock()

	if ti == nil {
		return
	}

	ti.RouteManager.RemovePeerSubnets(peerPubKey)
}

// RemoveAllTUNRoutesForPeer removes both the peer's VirtualIP /32 route and
// all subnet proxy routes. This is the comprehensive cleanup that should be
// called when a peer is truly gone (smux session dead and reconnect exhausted),
// as opposed to a memberlist flap where the session is still alive.
func (n *MeshNode) RemoveAllTUNRoutesForPeer(peerPubKey string) {
	n.RemovePeerVirtualIPRoute(peerPubKey)
	n.RemovePeerSubnetProxies(peerPubKey)
}

// SetTUNLocalVirtualIP propagates the local node's VirtualIP to the
// gossip layer. This is called from setupTUN after IPAM allocation.
// The actual gossip propagation is done via a callback set by main.go.
func (n *MeshNode) SetTUNLocalVirtualIP(virtualIP string) {
	n.mu.RLock()
	cb := n.virtualIPBroadcaster
	n.mu.RUnlock()
	log.Printf("[mesh/tun] SetTUNLocalVirtualIP: vip=%s, broadcaster=%v", virtualIP, cb != nil)

	if cb != nil {
		cb(virtualIP)
	}
}

// SetVirtualIPBroadcaster registers a callback to propagate the local
// node's VirtualIP to the gossip layer. main.go wires this to
// gossipLayer.SetLocalVirtualIP.
func (n *MeshNode) SetVirtualIPBroadcaster(cb func(string)) {
	n.mu.Lock()
	n.virtualIPBroadcaster = cb
	n.mu.Unlock()
}

// SetTUNSubnetProxies propagates the local node's subnet proxies to
// the gossip layer. Called from setupTUN.
func (n *MeshNode) SetTUNSubnetProxies(subnets []string) {
	n.mu.RLock()
	cb := n.subnetProxyBroadcaster
	n.mu.RUnlock()

	if cb != nil {
		cb(subnets)
	}
}

// SetSubnetProxyBroadcaster registers a callback to propagate the local
// node's subnet proxies to the gossip layer. main.go wires this to
// gossipLayer.SetLocalSubnetProxies.
func (n *MeshNode) SetSubnetProxyBroadcaster(cb func([]string)) {
	n.mu.Lock()
	n.subnetProxyBroadcaster = cb
	n.mu.Unlock()
}

// removeKernelAddr removes an IP address from a kernel interface.
// The prefix length must match what was used when the address was added
// (i.e. the mesh CIDR prefix), because Linux matches addresses by both
// IP and prefix length — using /32 when the address was added as /24
// results in "Address not found".
func removeKernelAddr(ifName string, ip net.IP, ipNet *net.IPNet) {
	prefix, _ := ipNet.Mask.Size()
	addrStr := fmt.Sprintf("%s/%d", ip.String(), prefix)
	cmd := exec.Command("ip", "addr", "del", addrStr, "dev", ifName)
	if output, err := cmd.CombinedOutput(); err != nil {
		// "Cannot assign requested address" and "Address not found" are
		// both non-fatal — the address may have already been removed or
		// never assigned (e.g. prefix mismatch from a previous version).
		out := string(output)
		if !strings.Contains(out, "Cannot assign requested address") &&
			!strings.Contains(out, "Address not found") {
			log.Printf("[mesh/tun] ip addr del %s dev %s: %v: %s",
				addrStr, ifName, err, strings.TrimSpace(out))
		}
	}
}

// addrWithPrefix formats an IP address with the prefix length from the
// given IPNet, e.g. ("10.100.0.1", /24) → "10.100.0.1/24".
func addrWithPrefix(ip net.IP, ipNet *net.IPNet) string {
	prefix, _ := ipNet.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), prefix)
}

// addKernelAddr adds an IP address to a kernel interface.
func addKernelAddr(ifName string, ip net.IP, ipNet *net.IPNet) {
	addrStr := addrWithPrefix(ip, ipNet)
	cmd := exec.Command("ip", "addr", "add", addrStr, "dev", ifName)
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "File exists") {
			log.Printf("[mesh/tun] ip addr add %s dev %s: %v: %s",
				addrStr, ifName, err, strings.TrimSpace(string(output)))
		}
	}
}

// configureTUNInterface configures the kernel network interface:
//   - ip addr add <ip>/<prefix> dev <ifName>
//   - ip link set up dev <ifName>
//   - ip route replace <subnet> dev <ifName> metric 0  (on-link route for the mesh subnet)
//
// The on-link route uses `ip route replace` (not `add`) with metric 0 so
// that it takes priority over any existing route for the same subnet on
// another interface (e.g., EasyTier's tun0). Metric 0 is the highest
// priority in the kernel routing table — lower metric = higher priority.
func configureTUNInterface(ifName string, virtualIP net.IP, ipNet *net.IPNet, mtu int) error {
	// Set MTU.
	if mtu > 0 {
		cmd := exec.Command("ip", "link", "set", "mtu", fmt.Sprintf("%d", mtu), "dev", ifName)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[mesh/tun] ip link set mtu %d dev %s: %v: %s", mtu, ifName, err, strings.TrimSpace(string(output)))
		}
	}

	// Assign IP address.
	addrStr := addrWithPrefix(virtualIP, ipNet)
	cmd := exec.Command("ip", "addr", "add", addrStr, "dev", ifName)
	if output, err := cmd.CombinedOutput(); err != nil {
		out := string(output)
		// "File exists" and "Address already assigned" are non-fatal —
		// the address may already be set from a previous run or by the
		// kernel when the TUN device was created with the same subnet.
		if !strings.Contains(out, "File exists") && !strings.Contains(out, "Address already assigned") {
			return fmt.Errorf("ip addr add %s dev %s: %w: %s", addrStr, ifName, err, strings.TrimSpace(out))
		}
		log.Printf("[mesh/tun] ip addr add %s dev %s: already exists", addrStr, ifName)
	} else {
		log.Printf("[mesh/tun] assigned %s to %s", addrStr, ifName)
	}

	// Bring the interface up.
	cmd = exec.Command("ip", "link", "set", "up", "dev", ifName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up dev %s: %w: %s", ifName, err, strings.TrimSpace(string(output)))
	}
	log.Printf("[mesh/tun] interface %s is up", ifName)

	// Add on-link route for the mesh subnet with metric 0 (highest priority).
	// Use `ip route replace` instead of `ip route add` so that if another
	// interface (e.g., EasyTier's tun0) already has a route for the same
	// subnet, our route replaces it instead of failing with "File exists".
	// Metric 0 ensures the kernel prefers mesh0 over any competing route
	// with a higher metric.
	subnetStr := ipNet.String()
	cmd = exec.Command("ip", "route", "replace", subnetStr, "dev", ifName, "metric", "0")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[mesh/tun] ip route replace %s dev %s metric 0: %v: %s (may need manual intervention)",
			subnetStr, ifName, err, strings.TrimSpace(string(output)))
	} else {
		log.Printf("[mesh/tun] added on-link route: %s dev %s metric 0", subnetStr, ifName)
	}

	return nil
}

// detectSubnetConflict checks whether any existing kernel route or
// interface subnet overlaps with the mesh CIDR. This detects the
// scenario where another VPN (e.g., EasyTier) has already created a
// tun0 interface with a route for the same subnet as mesh_cidr.
//
// Returns a list of conflicting interface entries (each "dev <ifname>
// src <ip>") if conflicts are found, or nil if no conflict exists.
// The caller should log a prominent warning when conflicts are found.
func detectSubnetConflict(meshCIDR string) []string {
	_, meshNet, err := net.ParseCIDR(meshCIDR)
	if err != nil {
		return nil
	}

	// Run `ip -o addr show` to get all interface addresses in a
	// machine-readable format (one line per address).
	cmd := exec.Command("ip", "-o", "addr", "show")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If we can't check, don't block startup — just return nil.
		log.Printf("[mesh/tun] detectSubnetConflict: ip addr show failed: %v", err)
		return nil
	}

	var conflicts []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Parse `ip -o addr show` output format:
		// "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\"
		// We look for "inet <ip>/<prefix>" and check if the CIDR overlaps.
		inetIdx := strings.Index(line, "inet ")
		if inetIdx < 0 {
			continue
		}
		rest := line[inetIdx+5:] // skip "inet "
		spaceIdx := strings.Index(rest, " ")
		if spaceIdx < 0 {
			continue
		}
		addrCIDR := rest[:spaceIdx]
		// Skip link-local (169.254.x.x) and loopback (127.x.x.x) addresses.
		if strings.HasPrefix(addrCIDR, "169.254.") || strings.HasPrefix(addrCIDR, "127.") {
			continue
		}

		_, existingNet, err := net.ParseCIDR(addrCIDR)
		if err != nil {
			continue
		}

		// Check for overlap: two CIDRs overlap if either contains the
		// other's network address.
		if cidrOverlap(meshNet, existingNet) {
			// Extract the interface name from the line.
			// Format: "<ifindex>: <ifname>    inet ..."
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ifName := strings.TrimSuffix(parts[1], ":")
				// Skip our own mesh interface (in case of restart).
				if ifName == "mesh0" || strings.HasPrefix(ifName, "mesh") {
					continue
				}
				conflicts = append(conflicts, fmt.Sprintf("%s on %s", addrCIDR, ifName))
			}
		}
	}

	return conflicts
}

// cidrOverlap returns true if two CIDR subnets overlap (one contains
// the other's network address, or vice versa).
func cidrOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// addKernelRoute adds a /32 route for a peer's VirtualIP:
// `ip route add <ip>/32 dev <ifName> metric 0`
//
// Metric 0 ensures peer VirtualIP routes take priority over any
// competing subnet route on another interface (e.g., EasyTier's tun0
// with a route for the same /24 subnet). The /32 prefix already wins
// via longest-prefix-match, but adding metric 0 is belt-and-suspenders
// for environments where the competing route also has metric 0.
func addKernelRoute(ifName string, ip net.IP) {
	args := []string{"route", "add", fmt.Sprintf("%s/32", ip.String()), "dev", ifName, "metric", "0"}
	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// "File exists" is non-fatal.
		if !strings.Contains(string(output), "File exists") {
			log.Printf("[mesh/tun] ip route add %s/32 dev %s metric 0: %v: %s",
				ip, ifName, err, strings.TrimSpace(string(output)))
		}
	}
}

// removeKernelRoute removes a /32 route for a peer's VirtualIP:
// `ip route del <ip>/32 dev <ifName> metric 0`
//
// The metric 0 must be included in the delete to match the add —
// Linux matches routes by (prefix, dev, metric) tuple, so a delete
// without the metric would fail to remove the route.
func removeKernelRoute(ifName string, ip net.IP) {
	args := []string{"route", "del", fmt.Sprintf("%s/32", ip.String()), "dev", ifName, "metric", "0"}
	cmd := exec.Command("ip", args...)
	if _, err := cmd.CombinedOutput(); err != nil {
		// Non-fatal — route may have already been removed.
		// Try without metric as a fallback (for routes created by older versions).
		fallbackArgs := []string{"route", "del", fmt.Sprintf("%s/32", ip.String()), "dev", ifName}
		fbCmd := exec.Command("ip", fallbackArgs...)
		if fbOutput, fbErr := fbCmd.CombinedOutput(); fbErr != nil {
			log.Printf("[mesh/tun] ip route del %s/32 dev %s: %v: %s",
				ip, ifName, fbErr, strings.TrimSpace(string(fbOutput)))
		}
	}
}
