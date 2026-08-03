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

	// Allocate this node's VirtualIP. If we know the peer public keys
	// (from gossip), use AllocateWithPeers for conflict resolution.
	// Otherwise, allocate as a single-node mesh.
	pubKey := n.identity.PublicKey
	peerIPs := n.collectPeerVirtualIPs()
	hostCount := len(peerIPs) + 1

	virtualIP, err := alloc.AllocateWithPeers(pubKey, hostCount, peerIPs)
	if err != nil {
		dev.Close()
		return fmt.Errorf("tun: IPAM allocate: %w", err)
	}

	log.Printf("[mesh/tun] allocated VirtualIP %s (host_count=%d, peers=%d)",
		virtualIP, hostCount, len(peerIPs))

	// Step 3: Create router and set local IP.
	_, ipNet, _ := net.ParseCIDR(cfg.Mesh.MeshCIDR)
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

// SetTUNLocalVirtualIP propagates the local node's VirtualIP to the
// gossip layer. This is called from setupTUN after IPAM allocation.
// The actual gossip propagation is done via a callback set by main.go.
func (n *MeshNode) SetTUNLocalVirtualIP(virtualIP string) {
	n.mu.RLock()
	cb := n.virtualIPBroadcaster
	n.mu.RUnlock()

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

// configureTUNInterface configures the kernel network interface:
//   - ip addr add <ip>/<prefix> dev <ifName>
//   - ip link set up dev <ifName>
//   - ip route add <subnet> dev <ifName>  (on-link route for the mesh subnet)
func configureTUNInterface(ifName string, virtualIP net.IP, ipNet *net.IPNet, mtu int) error {
	// Set MTU.
	if mtu > 0 {
		cmd := exec.Command("ip", "link", "set", "mtu", fmt.Sprintf("%d", mtu), "dev", ifName)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[mesh/tun] ip link set mtu %d dev %s: %v: %s", mtu, ifName, err, strings.TrimSpace(string(output)))
		}
	}

	// Assign IP address.
	prefix, _ := ipNet.Mask.Size()
	addrStr := fmt.Sprintf("%s/%d", virtualIP.String(), prefix)
	cmd := exec.Command("ip", "addr", "add", addrStr, "dev", ifName)
	if output, err := cmd.CombinedOutput(); err != nil {
		// "File exists" is non-fatal — the address may already be set.
		if !strings.Contains(string(output), "File exists") {
			return fmt.Errorf("ip addr add %s dev %s: %w: %s", addrStr, ifName, err, strings.TrimSpace(string(output)))
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

	// Add on-link route for the mesh subnet (if not already present).
	// This makes the kernel route packets for the mesh subnet to the TUN.
	subnetStr := ipNet.String()
	cmd = exec.Command("ip", "route", "add", subnetStr, "dev", ifName)
	if output, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(output), "File exists") {
			log.Printf("[mesh/tun] ip route add %s dev %s: %v: %s (may already exist)",
				subnetStr, ifName, err, strings.TrimSpace(string(output)))
		}
	} else {
		log.Printf("[mesh/tun] added on-link route: %s dev %s", subnetStr, ifName)
	}

	return nil
}

// addKernelRoute adds a /32 route for a peer's VirtualIP:
// `ip route add <ip>/32 dev <ifName>`
func addKernelRoute(ifName string, ip net.IP) {
	args := []string{"route", "add", fmt.Sprintf("%s/32", ip.String()), "dev", ifName}
	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// "File exists" is non-fatal.
		if !strings.Contains(string(output), "File exists") {
			log.Printf("[mesh/tun] ip route add %s/32 dev %s: %v: %s",
				ip, ifName, err, strings.TrimSpace(string(output)))
		}
	}
}

// removeKernelRoute removes a /32 route for a peer's VirtualIP:
// `ip route del <ip>/32 dev <ifName>`
func removeKernelRoute(ifName string, ip net.IP) {
	args := []string{"route", "del", fmt.Sprintf("%s/32", ip.String()), "dev", ifName}
	cmd := exec.Command("ip", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Non-fatal — route may have already been removed.
		log.Printf("[mesh/tun] ip route del %s/32 dev %s: %v: %s",
			ip, ifName, err, strings.TrimSpace(string(output)))
	}
}
