// Package p2p implements dynamic peer discovery, metadata propagation, and
// WireGuard peer management for the MeshDesk mesh VPN.
//
// This package implements the Gossip Layer (§1) and WireGuard Delegate (§2)
// of the P2P Dynamic Networking Architecture. It uses hashicorp/memberlist
// for epidemic-style peer discovery and failure detection, with a custom
// delegate that carries MeshDesk-specific node metadata (capabilities, load
// metrics, endpoints) via MessagePack serialization.
//
// The gossip layer runs ON TOP OF the existing WireGuard mesh — memberlist
// uses TCP via the gVisor netstack, so gossip traffic is encrypted by
// WireGuard and works through NAT via relayed connections.
package p2p

import (
	"github.com/yzy806806/meshdesk/internal/config"
)

// P2pConfig holds the configuration for the P2P dynamic networking layer.
// It maps to the `p2p` section in config.yaml.
type P2pConfig struct {
	// Enabled controls whether dynamic P2P networking is active.
	// When false, the node uses static peers only (backward compat).
	Enabled bool `yaml:"enabled,omitempty"`

	// Seeds is the list of known mesh IP:gossip_port addresses used to
	// bootstrap the gossip cluster. At least one is required when Enabled
	// is true and no static peers are configured.
	Seeds []string `yaml:"seeds,omitempty"`

	// NatTraversal enables STUN discovery and UDP hole-punching.
	// Default: true.
	NatTraversal bool `yaml:"nat_traversal,omitempty"`

	// StunServers is the list of STUN server addresses for NAT discovery.
	// Defaults to Google and Cloudflare public STUN servers.
	StunServers []string `yaml:"stun_servers,omitempty"`

	// RelayMode controls how relay fallback is handled:
	//   "auto"     — automatically select relay peers (default)
	//   "manual"   — use only manually configured relay peers
	//   "disabled" — no relay fallback (direct-only)
	RelayMode string `yaml:"relay_mode,omitempty"`

	// MaxRelayHops is the maximum number of relay hops for relayed
	// connections. Default: 2.
	MaxRelayHops int `yaml:"max_relay_hops,omitempty"`

	// JoinApproval controls the authentication mode for new nodes:
	//   "auto"   — pre-authorized key list (authorized_keys)
	//   "manual" — admin approval via dashboard
	JoinApproval string `yaml:"join_approval,omitempty"`

	// AuthorizedKeys is the list of WireGuard public keys (hex) that are
	// pre-authorized to join the mesh. Used when JoinApproval is "auto".
	AuthorizedKeys []string `yaml:"authorized_keys,omitempty"`

	// GossipInterval is the PushPull interval in seconds (state sync).
	// Default: 30.
	GossipInterval int `yaml:"gossip_interval,omitempty"`

	// GossipProbeInterval is the probe interval in seconds (health check).
	// Default: 1.
	GossipProbeInterval int `yaml:"gossip_probe_interval,omitempty"`

	// DirectReprobeInterval is the interval in seconds between direct
	// re-probe attempts when in relay fallback mode. Default: 120.
	DirectReprobeInterval int `yaml:"direct_reprobe_interval,omitempty"`

	// MaxPeers is the hard limit on total peers. Default: 256.
	MaxPeers int `yaml:"max_peers,omitempty"`

	// GossipBindAddr is the bind address for the memberlist NetTransport.
	// Default: "0.0.0.0" (all interfaces).
	GossipBindAddr string `yaml:"gossip_bind_addr,omitempty"`

	// GossipPort is the TCP port for memberlist gossip.
	// Default: 7946.
	GossipPort int `yaml:"gossip_port,omitempty"`

	// WgPort is the WireGuard UDP listen port. Used to proactively announce
	// a local endpoint (localIP:WgPort) so peers have a candidate address to
	// try before reactive endpoint learning kicks in. Default: 51820.
	WgPort int `yaml:"-"`

	// AdvertiseEndpoints is a list of explicit endpoints (host:port) that
	// this node advertises to peers via gossip. When set, they override
	// auto-detection. Use this when the node is behind NAT and you know the
	// public IP:port mapping, or when auto-detection would pick the wrong
	// interface. Multiple endpoints are useful for dual-stack IPv4/IPv6 nodes.
	AdvertiseEndpoints []string `yaml:"advertise_endpoints,omitempty"`
}

// DefaultP2pConfig returns a P2pConfig with sensible defaults.
func DefaultP2pConfig() P2pConfig {
	return P2pConfig{
		Enabled:               false,
		Seeds:                 nil,
		NatTraversal:          true,
		StunServers:           []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"},
		RelayMode:             "auto",
		MaxRelayHops:          2,
		JoinApproval:          "auto",
		AuthorizedKeys:        nil,
		GossipInterval:        30,
		GossipProbeInterval:   1,
		DirectReprobeInterval: 120,
		MaxPeers:              256,
		GossipBindAddr:        "0.0.0.0",
		GossipPort:            7946,
	}
}

// FromConfig converts a config.P2pConfig (from the config package) to a
// p2p.P2pConfig (internal to this package). This is the bridge between
// the YAML-deserialized config and the gossip layer.
func FromConfig(c config.P2pConfig) P2pConfig {
	return P2pConfig{
		Enabled:               c.Enabled,
		Seeds:                 c.Seeds,
		NatTraversal:          c.NatTraversal,
		StunServers:           c.StunServers,
		RelayMode:             c.RelayMode,
		MaxRelayHops:          c.MaxRelayHops,
		JoinApproval:          c.JoinApproval,
		AuthorizedKeys:        c.AuthorizedKeys,
		GossipInterval:        c.GossipInterval,
		GossipProbeInterval:   c.GossipProbeInterval,
		DirectReprobeInterval: c.DirectReprobeInterval,
		MaxPeers:              c.MaxPeers,
		GossipPort:            7946, // Default; overridden by MeshConfig.GossipPort in practice
		AdvertiseEndpoints:    c.AdvertiseEndpoints,
	}
}

// HasSeed returns true if the config has at least one seed peer.
func (c *P2pConfig) HasSeed() bool {
	return len(c.Seeds) > 0
}

// IsAuthorized checks whether a given public key is in the authorized_keys list.
// Returns true if JoinApproval is "auto" and the key is in the list.
// Returns true if JoinApproval is not "auto" (manual mode handles auth elsewhere).
func (c *P2pConfig) IsAuthorized(publicKey string) bool {
	if c.JoinApproval != "auto" {
		return true // manual mode — auth handled by dashboard approval flow
	}
	for _, k := range c.AuthorizedKeys {
		if k == publicKey {
			return true
		}
	}
	return false
}
