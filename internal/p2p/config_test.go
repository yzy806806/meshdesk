package p2p

import (
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

func TestDefaultP2pConfig(t *testing.T) {
	cfg := DefaultP2pConfig()

	if cfg.Enabled != false {
		t.Errorf("default Enabled should be false, got %v", cfg.Enabled)
	}
	if cfg.NatTraversal != true {
		t.Errorf("default NatTraversal should be true, got %v", cfg.NatTraversal)
	}
	if cfg.RelayMode != "auto" {
		t.Errorf("default RelayMode should be 'auto', got %s", cfg.RelayMode)
	}
	if cfg.MaxRelayHops != 2 {
		t.Errorf("default MaxRelayHops should be 2, got %d", cfg.MaxRelayHops)
	}
	if cfg.JoinApproval != "auto" {
		t.Errorf("default JoinApproval should be 'auto', got %s", cfg.JoinApproval)
	}
	if cfg.GossipInterval != 30 {
		t.Errorf("default GossipInterval should be 30, got %d", cfg.GossipInterval)
	}
	if cfg.GossipProbeInterval != 1 {
		t.Errorf("default GossipProbeInterval should be 1, got %d", cfg.GossipProbeInterval)
	}
	if cfg.DirectReprobeInterval != 120 {
		t.Errorf("default DirectReprobeInterval should be 120, got %d", cfg.DirectReprobeInterval)
	}
	if cfg.MaxPeers != 256 {
		t.Errorf("default MaxPeers should be 256, got %d", cfg.MaxPeers)
	}
	if cfg.GossipPort != 7946 {
		t.Errorf("default GossipPort should be 7946, got %d", cfg.GossipPort)
	}
	if len(cfg.StunServers) != 2 {
		t.Errorf("default StunServers should have 2 entries, got %d", len(cfg.StunServers))
	}
}

func TestP2pConfigHasSeed(t *testing.T) {
	tests := []struct {
		name  string
		seeds []string
		want  bool
	}{
		{"empty", nil, false},
		{"one seed", []string{"10.10.0.5:7946"}, true},
		{"multiple seeds", []string{"10.10.0.5:7946", "10.10.0.10:7946"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultP2pConfig()
			cfg.Seeds = tt.seeds
			if cfg.HasSeed() != tt.want {
				t.Errorf("HasSeed() = %v, want %v", cfg.HasSeed(), tt.want)
			}
		})
	}
}

func TestP2pConfigIsAuthorized(t *testing.T) {
	authorizedKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	unauthorizedKey := "deadbeef00000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name         string
		joinApproval string
		authorized   []string
		checkKey     string
		want         bool
	}{
		{
			name:         "auto_mode_authorized",
			joinApproval: "auto",
			authorized:   []string{authorizedKey},
			checkKey:     authorizedKey,
			want:         true,
		},
		{
			name:         "auto_mode_unauthorized",
			joinApproval: "auto",
			authorized:   []string{authorizedKey},
			checkKey:     unauthorizedKey,
			want:         false,
		},
		{
			name:         "auto_mode_empty_list",
			joinApproval: "auto",
			authorized:   []string{},
			checkKey:     unauthorizedKey,
			want:         false,
		},
		{
			name:         "manual_mode_always_true",
			joinApproval: "manual",
			authorized:   []string{},
			checkKey:     unauthorizedKey,
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := P2pConfig{
				JoinApproval:   tt.joinApproval,
				AuthorizedKeys: tt.authorized,
			}
			if cfg.IsAuthorized(tt.checkKey) != tt.want {
				t.Errorf("IsAuthorized() = %v, want %v", cfg.IsAuthorized(tt.checkKey), tt.want)
			}
		})
	}
}

func TestFromConfig(t *testing.T) {
	src := config.P2pConfig{
		Enabled:               true,
		Seeds:                 []string{"10.10.0.5:7946"},
		NatTraversal:          true,
		StunServers:           []string{"stun.l.google.com:19302"},
		RelayMode:             "auto",
		MaxRelayHops:          3,
		JoinApproval:          "manual",
		AuthorizedKeys:        []string{"key1", "key2"},
		GossipInterval:        60,
		GossipProbeInterval:   2,
		DirectReprobeInterval: 180,
		MaxPeers:              128,
	}

	dst := FromConfig(src)

	if dst.Enabled != src.Enabled {
		t.Errorf("Enabled mismatch: got %v, want %v", dst.Enabled, src.Enabled)
	}
	if len(dst.Seeds) != len(src.Seeds) {
		t.Errorf("Seeds mismatch")
	}
	if dst.NatTraversal != src.NatTraversal {
		t.Errorf("NatTraversal mismatch")
	}
	if dst.RelayMode != src.RelayMode {
		t.Errorf("RelayMode mismatch")
	}
	if dst.MaxRelayHops != src.MaxRelayHops {
		t.Errorf("MaxRelayHops mismatch")
	}
	if dst.JoinApproval != src.JoinApproval {
		t.Errorf("JoinApproval mismatch")
	}
	if len(dst.AuthorizedKeys) != len(src.AuthorizedKeys) {
		t.Errorf("AuthorizedKeys mismatch")
	}
	if dst.GossipInterval != src.GossipInterval {
		t.Errorf("GossipInterval mismatch")
	}
	if dst.GossipProbeInterval != src.GossipProbeInterval {
		t.Errorf("GossipProbeInterval mismatch")
	}
	if dst.DirectReprobeInterval != src.DirectReprobeInterval {
		t.Errorf("DirectReprobeInterval mismatch")
	}
	if dst.MaxPeers != src.MaxPeers {
		t.Errorf("MaxPeers mismatch")
	}
}
