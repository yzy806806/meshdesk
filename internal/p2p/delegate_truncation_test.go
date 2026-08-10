package p2p

import (
	"fmt"
	"strings"
	"testing"
)

// Reproduces the "byte misalignment" defect: when NodeMeta exceeds
// memberlist's 512-byte limit, NodeMeta(limit) truncates the msgpack
// stream mid-structure. The receiver then either fails to decode or —
// worse — decodes garbage fields (byte misalignment), which has been
// observed as corrupt gossip metadata across nodes.
func TestNodeMeta_TruncationCorruptsDecode(t *testing.T) {
	big := &NodeMeta{
		PublicKey:     strings.Repeat("a", 64),
		Hostname:      strings.Repeat("hostname-", 8), // 72 chars
		Role:          "relay",
		CapRelay:      true,
		VirtualIP:     "10.100.0.9",
		Endpoints:     []string{"203.0.113.1:52888", "[2001:db8::1]:52888", "10.0.0.1:52888", "192.168.1.1:52888"},
		NatType:       "restricted",
		SubnetProxies: []string{"10.10.0.0/16", "172.16.0.0/12", "192.168.10.0/24"},
		ACLRules: []string{
			"allow|10.100.0.0/24|10.100.0.0/24|tcp|any|any|peer_a|allow lan",
			"deny|0.0.0.0/0|10.100.0.5/32|udp|any|any|peer_b|deny oracle",
			"allow|10.100.0.0/24|10.100.0.0/24|icmp|any|any||ping",
		},
		TrafficInBytes:  123456789,
		TrafficOutBytes: 987654321,
		SmuxStreams:     5,
		RelayForwards:   2,
		LoadCPU:         0.42,
		LoadMem:         0.61,
		LoadCircuits:    3,
		RTTUs:           123456,
	}

	data, err := big.MarshalMeta()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Logf("serialized size: %d bytes (memberlist limit: 512)", len(data))
	if len(data) <= 512 {
		t.Skipf("meta fits in limit (%d <= 512) — defect not triggered", len(data))
	}

	// NodeMeta(limit) with the default 512-byte limit must return a
	// VALID document (the compact encoding), never a truncation.
	d := newMeshDelegate(big)
	got := d.NodeMeta(512)
	if len(got) == 0 {
		t.Fatalf("NodeMeta(512) returned empty bytes")
	}
	if len(got) > 512 {
		t.Fatalf("NodeMeta(512) returned %d bytes > limit", len(got))
	}
	decoded, err := UnmarshalMeta(got)
	if err != nil {
		t.Fatalf("DEFECT: compact encoding failed to decode: %v", err)
	}
	// Identity must survive compaction.
	if decoded.PublicKey != big.PublicKey {
		t.Errorf("public key lost in compaction: got %q", shortStr(decoded.PublicKey))
	}
	if decoded.VirtualIP != big.VirtualIP {
		t.Errorf("VIP lost in compaction: got %q", decoded.VirtualIP)
	}
	t.Logf("compact OK: %d bytes, vip=%s, pk=%s", len(got), decoded.VirtualIP, shortStr(decoded.PublicKey))
}

func shortStr(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

// Sanity: confirm the honest fallback (compact meta) stays under limit.
func TestNodeMeta_CompactFits(t *testing.T) {
	compact := &NodeMeta{
		PublicKey:  strings.Repeat("b", 64),
		Hostname:   "node",
		Role:       "agent",
		VirtualIP:  "10.100.0.9",
		Endpoints:  []string{"203.0.113.1:52888"},
		Seq:        42,
		CapRelay:   true,
	}
	data, err := compact.MarshalMeta()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) > 512 {
		t.Fatalf("compact meta still exceeds limit: %d", len(data))
	}
	fmt.Printf("compact size: %d\n", len(data))
}
