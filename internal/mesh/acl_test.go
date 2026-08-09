package mesh

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/yzy806806/meshdesk/internal/config"
)

// ─── ACLEngine construction tests ───

func TestNewACLEngine_Disabled(t *testing.T) {
	e, err := NewACLEngine(config.ACLConfig{
		Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.IsEnabled() {
		t.Fatal("engine should be disabled")
	}
	if e.DefaultPolicy() != config.ACLActionAllow {
		t.Fatalf("default policy should be allow, got %s", e.DefaultPolicy())
	}
}

func TestNewACLEngine_EnabledNoRules(t *testing.T) {
	e, err := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !e.IsEnabled() {
		t.Fatal("engine should be enabled")
	}
	if e.DefaultPolicy() != config.ACLActionDeny {
		t.Fatalf("default policy should be deny, got %s", e.DefaultPolicy())
	}
}

func TestNewACLEngine_DefaultPolicyDefaultsToAllow(t *testing.T) {
	e, err := NewACLEngine(config.ACLConfig{
		Enabled: true,
		// DefaultPolicy not set — should default to allow.
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.DefaultPolicy() != config.ACLActionAllow {
		t.Fatalf("default policy should be allow, got %s", e.DefaultPolicy())
	}
}

func TestNewACLEngine_InvalidRule(t *testing.T) {
	_, err := NewACLEngine(config.ACLConfig{
		Enabled: true,
		Rules: []config.ACLRule{
			{Action: "invalid"},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestNewACLEngine_InvalidCIDR(t *testing.T) {
	_, err := NewACLEngine(config.ACLConfig{
		Enabled: true,
		Rules: []config.ACLRule{
			{
				Action:     config.ACLActionDeny,
				SourceCIDR: "not-a-cidr",
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestNewACLEngine_DestIPAsSingleIP(t *testing.T) {
	e, err := NewACLEngine(config.ACLConfig{
		Enabled: true,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionDeny,
				DestCIDR: "10.10.0.5",
			},
		},
	})
	if err != nil {
		t.Fatalf("single IP as dest CIDR should work: %v", err)
	}
	rules := e.CurrentRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].DestCIDR != "10.10.0.5/32" {
		t.Fatalf("expected dest CIDR 10.10.0.5/32, got %s", rules[0].DestCIDR)
	}
}

// ─── Check() tests ───

func TestACLEngine_CheckDisabled_AlwaysAllow(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{Enabled: false})
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if !e.Check(pkt, "peerABC") {
		t.Fatal("disabled engine should allow all packets")
	}
}

func TestACLEngine_DefaultPolicyAllow(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
	})
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if !e.Check(pkt, "peerABC") {
		t.Fatal("allow-default should allow unmatched packets")
	}
}

func TestACLEngine_DefaultPolicyDeny(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
	})
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if e.Check(pkt, "peerABC") {
		t.Fatal("deny-default should deny unmatched packets")
	}
}

func TestACLEngine_DenyRuleMatches(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionDeny,
				DestCIDR: "10.10.0.5/32",
				Protocol: "tcp",
				DstPort:  22,
			},
		},
	})
	// Matching packet — should be denied.
	pkt := makeIPv4PacketACL("10.10.0.1", "10.10.0.5", 6, 54321, 22)
	if e.Check(pkt, "peerABC") {
		t.Fatal("packet matching deny rule should be denied")
	}

	// Non-matching packet (different port) — should be allowed.
	pkt2 := makeIPv4PacketACL("10.10.0.1", "10.10.0.5", 6, 54321, 80)
	if !e.Check(pkt2, "peerABC") {
		t.Fatal("packet not matching any rule should be allowed (default)")
	}

	// Non-matching destination — should be allowed.
	pkt3 := makeIPv4PacketACL("10.10.0.1", "10.10.0.99", 6, 54321, 22)
	if !e.Check(pkt3, "peerABC") {
		t.Fatal("packet to different dest should be allowed")
	}
}

func TestACLEngine_AllowRuleBeforeDeny(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionAllow,
				DestCIDR: "10.10.0.0/24",
				Protocol: "tcp",
				DstPort:  443,
			},
			{
				Action:   config.ACLActionDeny,
				DestCIDR: "10.10.0.0/24",
			},
		},
	})
	// Port 443 to 10.10.0.x — should match allow rule first.
	pkt := makeIPv4PacketACL("10.10.0.1", "10.10.0.50", 6, 12345, 443)
	if !e.Check(pkt, "peerABC") {
		t.Fatal("packet matching allow rule (first) should be allowed")
	}

	// Port 80 to 10.10.0.x — matches deny rule.
	pkt2 := makeIPv4PacketACL("10.10.0.1", "10.10.0.50", 6, 12345, 80)
	if e.Check(pkt2, "peerABC") {
		t.Fatal("packet matching deny rule should be denied")
	}
}

func TestACLEngine_PeerIDMatch(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action: config.ACLActionDeny,
				PeerID: "abcdef123456",
			},
		},
	})
	// Matching peer — denied.
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if e.Check(pkt, "abcdef123456") {
		t.Fatal("packet from denied peer should be denied")
	}
	// Different peer — allowed.
	if !e.Check(pkt, "different") {
		t.Fatal("packet from non-denied peer should be allowed")
	}
}

func TestACLEngine_ProtocolMatch(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionDeny,
				Protocol: "icmp",
			},
		},
	})
	// ICMP — denied.
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 1, 0, 0)
	if e.Check(pkt, "peer") {
		t.Fatal("ICMP packet should be denied")
	}
	// TCP — allowed.
	pkt2 := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if !e.Check(pkt2, "peer") {
		t.Fatal("TCP packet should be allowed")
	}
}

// ─── UpdateRules() tests ───

func TestACLEngine_UpdateRules(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
	})

	// Initially no rules.
	if len(e.CurrentRules()) != 0 {
		t.Fatal("expected 0 rules initially")
	}

	// Update with new rules.
	err := e.UpdateRules(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionAllow,
				DestCIDR: "10.0.0.0/8",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if e.DefaultPolicy() != config.ACLActionDeny {
		t.Fatal("default policy should be deny after update")
	}
	if len(e.CurrentRules()) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(e.CurrentRules()))
	}
}

func TestACLEngine_UpdateRules_Invalid(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{Enabled: true})
	err := e.UpdateRules(config.ACLConfig{
		Enabled: true,
		Rules: []config.ACLRule{
			{Action: "bogus"},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid rule")
	}
}

// ─── Stats() tests ───

func TestACLEngine_Stats(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:      config.ACLActionDeny,
				DestCIDR:    "10.0.0.1/32",
				Description: "test deny",
			},
		},
	})

	// Trigger one deny and one allow.
	pkt1 := makeIPv4PacketACL("10.0.0.2", "10.0.0.1", 6, 1234, 80) // matches deny
	pkt2 := makeIPv4PacketACL("10.0.0.2", "10.0.0.3", 6, 1234, 80) // no match → allow
	e.Check(pkt1, "peer")
	e.Check(pkt2, "peer")

	stats := e.Stats()
	if stats.DenyCount != 1 {
		t.Fatalf("expected 1 deny, got %d", stats.DenyCount)
	}
	if stats.AllowCount != 1 {
		t.Fatalf("expected 1 allow, got %d", stats.AllowCount)
	}
	if len(stats.RuleHits) != 1 {
		t.Fatalf("expected 1 rule hit entry, got %d", len(stats.RuleHits))
	}
	if stats.RuleHits[0].Hits != 1 {
		t.Fatalf("expected 1 hit on rule 0, got %d", stats.RuleHits[0].Hits)
	}
}

// ─── EncodeACLRulesForGossip tests ───

func TestEncodeACLRulesForGossip(t *testing.T) {
	rules := []config.ACLRule{
		{
			Action:      config.ACLActionDeny,
			SourceCIDR:  "10.0.0.0/8",
			DestCIDR:    "192.168.1.0/24",
			Protocol:    "tcp",
			SrcPort:     0,
			DstPort:     22,
			PeerID:      "*",
			Description: "block SSH",
		},
	}
	encoded := EncodeACLRulesForGossip(rules)
	if len(encoded) != 1 {
		t.Fatalf("expected 1 encoded rule, got %d", len(encoded))
	}
	// Format: action|src_cidr|dst_cidr|protocol|src_port|dst_port|peer_id|description
	expected := "deny|10.0.0.0/8|192.168.1.0/24|tcp|0|22|*|block SSH"
	if encoded[0] != expected {
		t.Fatalf("encoded rule mismatch:\nexpected: %s\ngot:      %s", expected, encoded[0])
	}
}

func TestEncodeACLRulesForGossip_EmptyFields(t *testing.T) {
	rules := []config.ACLRule{
		{
			Action: config.ACLActionAllow,
		},
	}
	encoded := EncodeACLRulesForGossip(rules)
	expected := "allow|*|*|*|0|0|*|"
	if encoded[0] != expected {
		t.Fatalf("encoded rule mismatch:\nexpected: %s\ngot:      %s", expected, encoded[0])
	}
}

// ─── parsePacketInfo tests ───

func TestParsePacketInfo_IPv4TCP(t *testing.T) {
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 12345, 80)
	info, ok := parsePacketInfo(pkt)
	if !ok {
		t.Fatal("failed to parse IPv4 TCP packet")
	}
	if info.protocol != "tcp" {
		t.Fatalf("expected tcp, got %s", info.protocol)
	}
	if info.srcPort != 12345 {
		t.Fatalf("expected src port 12345, got %d", info.srcPort)
	}
	if info.dstPort != 80 {
		t.Fatalf("expected dst port 80, got %d", info.dstPort)
	}
	if !info.srcIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("expected src IP 10.0.0.1, got %s", info.srcIP)
	}
	if !info.dstIP.Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("expected dst IP 10.0.0.2, got %s", info.dstIP)
	}
}

func TestParsePacketInfo_IPv4UDP(t *testing.T) {
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 17, 5353, 53)
	info, ok := parsePacketInfo(pkt)
	if !ok {
		t.Fatal("failed to parse IPv4 UDP packet")
	}
	if info.protocol != "udp" {
		t.Fatalf("expected udp, got %s", info.protocol)
	}
	if info.srcPort != 5353 {
		t.Fatalf("expected src port 5353, got %d", info.srcPort)
	}
	if info.dstPort != 53 {
		t.Fatalf("expected dst port 53, got %d", info.dstPort)
	}
}

func TestParsePacketInfo_IPv4ICMP(t *testing.T) {
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 1, 0, 0)
	info, ok := parsePacketInfo(pkt)
	if !ok {
		t.Fatal("failed to parse IPv4 ICMP packet")
	}
	if info.protocol != "icmp" {
		t.Fatalf("expected icmp, got %s", info.protocol)
	}
}

func TestParsePacketInfo_TooShort(t *testing.T) {
	_, ok := parsePacketInfo([]byte{0x45, 0x00})
	if ok {
		t.Fatal("expected parse failure for too-short packet")
	}
}

func TestParsePacketInfo_Empty(t *testing.T) {
	_, ok := parsePacketInfo([]byte{})
	if ok {
		t.Fatal("expected parse failure for empty packet")
	}
}

// ─── CurrentRules() tests ───

func TestACLEngine_CurrentRules(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:      config.ACLActionDeny,
				SourceCIDR:  "10.0.0.0/8",
				DestCIDR:    "192.168.1.0/24",
				Protocol:    "tcp",
				DstPort:     22,
				PeerID:      "abc123",
				Description: "test rule",
			},
		},
	})

	rules := e.CurrentRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.Action != config.ACLActionDeny {
		t.Fatalf("expected deny, got %s", r.Action)
	}
	if r.SourceCIDR != "10.0.0.0/8" {
		t.Fatalf("expected src CIDR 10.0.0.0/8, got %s", r.SourceCIDR)
	}
	if r.DestCIDR != "192.168.1.0/24" {
		t.Fatalf("expected dst CIDR 192.168.1.0/24, got %s", r.DestCIDR)
	}
	if r.Protocol != "tcp" {
		t.Fatalf("expected tcp, got %s", r.Protocol)
	}
	if r.DstPort != 22 {
		t.Fatalf("expected dst port 22, got %d", r.DstPort)
	}
	if r.PeerID != "abc123" {
		t.Fatalf("expected peer ID abc123, got %s", r.PeerID)
	}
	if r.Description != "test rule" {
		t.Fatalf("expected description 'test rule', got %s", r.Description)
	}
}

// ─── IPv6 parsePacketInfo tests ───

func TestParsePacketInfo_IPv6TCP(t *testing.T) {
	pkt := makeIPv6PacketACL("2001:db8::1", "2001:db8::2", 6, 12345, 80)
	info, ok := parsePacketInfo(pkt)
	if !ok {
		t.Fatal("failed to parse IPv6 TCP packet")
	}
	if info.protocol != "tcp" {
		t.Fatalf("expected tcp, got %s", info.protocol)
	}
	if info.srcPort != 12345 {
		t.Fatalf("expected src port 12345, got %d", info.srcPort)
	}
	if info.dstPort != 80 {
		t.Fatalf("expected dst port 80, got %d", info.dstPort)
	}
	if !info.srcIP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected src IP 2001:db8::1, got %s", info.srcIP)
	}
	if !info.dstIP.Equal(net.ParseIP("2001:db8::2")) {
		t.Fatalf("expected dst IP 2001:db8::2, got %s", info.dstIP)
	}
}

func TestParsePacketInfo_IPv6UDP(t *testing.T) {
	pkt := makeIPv6PacketACL("2001:db8::1", "2001:db8::2", 17, 5353, 53)
	info, ok := parsePacketInfo(pkt)
	if !ok {
		t.Fatal("failed to parse IPv6 UDP packet")
	}
	if info.protocol != "udp" {
		t.Fatalf("expected udp, got %s", info.protocol)
	}
	if info.srcPort != 5353 {
		t.Fatalf("expected src port 5353, got %d", info.srcPort)
	}
	if info.dstPort != 53 {
		t.Fatalf("expected dst port 53, got %d", info.dstPort)
	}
}

func TestParsePacketInfo_IPv6ICMP(t *testing.T) {
	pkt := makeIPv6PacketACL("2001:db8::1", "2001:db8::2", 58, 0, 0)
	info, ok := parsePacketInfo(pkt)
	if !ok {
		t.Fatal("failed to parse IPv6 ICMPv6 packet")
	}
	if info.protocol != "icmp" {
		t.Fatalf("expected icmp, got %s", info.protocol)
	}
}

func TestParsePacketInfo_IPv6TooShort(t *testing.T) {
	_, ok := parsePacketInfo([]byte{0x60, 0x00})
	if ok {
		t.Fatal("expected parse failure for too-short IPv6 packet")
	}
}

func TestParsePacketInfo_BadVersion(t *testing.T) {
	_, ok := parsePacketInfo([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if ok {
		t.Fatal("expected parse failure for bad IP version")
	}
}

// ─── Source CIDR matching tests ───

func TestACLEngine_SourceCIDRMatch(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:     config.ACLActionDeny,
				SourceCIDR: "10.10.0.0/24",
			},
		},
	})
	// Source inside denied range — denied.
	pkt := makeIPv4PacketACL("10.10.0.50", "192.168.1.1", 6, 1234, 80)
	if e.Check(pkt, "peer") {
		t.Fatal("packet from denied source CIDR should be denied")
	}
	// Source outside denied range — allowed.
	pkt2 := makeIPv4PacketACL("10.10.1.50", "192.168.1.1", 6, 1234, 80)
	if !e.Check(pkt2, "peer") {
		t.Fatal("packet from allowed source CIDR should be allowed")
	}
}

func TestACLEngine_SourceCIDRAndProtocolMatch(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:     config.ACLActionDeny,
				SourceCIDR: "10.10.0.0/24",
				Protocol:   "udp",
			},
		},
	})
	// Source matches, protocol matches — denied.
	pkt := makeIPv4PacketACL("10.10.0.50", "192.168.1.1", 17, 1234, 80)
	if e.Check(pkt, "peer") {
		t.Fatal("UDP from denied source CIDR should be denied")
	}
	// Source matches, different protocol — allowed.
	pkt2 := makeIPv4PacketACL("10.10.0.50", "192.168.1.1", 6, 1234, 80)
	if !e.Check(pkt2, "peer") {
		t.Fatal("TCP from same source CIDR should be allowed (protocol mismatch)")
	}
}

// ─── Source port matching tests ───

func TestACLEngine_SrcPortMatch(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:  config.ACLActionDeny,
				SrcPort: 8080,
			},
		},
	})
	// Source port 8080 — denied.
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 8080, 80)
	if e.Check(pkt, "peer") {
		t.Fatal("packet from src port 8080 should be denied")
	}
	// Source port 9090 — allowed.
	pkt2 := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 9090, 80)
	if !e.Check(pkt2, "peer") {
		t.Fatal("packet from src port 9090 should be allowed")
	}
}

func TestACLEngine_DstPortMatch(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:  config.ACLActionDeny,
				DstPort: 22,
			},
		},
	})
	// Dest port 22 — denied.
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 12345, 22)
	if e.Check(pkt, "peer") {
		t.Fatal("packet to dst port 22 should be denied")
	}
	// Dest port 80 — allowed.
	pkt2 := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 12345, 80)
	if !e.Check(pkt2, "peer") {
		t.Fatal("packet to dst port 80 should be allowed")
	}
}

// ─── Combined rule matching tests ───

func TestACLEngine_AllFieldsMatch(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:     config.ACLActionDeny,
				SourceCIDR: "10.10.0.0/24",
				DestCIDR:   "192.168.1.1/32",
				Protocol:   "tcp",
				SrcPort:    8000,
				DstPort:    443,
				PeerID:     "badpeer",
			},
		},
	})
	// All fields match — denied.
	pkt := makeIPv4PacketACL("10.10.0.50", "192.168.1.1", 6, 8000, 443)
	if e.Check(pkt, "badpeer") {
		t.Fatal("packet matching all rule fields should be denied")
	}
	// One field mismatches (src port) — allowed.
	pkt2 := makeIPv4PacketACL("10.10.0.50", "192.168.1.1", 6, 8001, 443)
	if !e.Check(pkt2, "badpeer") {
		t.Fatal("packet with wrong src port should be allowed")
	}
	// One field mismatches (peer ID) — allowed.
	pkt3 := makeIPv4PacketACL("10.10.0.50", "192.168.1.1", 6, 8000, 443)
	if !e.Check(pkt3, "goodpeer") {
		t.Fatal("packet from different peer should be allowed")
	}
}

// ─── Edge case tests ───

func TestACLEngine_UnparseablePacketDefaultDeny(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
	})
	// Unparseable packet with default-deny — should be denied.
	if e.Check([]byte{0x00, 0x01}, "peer") {
		t.Fatal("unparseable packet should be denied under default-deny")
	}
	stats := e.Stats()
	if stats.DenyCount != 1 {
		t.Fatalf("expected 1 deny, got %d", stats.DenyCount)
	}
}

func TestACLEngine_UnparseablePacketDefaultAllow(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
	})
	// Unparseable packet with default-allow — should be allowed.
	if !e.Check([]byte{0x00, 0x01}, "peer") {
		t.Fatal("unparseable packet should be allowed under default-allow")
	}
	stats := e.Stats()
	if stats.AllowCount != 1 {
		t.Fatalf("expected 1 allow, got %d", stats.AllowCount)
	}
}

func TestACLEngine_WildcardPeerID(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action: config.ACLActionDeny,
				PeerID: "*",
			},
		},
	})
	// Wildcard peer ID should match any peer.
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if e.Check(pkt, "anypeer") {
		t.Fatal("wildcard peer ID rule should deny any peer")
	}
}

func TestACLEngine_WildcardProtocol(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionAllow,
				Protocol: "*",
			},
		},
	})
	// Wildcard protocol should match TCP.
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if !e.Check(pkt, "peer") {
		t.Fatal("wildcard protocol should match TCP")
	}
	// Wildcard protocol should match UDP.
	pkt2 := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 17, 1234, 80)
	if !e.Check(pkt2, "peer") {
		t.Fatal("wildcard protocol should match UDP")
	}
	// Wildcard protocol should match ICMP.
	pkt3 := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 1, 0, 0)
	if !e.Check(pkt3, "peer") {
		t.Fatal("wildcard protocol should match ICMP")
	}
}

func TestACLEngine_EmptyPeerIDField(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action: config.ACLActionDeny,
				// PeerID empty — means "match any peer" (no peer filter).
			},
		},
	})
	// Empty peer ID means "don't filter by peer" — so all peers match. Denied.
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if e.Check(pkt, "anypeer") {
		t.Fatal("rule with empty peer ID should match (no peer filter) and deny")
	}
}

// ─── UpdateRules with state carryover tests ───

func TestACLEngine_UpdateRulesResetsHits(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionDeny,
				DestCIDR: "10.0.0.1/32",
			},
		},
	})
	// Generate some hits.
	pkt := makeIPv4PacketACL("10.0.0.2", "10.0.0.1", 6, 1234, 80)
	e.Check(pkt, "peer")
	e.Check(pkt, "peer")

	stats := e.Stats()
	if stats.RuleHits[0].Hits != 2 {
		t.Fatalf("expected 2 hits before update, got %d", stats.RuleHits[0].Hits)
	}

	// Update rules (replaces the rule set).
	err := e.UpdateRules(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionAllow,
				DestCIDR: "10.0.0.0/8",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Hits should be reset.
	stats2 := e.Stats()
	if len(stats2.RuleHits) != 1 {
		t.Fatalf("expected 1 rule hit entry, got %d", len(stats2.RuleHits))
	}
	if stats2.RuleHits[0].Hits != 0 {
		t.Fatalf("hits should be reset after UpdateRules, got %d", stats2.RuleHits[0].Hits)
	}
	if stats2.DefaultPolicy != config.ACLActionDeny {
		t.Fatal("default policy should be deny after update")
	}
}

func TestACLEngine_UpdateRulesCanDisable(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
		Rules: []config.ACLRule{
			{Action: config.ACLActionDeny, DestCIDR: "10.0.0.1/32"},
		},
	})
	// Disable ACL.
	err := e.UpdateRules(config.ACLConfig{
		Enabled: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.IsEnabled() {
		t.Fatal("engine should be disabled after update")
	}
	// All packets should be allowed when disabled.
	pkt := makeIPv4PacketACL("10.0.0.2", "10.0.0.1", 6, 1234, 80)
	if !e.Check(pkt, "peer") {
		t.Fatal("disabled engine should allow all")
	}
}

// ─── Concurrency test ───

func TestACLEngine_ConcurrentCheck(t *testing.T) {
	e, _ := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{Action: config.ACLActionDeny, DestCIDR: "10.0.0.1/32"},
		},
	})

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				pkt := makeIPv4PacketACL("10.0.0.2", "10.0.0.1", 6, 1234, 80)
				e.Check(pkt, "peer")
				// Also check a non-matching packet (different dest) to exercise allow path.
				pkt2 := makeIPv4PacketACL("10.0.0.2", "10.0.0.3", 6, 1234, 80)
				e.Check(pkt2, "peer")
			}
			done <- struct{}{}
		}()
		go func() {
			for j := 0; j < 50; j++ {
				e.Stats()
				e.CurrentRules()
				e.IsEnabled()
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines (10 checkers + 10 readers = 20).
	for i := 0; i < 20; i++ {
		<-done
	}

	stats := e.Stats()
	total := stats.AllowCount + stats.DenyCount
	// 10 goroutines × 100 iterations × 2 calls each = 2000 total.
	if total != 2000 {
		t.Fatalf("expected 2000 total decisions, got %d (allow=%d, deny=%d)", total, stats.AllowCount, stats.DenyCount)
	}
}

// ─── Helper: makeIPv4PacketACL ───
// Creates a minimal valid IPv4 packet for testing.
func makeIPv4PacketACL(srcIP, dstIP string, protocol byte, srcPort, dstPort int) []byte {
	pkt := make([]byte, 28) // minimum for TCP/UDP with ports
	// IPv4 header
	pkt[0] = 0x45                            // version 4, IHL 5
	pkt[1] = 0x00                            // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], 28) // total length
	pkt[9] = protocol                        // protocol
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	// Transport header (ports for TCP/UDP)
	if protocol == 6 || protocol == 17 {
		binary.BigEndian.PutUint16(pkt[20:22], uint16(srcPort))
		binary.BigEndian.PutUint16(pkt[22:24], uint16(dstPort))
	}
	return pkt
}

// makeIPv6PacketACL creates a minimal valid IPv6 packet for testing ACL parsePacketInfo.
func makeIPv6PacketACL(srcIP, dstIP string, protocol byte, srcPort, dstPort int) []byte {
	pkt := make([]byte, 60) // IPv6 header (40) + TCP/UDP header (20)
	// IPv6 header
	pkt[0] = 0x60 // version 6, traffic class 0
	// Flow label: 0 (next 3 bytes)
	// Payload length will vary based on transport header
	if protocol == 6 || protocol == 17 {
		binary.BigEndian.PutUint16(pkt[4:6], 20) // TCP/UDP header = 20 bytes
	} else {
		binary.BigEndian.PutUint16(pkt[4:6], 0) // No payload for ICMPv6
	}
	pkt[6] = protocol // Next Header
	pkt[7] = 0x40     // Hop Limit = 64
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)
	copy(pkt[8:24], src)
	copy(pkt[24:40], dst)
	// Transport header (ports for TCP/UDP)
	if protocol == 6 || protocol == 17 {
		binary.BigEndian.PutUint16(pkt[40:42], uint16(srcPort))
		binary.BigEndian.PutUint16(pkt[42:44], uint16(dstPort))
	}
	return pkt
}

// TestACLEngine_PeerDeny verifies a deny rule matching a specific peer.
func TestACLEngine_PeerDeny(t *testing.T) {
	e, err := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionDeny,
				PeerID:   "badpeer123",
				Protocol: "tcp",
			},
		},
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	pkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if e.Check(pkt, "badpeer123") {
		t.Fatal("badpeer should be denied")
	}
	if !e.Check(pkt, "goodpeer456") {
		t.Fatal("other peer should be allowed (default allow)")
	}
}

// TestACLEngine_PortDeny verifies a deny rule matching a dest port.
func TestACLEngine_PortDeny(t *testing.T) {
	e, err := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionAllow,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionDeny,
				DstPort:  22,
				Protocol: "tcp",
			},
		},
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	sshPkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 22)
	if e.Check(sshPkt, "anypeer") {
		t.Fatal("port 22 should be denied")
	}
	webPkt := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if !e.Check(webPkt, "anypeer") {
		t.Fatal("port 80 should be allowed")
	}
}

// TestACLEngine_DefaultDeny verifies default-policy deny.
func TestACLEngine_DefaultDeny(t *testing.T) {
	e, err := NewACLEngine(config.ACLConfig{
		Enabled:       true,
		DefaultPolicy: config.ACLActionDeny,
		Rules: []config.ACLRule{
			{
				Action:   config.ACLActionAllow,
				Protocol: "icmp",
			},
		},
	})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	ping := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 1, 0, 0)
	if !e.Check(ping, "peer") {
		t.Fatal("icmp should be allowed by rule")
	}
	tcp := makeIPv4PacketACL("10.0.0.1", "10.0.0.2", 6, 1234, 80)
	if e.Check(tcp, "peer") {
		t.Fatal("tcp should be denied by default")
	}
}
