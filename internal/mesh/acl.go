package mesh

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/yzy806806/meshdesk/internal/config"
)

// ACLEngine evaluates ACL rules for TUN packets. It is called by the
// TUN forwarder on every inbound packet after anti-spoofing validation
// but before writing to the TUN device, and on every outbound packet
// before forwarding to a peer.
//
// The engine is safe for concurrent use. Rule updates are atomic via
// a RWMutex. Per-rule hit counts are tracked with atomic counters for
// lock-free statistics collection.
type ACLEngine struct {
	// snapshot is the immutable rule set + policy, swapped atomically
	// by UpdateRules. Check reads it lock-free — this removes both the
	// unsynchronized `enabled` read and the rules/hitCounts index
	// mismatch (a concurrent UpdateRules replacing hitCounts with a
	// shorter slice used to panic Check's hitCounts[i]).
	snapshot atomic.Pointer[aclSnapshot]

	// allowCount / denyCount track aggregate decisions.
	allowCount atomic.Uint64
	denyCount  atomic.Uint64
}

// aclSnapshot is an immutable rule-set snapshot.
type aclSnapshot struct {
	enabled       bool
	defaultPolicy config.ACLAction
	rules         []compiledACLRule
	hitCounts     []atomic.Uint64
}

// compiledACLRule is a pre-parsed ACL rule with compiled CIDR matchers.
type compiledACLRule struct {
	action   config.ACLAction
	srcNet   *net.IPNet // nil = match any
	dstNet   *net.IPNet // nil = match any
	protocol string     // "", "*", "tcp", "udp", "icmp"
	srcPort  int        // 0 = any
	dstPort  int        // 0 = any
	peerID   string     // "", "*", or specific hex key
	desc     string
}

// ACLStats holds a snapshot of ACL engine statistics.
type ACLStats struct {
	Enabled       bool              `json:"enabled"`
	DefaultPolicy config.ACLAction  `json:"default_policy"`
	AllowCount    uint64            `json:"allow_count"`
	DenyCount     uint64            `json:"deny_count"`
	RuleHits      []ACLRuleHitStats `json:"rule_hits"`
}

// ACLRuleHitStats holds hit statistics for a single rule.
type ACLRuleHitStats struct {
	Index  int    `json:"index"`
	Action string `json:"action"`
	Hits   uint64 `json:"hits"`
	Desc   string `json:"description"`
}

// NewACLEngine creates a new ACL engine from config. If ACL is disabled,
// the engine returns allow for all packets (no-op).
func NewACLEngine(cfg config.ACLConfig) (*ACLEngine, error) {
	e := &ACLEngine{}

	dp := cfg.DefaultPolicy
	if dp == "" {
		dp = config.ACLActionAllow
	}

	var compiled []compiledACLRule
	for i, rule := range cfg.Rules {
		c, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("acl: rule %d: %w", i, err)
		}
		compiled = append(compiled, c)
	}
	e.snapshot.Store(&aclSnapshot{
		enabled:       cfg.Enabled,
		defaultPolicy: dp,
		rules:         compiled,
		hitCounts:     make([]atomic.Uint64, len(compiled)),
	})

	return e, nil
}

// compileRule converts a config.ACLRule into a compiledACLRule with
// pre-parsed CIDR matchers.
func compileRule(rule config.ACLRule) (compiledACLRule, error) {
	if rule.Action != config.ACLActionAllow && rule.Action != config.ACLActionDeny {
		return compiledACLRule{}, fmt.Errorf("invalid action %q (must be allow or deny)", rule.Action)
	}

	c := compiledACLRule{
		action:   rule.Action,
		protocol: strings.ToLower(rule.Protocol),
		srcPort:  rule.SrcPort,
		dstPort:  rule.DstPort,
		peerID:   rule.PeerID,
		desc:     rule.Description,
	}

	if c.protocol == "" {
		c.protocol = "*"
	}

	// Compile source CIDR.
	if rule.SourceCIDR != "" && rule.SourceCIDR != "*" {
		_, ipNet, err := net.ParseCIDR(rule.SourceCIDR)
		if err != nil {
			return compiledACLRule{}, fmt.Errorf("invalid src_cidr %q: %w", rule.SourceCIDR, err)
		}
		c.srcNet = ipNet
	}

	// Compile dest CIDR.
	if rule.DestCIDR != "" && rule.DestCIDR != "*" {
		_, ipNet, err := net.ParseCIDR(rule.DestCIDR)
		if err != nil {
			// Try as a single IP → /32 or /128
			ip := net.ParseIP(rule.DestCIDR)
			if ip == nil {
				return compiledACLRule{}, fmt.Errorf("invalid dst_cidr %q: not a valid CIDR or IP", rule.DestCIDR)
			}
			if ip.To4() != nil {
				c.dstNet = &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
			} else {
				c.dstNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		} else {
			c.dstNet = ipNet
		}
	}

	return c, nil
}

// Check evaluates a packet against the ACL ruleset.
// Returns true if the packet is allowed, false if denied.
// When ACL is disabled, always returns true.
func (e *ACLEngine) Check(packet []byte, peerID string) bool {
	snap := e.snapshot.Load()
	if snap == nil || !snap.enabled {
		return true
	}

	// Parse packet info once.
	pktInfo, ok := parsePacketInfo(packet)
	if !ok {
		// Can't parse — fall back to default policy.
		if snap.defaultPolicy == config.ACLActionAllow {
			e.allowCount.Add(1)
			return true
		}
		e.denyCount.Add(1)
		return false
	}

	for i, rule := range snap.rules {
		if ruleMatches(rule, pktInfo, peerID) {
			snap.hitCounts[i].Add(1)
			if rule.action == config.ACLActionAllow {
				e.allowCount.Add(1)
				return true
			}
			e.denyCount.Add(1)
			return false
		}
	}

	// No rule matched — apply default policy.
	if snap.defaultPolicy == config.ACLActionAllow {
		e.allowCount.Add(1)
		return true
	}
	e.denyCount.Add(1)
	return false
}

// packetInfo holds parsed IP packet fields used for ACL matching.
type packetInfo struct {
	srcIP    net.IP
	dstIP    net.IP
	protocol string // "tcp", "udp", "icmp", or ""
	srcPort  int
	dstPort  int
}

// parsePacketInfo extracts source IP, dest IP, protocol, and ports
// from an IP packet. Returns false if the packet cannot be parsed.
func parsePacketInfo(packet []byte) (packetInfo, bool) {
	if len(packet) < 1 {
		return packetInfo{}, false
	}

	var info packetInfo
	version := packet[0] >> 4

	switch version {
	case 4:
		if len(packet) < 20 {
			return packetInfo{}, false
		}
		info.srcIP = net.IP(packet[12:16]).To4()
		info.dstIP = net.IP(packet[16:20]).To4()

		proto := packet[9]
		switch proto {
		case 6: // TCP
			if len(packet) < 24 {
				info.protocol = "tcp"
				return info, true
			}
			info.protocol = "tcp"
			info.srcPort = int(binary.BigEndian.Uint16(packet[20:22]))
			info.dstPort = int(binary.BigEndian.Uint16(packet[22:24]))
		case 17: // UDP
			if len(packet) < 28 {
				info.protocol = "udp"
				return info, true
			}
			info.protocol = "udp"
			info.srcPort = int(binary.BigEndian.Uint16(packet[20:22]))
			info.dstPort = int(binary.BigEndian.Uint16(packet[22:24]))
		case 1: // ICMP
			info.protocol = "icmp"
		default:
			info.protocol = ""
		}
		return info, true

	case 6:
		if len(packet) < 40 {
			return packetInfo{}, false
		}
		info.srcIP = make(net.IP, 16)
		copy(info.srcIP, packet[8:24])
		info.dstIP = make(net.IP, 16)
		copy(info.dstIP, packet[24:40])

		proto := packet[6]
		switch proto {
		case 6: // TCP
			info.protocol = "tcp"
			if len(packet) >= 44 {
				info.srcPort = int(binary.BigEndian.Uint16(packet[40:42]))
				info.dstPort = int(binary.BigEndian.Uint16(packet[42:44]))
			}
		case 17: // UDP
			info.protocol = "udp"
			if len(packet) >= 44 {
				info.srcPort = int(binary.BigEndian.Uint16(packet[40:42]))
				info.dstPort = int(binary.BigEndian.Uint16(packet[42:44]))
			}
		case 58: // ICMPv6
			info.protocol = "icmp"
		default:
			info.protocol = ""
		}
		return info, true

	default:
		return packetInfo{}, false
	}
}

// ruleMatches checks if a compiled rule matches the given packet info.
func ruleMatches(rule compiledACLRule, info packetInfo, peerID string) bool {
	// Check source CIDR.
	if rule.srcNet != nil && !rule.srcNet.Contains(info.srcIP) {
		return false
	}

	// Check dest CIDR.
	if rule.dstNet != nil && !rule.dstNet.Contains(info.dstIP) {
		return false
	}

	// Check protocol.
	if rule.protocol != "*" && rule.protocol != "" {
		if info.protocol != rule.protocol {
			return false
		}
	}

	// Check source port.
	if rule.srcPort != 0 && info.srcPort != rule.srcPort {
		return false
	}

	// Check dest port.
	if rule.dstPort != 0 && info.dstPort != rule.dstPort {
		return false
	}

	// Check peer ID.
	if rule.peerID != "" && rule.peerID != "*" {
		if peerID != rule.peerID {
			return false
		}
	}

	return true
}

// UpdateRules atomically replaces the ACL rule set.
func (e *ACLEngine) UpdateRules(cfg config.ACLConfig) error {
	var compiled []compiledACLRule
	for i, rule := range cfg.Rules {
		c, err := compileRule(rule)
		if err != nil {
			return fmt.Errorf("acl: rule %d: %w", i, err)
		}
		compiled = append(compiled, c)
	}

	dp := cfg.DefaultPolicy
	if dp == "" {
		dp = config.ACLActionAllow
	}
	e.snapshot.Store(&aclSnapshot{
		enabled:       cfg.Enabled,
		defaultPolicy: dp,
		rules:         compiled,
		hitCounts:     make([]atomic.Uint64, len(compiled)),
	})

	return nil
}

// Stats returns a snapshot of ACL engine statistics.
func (e *ACLEngine) Stats() ACLStats {
	snap := e.snapshot.Load()

	stats := ACLStats{
		AllowCount: e.allowCount.Load(),
		DenyCount:  e.denyCount.Load(),
	}
	if snap == nil {
		return stats
	}
	stats.Enabled = snap.enabled
	stats.DefaultPolicy = snap.defaultPolicy

	for i, rule := range snap.rules {
		stats.RuleHits = append(stats.RuleHits, ACLRuleHitStats{
			Index:  i,
			Action: string(rule.action),
			Hits:   snap.hitCounts[i].Load(),
			Desc:   rule.desc,
		})
	}

	return stats
}

// IsEnabled returns whether ACL checking is currently active.
func (e *ACLEngine) IsEnabled() bool {
	snap := e.snapshot.Load()
	return snap != nil && snap.enabled
}

// DefaultPolicy returns the current default policy action.
func (e *ACLEngine) DefaultPolicy() config.ACLAction {
	snap := e.snapshot.Load()
	if snap == nil {
		return config.ACLActionAllow
	}
	return snap.defaultPolicy
}

// CurrentRules returns the current ACL rules as config.ACLRule slice.
// This is used by the web Dashboard to display and manage rules.
func (e *ACLEngine) CurrentRules() []config.ACLRule {
	snap := e.snapshot.Load()
	if snap == nil {
		return nil
	}

	rules := make([]config.ACLRule, 0, len(snap.rules))
	for _, c := range snap.rules {
		r := config.ACLRule{
			Action:      c.action,
			Protocol:    c.protocol,
			SrcPort:     c.srcPort,
			DstPort:     c.dstPort,
			PeerID:      c.peerID,
			Description: c.desc,
		}
		if c.srcNet != nil {
			r.SourceCIDR = c.srcNet.String()
		}
		if c.dstNet != nil {
			r.DestCIDR = c.dstNet.String()
		}
		rules = append(rules, r)
	}
	return rules
}

// EncodeACLRulesForGossip converts config ACL rules to the compact
// string encoding used in NodeMeta.ACLRules. Each rule is encoded as:
// "action|src_cidr|dst_cidr|protocol|src_port|dst_port|peer_id|description"
func EncodeACLRulesForGossip(rules []config.ACLRule) []string {
	result := make([]string, 0, len(rules))
	for _, r := range rules {
		encoded := fmt.Sprintf("%s|%s|%s|%s|%d|%d|%s|%s",
			r.Action,
			defaultStar(r.SourceCIDR),
			defaultStar(r.DestCIDR),
			defaultStar(r.Protocol),
			r.SrcPort,
			r.DstPort,
			defaultStar(r.PeerID),
			r.Description,
		)
		result = append(result, encoded)
	}
	return result
}

func defaultStar(s string) string {
	if s == "" {
		return "*"
	}
	return s
}
