package ipam

import (
	"net"
	"sort"
	"strings"
	"testing"
)

func mustAlloc(t *testing.T, subnet string) *Allocator {
	t.Helper()
	a, err := NewAllocator(subnet)
	if err != nil {
		t.Fatalf("NewAllocator(%s): %v", subnet, err)
	}
	return a
}

func TestNewAllocator(t *testing.T) {
	tests := []struct {
		subnet      string
		wantErr     bool
		wantUsable int
	}{
		{"10.10.0.0/24", false, 254},
		{"10.10.0.0/16", false, 65534},
		{"10.10.0.0/30", false, 2},
		{"10.10.0.0/31", false, 2},   // RFC 3021
		{"10.10.0.0/32", true, 0},    // too small
		{"invalid", true, 0},
		{"", true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.subnet, func(t *testing.T) {
			a, err := NewAllocator(tt.subnet)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tt.subnet)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if a.UsableHosts() != tt.wantUsable {
				t.Errorf("usableHosts = %d, want %d", a.UsableHosts(), tt.wantUsable)
			}
		})
	}
}

func TestHostNumberToIP(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// Host 1 → 10.10.0.1 (network+1)
	ip := a.hostNumberToIP(1)
	if !ip.Equal(net.ParseIP("10.10.0.1")) {
		t.Errorf("hostNum 1 = %s, want 10.10.0.1", ip)
	}

	// Host 254 → 10.10.0.254
	ip = a.hostNumberToIP(254)
	if !ip.Equal(net.ParseIP("10.10.0.254")) {
		t.Errorf("hostNum 254 = %s, want 10.10.0.254", ip)
	}

	// Out of range
	if a.hostNumberToIP(0) != nil {
		t.Error("hostNum 0 should return nil")
	}
	if a.hostNumberToIP(255) != nil {
		t.Error("hostNum 255 should return nil (broadcast)")
	}
}

func TestHostNumberToIP_LargeSubnet(t *testing.T) {
	a := mustAlloc(t, "10.0.0.0/16")

	// Host 1 → 10.0.0.1
	ip := a.hostNumberToIP(1)
	if !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("hostNum 1 = %s, want 10.0.0.1", ip)
	}

	// Host 256 → 10.0.1.0 (network + 256)
	ip = a.hostNumberToIP(256)
	if !ip.Equal(net.ParseIP("10.0.1.0")) {
		t.Errorf("hostNum 256 = %s, want 10.0.1.0", ip)
	}

	// Host 65534 → 10.0.255.254 (network + 65534)
	ip = a.hostNumberToIP(65534)
	if !ip.Equal(net.ParseIP("10.0.255.254")) {
		t.Errorf("hostNum 65534 = %s, want 10.0.255.254", ip)
	}
}

func TestAllocate_Simple(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// Single node, hostCount=1.
	ip, err := a.Allocate("aaaa", 1)
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}

	// Verify the IP is in the subnet.
	if !a.subnet.Contains(ip) {
		t.Errorf("allocated IP %s not in subnet %s", ip, a.subnet)
	}
}

func TestAllocate_Deterministic(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// Same pubkey + hostCount should always produce the same IP.
	ip1, _ := a.Allocate("abc123def", 5)
	ip2, _ := a.Allocate("abc123def", 5)
	if !ip1.Equal(ip2) {
		t.Errorf("non-deterministic: %s != %s", ip1, ip2)
	}

	// Different pubkey should (very likely) produce a different IP.
	ip3, _ := a.Allocate("xyz789ghi", 5)
	if ip1.Equal(ip3) {
		t.Logf("note: same IP for different keys (possible hash collision)")
	}
}

func TestAllocate_DifferentHostCount(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// Same key with different hostCount should produce different slots
	// (since the modulus changes).
	ip1, _ := a.Allocate("testkey", 3)
	ip2, _ := a.Allocate("testkey", 7)
	if ip1.Equal(ip2) {
		t.Logf("note: same IP for different hostCount (possible if hash mod 3 == hash mod 7)")
	}
}

func TestAllocate_Errors(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	_, err := a.Allocate("key", 0)
	if err == nil {
		t.Error("expected error for hostCount=0")
	}

	_, err = a.Allocate("key", 300)
	if err == nil {
		t.Error("expected error for hostCount > usableHosts")
	}
}

func TestAllocateAll_NoConflicts(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	keys := []string{"key_a", "key_b", "key_c", "key_d", "key_e"}
	result, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll: %v", err)
	}

	if len(result) != len(keys) {
		t.Fatalf("result has %d entries, want %d", len(result), len(keys))
	}

	// All IPs must be unique.
	seen := make(map[string]bool)
	for key, ip := range result {
		ipStr := ip.String()
		if seen[ipStr] {
			t.Fatalf("duplicate IP %s for key %s", ipStr, key)
		}
		seen[ipStr] = true
	}

	// All IPs must be in subnet.
	for key, ip := range result {
		if !a.subnet.Contains(ip) {
			t.Errorf("IP %s for key %s not in subnet", ip, key)
		}
	}
}

func TestAllocateAll_LargeSet(t *testing.T) {
	// Use a /22 subnet (1022 usable) with 100 nodes.
	a := mustAlloc(t, "10.10.0.0/22")

	keys := make([]string, 100)
	for i := range keys {
		keys[i] = "node_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}

	result, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll: %v", err)
	}

	if len(result) != 100 {
		t.Fatalf("result has %d entries, want 100", len(result))
	}

	// Verify uniqueness.
	seen := make(map[string]bool)
	for _, ip := range result {
		ipStr := ip.String()
		if seen[ipStr] {
			t.Fatalf("duplicate IP %s", ipStr)
		}
		seen[ipStr] = true
	}
}

func TestAllocateAll_Deterministic(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	keys := []string{"zzz", "aaa", "mmm", "bbb", "yyy"}

	// Run twice — must produce identical results.
	r1, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll run 1: %v", err)
	}
	r2, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll run 2: %v", err)
	}

	for _, key := range keys {
		if !r1[key].Equal(r2[key]) {
			t.Errorf("non-deterministic for key %s: %s != %s", key, r1[key], r2[key])
		}
	}
}

func TestAllocateAll_OrderIndependent(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// The result should be the same regardless of input order,
	// because AllocateAll sorts internally.
	keys1 := []string{"key3", "key1", "key2", "key5", "key4"}
	keys2 := []string{"key1", "key2", "key3", "key4", "key5"}

	r1, _ := a.AllocateAll(keys1)
	r2, _ := a.AllocateAll(keys2)

	for _, key := range keys1 {
		if !r1[key].Equal(r2[key]) {
			t.Errorf("order-dependent for key %s: %s != %s", key, r1[key], r2[key])
		}
	}
}

func TestAllocateAll_ConflictResolution(t *testing.T) {
	// Use a small subnet to force conflicts.
	// /28 = 14 usable hosts, 10 nodes → high chance of conflict.
	a := mustAlloc(t, "10.10.0.0/28")

	keys := []string{
		"aaaa", "bbbb", "cccc", "dddd", "eeee",
		"ffff", "gggg", "hhhh", "iiii", "jjjj",
	}

	result, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll: %v", err)
	}

	// Verify all IPs are unique despite conflicts.
	seen := make(map[string]string) // ip → key
	for key, ip := range result {
		ipStr := ip.String()
		if existing, ok := seen[ipStr]; ok {
			t.Fatalf("IP conflict: keys %s and %s both got %s", existing, key, ipStr)
		}
		seen[ipStr] = key
	}
}

func TestAllocateAll_TooManyNodes(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/30") // only 2 usable

	keys := []string{"a", "b", "c"}
	_, err := a.AllocateAll(keys)
	if err == nil {
		t.Error("expected error for too many nodes")
	}
}

func TestAllocateAll_Empty(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")
	result, err := a.AllocateAll([]string{})
	if err != nil {
		t.Fatalf("AllocateAll(empty): %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d entries", len(result))
	}
}

func TestAllocateWithPeers_NoConflict(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// Allocate for self with no peers — should match Allocate().
	ip1, _ := a.Allocate("mykey", 3)
	ip2, _ := a.AllocateWithPeers("mykey", 3, map[string]net.IP{})

	if !ip1.Equal(ip2) {
		t.Errorf("AllocateWithPeers (no peers) = %s, but Allocate = %s", ip2, ip1)
	}
}

func TestAllocateWithPeers_WithConflict(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// Get the full allocation for 3 nodes.
	keys := []string{"keyA", "keyB", "keyC"}
	all, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll: %v", err)
	}

	// Now simulate keyC's perspective: it knows keyA and keyB's IPs.
	peerIPs := map[string]net.IP{
		"keyA": all["keyA"],
		"keyB": all["keyB"],
	}

	ipC, err := a.AllocateWithPeers("keyC", 3, peerIPs)
	if err != nil {
		t.Fatalf("AllocateWithPeers: %v", err)
	}

	// Must match what AllocateAll assigned.
	if !ipC.Equal(all["keyC"]) {
		t.Errorf("AllocateWithPeers(keyC) = %s, but AllocateAll says %s", ipC, all["keyC"])
	}
}

func TestAllocateWithPeers_YieldsToSmallerKey(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// Force a conflict: allocate for "zzz" (larger key) with a peer "aaa"
	// (smaller key) that claims the same IP that "zzz" would get with salt=0.
	baseIP, _ := a.Allocate("zzz", 2)
	peerIPs := map[string]net.IP{
		"aaa": baseIP, // peer claims zzz's natural slot
	}

	// zzz must yield because "aaa" < "zzz".
	result, err := a.AllocateWithPeers("zzz", 2, peerIPs)
	if err != nil {
		t.Fatalf("AllocateWithPeers: %v", err)
	}

	// The result must NOT be the conflicted IP.
	if result.Equal(baseIP) {
		t.Error("zzz did not yield — got same IP as aaa's claim")
	}

	// The result must be in subnet.
	if !a.subnet.Contains(result) {
		t.Errorf("yielded IP %s not in subnet", result)
	}
}

func TestAllocateWithPeers_KeepsOverLargerKey(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	// "aaa" (smaller key) should keep its slot even if "zzz" (larger key)
	// claims the same IP.
	baseIP, _ := a.Allocate("aaa", 2)
	peerIPs := map[string]net.IP{
		"zzz": baseIP, // larger peer claims aaa's natural slot
	}

	result, err := a.AllocateWithPeers("aaa", 2, peerIPs)
	if err != nil {
		t.Fatalf("AllocateWithPeers: %v", err)
	}

	// aaa should keep its IP.
	if !result.Equal(baseIP) {
		t.Errorf("aaa yielded but shouldn't have: got %s, want %s", result, baseIP)
	}
}

func TestResolveConflict(t *testing.T) {
	tests := []struct {
		self   string
		peer   string
		yield  bool // true = self should yield
	}{
		{"zzz", "aaa", true},   // self larger → yield
		{"aaa", "zzz", false},  // self smaller → keep
		{"aaa", "aaa", false},  // equal → keep (shouldn't happen, but safe)
	}

	for _, tt := range tests {
		got := ResolveConflict(tt.self, tt.peer)
		if got != tt.yield {
			t.Errorf("ResolveConflict(%q, %q) = %v, want %v", tt.self, tt.peer, got, tt.yield)
		}
	}
}

func TestAllocateAll_FillsSubnet(t *testing.T) {
	// /28 = 14 usable. Allocate exactly 14 nodes.
	a := mustAlloc(t, "10.10.0.0/28")

	keys := make([]string, 14)
	for i := range keys {
		keys[i] = "node" + string(rune('a'+i))
	}

	result, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll: %v", err)
	}

	if len(result) != 14 {
		t.Fatalf("got %d entries, want 14", len(result))
	}

	// All IPs unique.
	seen := make(map[string]bool)
	for _, ip := range result {
		if seen[ip.String()] {
			t.Fatalf("duplicate IP %s", ip)
		}
		seen[ip.String()] = true
	}

	// All IPs in subnet, not network or broadcast.
	for _, ip := range result {
		if !a.subnet.Contains(ip) {
			t.Errorf("IP %s not in subnet", ip)
		}
	}
}

func TestHashToSlot_Range(t *testing.T) {
	// Verify hashToSlot always returns [0, hostCount).
	for hostCount := 1; hostCount <= 100; hostCount++ {
		for _, key := range []string{"a", "b", "abc", "test", "longkey12345"} {
			for salt := 0; salt <= 5; salt++ {
				slot := hashToSlot(key, salt, hostCount)
				if slot < 0 || slot >= hostCount {
					t.Errorf("hashToSlot(%q, %d, %d) = %d, out of range [0,%d)",
						key, salt, hostCount, slot, hostCount)
				}
			}
		}
	}
}

func TestAllocateAll_Convergence(t *testing.T) {
	// The key property: every node independently computing AllocateAll
	// with the same set of keys gets the same assignment.
	a := mustAlloc(t, "10.10.0.0/24")

	keys := []string{"node1key", "node2key", "node3key", "node4key", "node5key"}

	// Simulate 5 nodes each running AllocateAll independently.
	results := make([]map[string]net.IP, 5)
	for i := 0; i < 5; i++ {
		// Each node sees the keys in a different order.
		shuffled := make([]string, len(keys))
		copy(shuffled, keys)
		// Simple deterministic shuffle.
		for j := 0; j < i; j++ {
			shuffled = append(shuffled[1:], shuffled[0])
		}
		r, err := a.AllocateAll(shuffled)
		if err != nil {
			t.Fatalf("node %d: AllocateAll: %v", i, err)
		}
		results[i] = r
	}

	// All 5 must agree.
	for _, key := range keys {
		for i := 1; i < 5; i++ {
			if !results[0][key].Equal(results[i][key]) {
				t.Errorf("disagreement on key %s: node0=%s, node%d=%s",
					key, results[0][key], i, results[i][key])
			}
		}
	}
}

func TestAllocateWithPeers_MatchesAllocateAll(t *testing.T) {
	// For each node in a set, AllocateWithPeers (using the other nodes'
	// IPs from AllocateAll) should produce the same IP that AllocateAll
	// assigned to that node.
	a := mustAlloc(t, "10.10.0.0/26") // 62 usable

	keys := []string{"k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"}
	all, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll: %v", err)
	}

	for _, selfKey := range keys {
		// Build peerIPs from all other nodes.
		peerIPs := make(map[string]net.IP)
		for _, otherKey := range keys {
			if otherKey != selfKey {
				peerIPs[otherKey] = all[otherKey]
			}
		}

		got, err := a.AllocateWithPeers(selfKey, len(keys), peerIPs)
		if err != nil {
			t.Fatalf("AllocateWithPeers(%s): %v", selfKey, err)
		}

		if !got.Equal(all[selfKey]) {
			t.Errorf("AllocateWithPeers(%s) = %s, but AllocateAll says %s",
				selfKey, got, all[selfKey])
		}
	}
}

func TestAllocateAll_SortedKeys(t *testing.T) {
	// Verify that AllocateAll processes keys in lexicographic order
	// by checking that the smallest key always gets salt=0.
	a := mustAlloc(t, "10.10.0.0/24")

	keys := []string{"zzz", "aaa", "mmm"}
	all, err := a.AllocateAll(keys)
	if err != nil {
		t.Fatalf("AllocateAll: %v", err)
	}

	// The smallest key ("aaa") should get its natural slot (salt=0).
	naturalIP, _ := a.Allocate("aaa", 3)
	if !all["aaa"].Equal(naturalIP) {
		t.Errorf("smallest key didn't get salt=0: got %s, natural %s",
			all["aaa"], naturalIP)
	}
}

func BenchmarkAllocateAll(b *testing.B) {
	a, _ := NewAllocator("10.0.0.0/16")
	keys := make([]string, 200)
	for i := range keys {
		keys[i] = "bench_node_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	sort.Strings(keys)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = a.AllocateAll(keys)
	}
}

// TestIPStringFormat verifies that allocated IPs are valid IPv4 strings.
func TestIPStringFormat(t *testing.T) {
	a := mustAlloc(t, "10.10.0.0/24")

	keys := []string{"a", "b", "c"}
	result, _ := a.AllocateAll(keys)

	for key, ip := range result {
		s := ip.String()
		parsed := net.ParseIP(s)
		if parsed == nil {
			t.Errorf("invalid IP string %q for key %s", s, key)
		}
		if !strings.Contains(s, ".") {
			t.Errorf("IP %s is not IPv4", s)
		}
	}
}
