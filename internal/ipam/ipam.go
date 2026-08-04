// Package ipam implements deterministic IP address management for the
// mesh TUN subnet.
//
// Design (from motion-a32c134c4d9c):
//
//  1. Deterministic allocation: each node computes its VirtualIP as
//     hash(pubkey) % host_count, where host_count is the total number
//     of known mesh nodes (including self). The result maps to a host
//     number within the configured TUN subnet.
//
//  2. Conflict resolution: when two nodes compute the same slot, the
//     node whose public key is lexicographically larger re-hashes with
//     an incrementing salt (hash(pubkey + salt) % host_count) until it
//     finds a free slot. The node with the smaller public key keeps
//     its original slot.
//
//  3. Propagation: the assigned VirtualIP is carried in gossip NodeMeta
//     so every node learns every other node's IP without a central
//     allocator.
//
// The algorithm is fully deterministic: given the same set of public
// keys and the same subnet, every node independently computes the same
// IP assignment. No coordinator, no consensus rounds, no split-brain.
package ipam

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
)

// MaxSaltIterations is the upper bound on salt-based conflict resolution
// attempts. In practice a free slot is found within a few iterations
// unless the subnet is nearly full.
const MaxSaltIterations = 1000

// Allocator computes deterministic VirtualIP assignments for mesh nodes
// within a TUN subnet.
type Allocator struct {
	// subnet is the CIDR subnet (e.g. "10.10.0.0/24") from which
	// VirtualIPs are allocated.
	subnet *net.IPNet

	// hostBits is the number of host bits in the subnet mask.
	// For /24, hostBits = 8 (256 total, 254 usable).
	hostBits int

	// usableHosts is the number of usable host addresses in the subnet
	// (total - network - broadcast), or total for /31 and /32.
	usableHosts int
}

// NewAllocator creates an Allocator for the given CIDR subnet.
// Returns an error if the subnet is invalid or has fewer than 2 hosts.
func NewAllocator(subnet string) (*Allocator, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("ipam: invalid subnet %q: %w", subnet, err)
	}

	// Calculate host bits from the mask.
	maskOnes, maskBits := ipNet.Mask.Size()
	if maskBits == 0 {
		return nil, fmt.Errorf("ipam: invalid mask in subnet %q", subnet)
	}
	hostBits := maskBits - maskOnes

	// Total addresses in the subnet.
	if hostBits > 63 {
		return nil, fmt.Errorf("ipam: subnet %s too large (hostBits=%d > 63)", subnet, hostBits)
	}
	totalAddrs := 1 << hostBits
	if totalAddrs < 2 {
		return nil, fmt.Errorf("ipam: subnet %s too small (need at least 2 addresses)", subnet)
	}

	// Usable hosts: exclude network and broadcast for /30 and larger.
	// For /31 (2 addresses) and /32 (1 address), both are usable
	// (RFC 3021 point-to-point).
	usableHosts := totalAddrs
	if hostBits >= 2 {
		usableHosts = totalAddrs - 2
	}

	return &Allocator{
		subnet:       ipNet,
		hostBits:     hostBits,
		usableHosts:  usableHosts,
	}, nil
}

// Subnet returns the CIDR subnet the allocator operates on.
func (a *Allocator) Subnet() *net.IPNet {
	return a.subnet
}

// UsableHosts returns the number of usable host addresses.
func (a *Allocator) UsableHosts() int {
	return a.usableHosts
}

// hostNumberToIP converts a 1-based host number to an IP address within
// the subnet. Host number 1 is the first usable address (network+1).
// For /31 subnets, host number 1 maps to the network address itself.
func (a *Allocator) hostNumberToIP(hostNum int) net.IP {
	if hostNum < 1 || hostNum > a.usableHosts {
		return nil
	}

	network := a.subnet.IP.To4()
	if network == nil {
		network = a.subnet.IP.To16()
	}

	// For /31 and /32, there's no network/broadcast exclusion,
	// so host number 1 maps to the network address itself.
	offset := hostNum - 1
	if a.hostBits >= 2 {
		offset = hostNum // skip network address (host 1 = network+1)
	}

	result := make(net.IP, len(network))
	copy(result, network)

	// Add offset to the IP (big-endian).
	carry := offset
	for i := len(result) - 1; i >= 0 && carry > 0; i-- {
		val := int(result[i]) + carry
		result[i] = byte(val & 0xFF)
		carry = val >> 8
	}

	return result
}

// hashToSlot computes a deterministic slot (0-based) for a public key
// given the total number of hosts. The slot is computed as:
//
//	hash(pubkey [+ salt]) % hostCount
//
// When salt is empty, the hash is just sha256(pubkey). When salt is
// non-empty, the hash is sha256(pubkey || salt).
func hashToSlot(pubKey string, salt int, hostCount int) int {
	h := sha256.New()
	h.Write([]byte(pubKey))
	if salt > 0 {
		var saltBytes [8]byte
		binary.LittleEndian.PutUint64(saltBytes[:], uint64(salt))
		h.Write(saltBytes[:])
	}
	hashBytes := h.Sum(nil)

	// Use the first 8 bytes as a uint64, then mod hostCount.
	val := binary.LittleEndian.Uint64(hashBytes[:8])
	return int(val % uint64(hostCount))
}

// Allocate computes the VirtualIP for a single node given its public
// key and the total number of mesh hosts (including itself).
//
// This is the simplest case: no known conflicts. The node takes slot
// hash(pubkey) % hostCount and converts it to an IP address.
//
// For conflict resolution, use AllocateWithPeers.
func (a *Allocator) Allocate(pubKey string, hostCount int) (net.IP, error) {
	if hostCount < 1 {
		return nil, fmt.Errorf("ipam: hostCount must be >= 1, got %d", hostCount)
	}
	if hostCount > a.usableHosts {
		return nil, fmt.Errorf("ipam: hostCount %d exceeds usable hosts %d in subnet %s",
			hostCount, a.usableHosts, a.subnet.String())
	}

	slot := hashToSlot(pubKey, 0, hostCount)
	// slot is 0-based; host number is 1-based.
	hostNum := slot + 1
	ip := a.hostNumberToIP(hostNum)
	if ip == nil {
		return nil, fmt.Errorf("ipam: computed slot %d out of range", slot)
	}
	return ip, nil
}

// AllocateWithPeers computes the VirtualIP for a node given its public
// key, the total host count, and the set of peer public keys (excluding
// self) that already have claimed IPs.
//
// Conflict resolution protocol:
//  1. Compute slot = hash(pubkey) % hostCount.
//  2. Check if any peer with a lexicographically SMALLER public key
//     has claimed this slot. If so, we (the larger key) must yield.
//  3. If we must yield, try salt=1,2,3,... until we find a free slot
//     that doesn't conflict with any peer's claimed slot.
//  4. If a peer with a LARGER public key has the same slot, we keep it
//     — the larger key will yield on their end.
//
// peerIPs maps peer public key → the VirtualIP that peer has claimed.
// The function returns the IP this node should use.
func (a *Allocator) AllocateWithPeers(pubKey string, hostCount int, peerIPs map[string]net.IP) (net.IP, error) {
	if hostCount < 1 {
		return nil, fmt.Errorf("ipam: hostCount must be >= 1, got %d", hostCount)
	}
	if hostCount > a.usableHosts {
		return nil, fmt.Errorf("ipam: hostCount %d exceeds usable hosts %d in subnet %s",
			hostCount, a.usableHosts, a.subnet.String())
	}

	// Build a set of claimed IPs (as string keys for comparison).
	claimed := make(map[string]bool, len(peerIPs))
	for _, ip := range peerIPs {
		claimed[ip.String()] = true
	}

	// Also build a set of peer public keys for lexicographic comparison.
	// We need to know which peers have which slot, but since we only get
	// peer IPs (not their slots), we compare by IP address: if our
	// computed IP matches a peer's IP, it's a conflict.
	//
	// For the conflict resolution, the rule is:
	//   - If our pubkey is lexicographically smaller than ALL conflicting
	//     peers, we keep our slot.
	//   - If ANY conflicting peer has a smaller pubkey, we yield.
	//
	// However, since peerIPs only gives us IPs (not pubkeys of the
	// conflicting peer), we need to also know which peer claims which IP.
	// Let's restructure: we also receive peerPubKeys for lexicographic
	// comparison.

	// Actually, the conflict check is simpler: we compute our candidate
	// IP. If no peer has claimed it, we're done. If a peer has claimed it,
	// we need to check if we should yield. We yield if ANY peer that
	// claims this IP has a pubkey lexicographically smaller than ours.
	// But since we only have peerIPs (keyed by pubkey), we can check.

	for salt := 0; salt <= MaxSaltIterations; salt++ {
		slot := hashToSlot(pubKey, salt, hostCount)
		hostNum := slot + 1
		candidateIP := a.hostNumberToIP(hostNum)
		if candidateIP == nil {
			continue
		}

		candidateStr := candidateIP.String()
		if !claimed[candidateStr] {
			// No conflict — this slot is free.
			return candidateIP, nil
		}

		// Conflict: check if we should yield.
		// Find the peer(s) that claimed this IP.
		mustYield := false
		for peerKey, peerIP := range peerIPs {
			if peerIP.String() == candidateStr {
				// This peer claims the same IP.
				// We yield if the peer's key is lexicographically smaller.
				// (The smaller key "wins" the slot.)
				if peerKey < pubKey {
					mustYield = true
					break
				}
			}
		}

		if !mustYield {
			// We have priority over all conflicting peers.
			// In practice, the larger-key peers should have already
			// yielded, but if they haven't yet (gossip propagation delay),
			// we still claim this IP — they'll re-allocate on their next
			// conflict detection cycle.
			return candidateIP, nil
		}

		// We must yield — try next salt.
		// If salt == 0 (first attempt), increment to salt=1.
		// Continue the loop.
	}

	return nil, fmt.Errorf("ipam: could not find a free slot after %d iterations (subnet may be full)",
		MaxSaltIterations)
}

// AllocateAll computes the complete IP assignment for a set of nodes.
// Given the list of all public keys in the mesh, it returns a map of
// pubkey → VirtualIP. This is the canonical reference assignment that
// every node should converge on.
//
// The algorithm:
//  1. Sort public keys lexicographically.
//  2. Process keys from smallest to largest. Each key gets
//     hash(key, 0) % hostCount. If that slot is taken, try salt=1,2,...
//     until a free slot is found.
//
// Since we process in lexicographic order, smaller keys always get
// priority — matching the conflict resolution protocol.
func (a *Allocator) AllocateAll(pubKeys []string) (map[string]net.IP, error) {
	hostCount := len(pubKeys)
	if hostCount == 0 {
		return map[string]net.IP{}, nil
	}
	if hostCount > a.usableHosts {
		return nil, fmt.Errorf("ipam: %d nodes exceed usable hosts %d in subnet %s",
			hostCount, a.usableHosts, a.subnet.String())
	}

	// Sort keys lexicographically (ascending).
	sorted := make([]string, len(pubKeys))
	copy(sorted, pubKeys)
	sort.Strings(sorted)

	// Track which IPs are claimed and by whom.
	claimed := make(map[string]net.IP, hostCount)
	result := make(map[string]net.IP, hostCount)

	for _, key := range sorted {
		ip, err := a.allocateWithClaimed(key, hostCount, claimed)
		if err != nil {
			return nil, fmt.Errorf("ipam: failed to allocate for key %s: %w", key[:min(len(key), 16)], err)
		}
		result[key] = ip
		claimed[ip.String()] = ip
	}

	return result, nil
}

// allocateWithClaimed is the internal allocation function that works
// against a set of already-claimed IP strings (not pubkey→IP map).
// It tries salt=0,1,2,... until it finds a slot whose IP is not in
// the claimed set.
func (a *Allocator) allocateWithClaimed(pubKey string, hostCount int, claimed map[string]net.IP) (net.IP, error) {
	for salt := 0; salt <= MaxSaltIterations; salt++ {
		slot := hashToSlot(pubKey, salt, hostCount)
		hostNum := slot + 1
		candidateIP := a.hostNumberToIP(hostNum)
		if candidateIP == nil {
			continue
		}
		if _, taken := claimed[candidateIP.String()]; !taken {
			return candidateIP, nil
		}
	}
	return nil, fmt.Errorf("ipam: no free slot after %d iterations", MaxSaltIterations)
}

// ResolveConflict determines whether a node should re-allocate its
// VirtualIP after discovering a conflict.
//
// Returns true if this node should yield (re-allocate with salt),
// false if it should keep its current IP.
//
// The node yields if the conflicting peer's public key is
// lexicographically smaller than this node's public key.
func ResolveConflict(selfPubKey, peerPubKey string) bool {
	return peerPubKey < selfPubKey
}
