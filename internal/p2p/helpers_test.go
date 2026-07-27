package p2p

// testMeshIP is a test helper that returns a deterministic mesh IP string
// from a public key. In v2, mesh IPs are deprecated — this helper exists
// only to set NodeMeta.MeshIP in tests for gossip wire compatibility.
func testMeshIP(pubKeyHex string) string {
	if len(pubKeyHex) < 4 {
		return "10.10.0.1"
	}
	return "10.10." + pubKeyHex[:2] + "." + pubKeyHex[2:4]
}

// testMeshCIDR wraps a mesh IP in /32 CIDR notation for test AllowedIPs.
func testMeshCIDR(meshIP string) string {
	if len(meshIP) > 0 && meshIP[len(meshIP)-1] != '/' {
		// Check if already has CIDR
		hasSlash := false
		for _, c := range meshIP {
			if c == '/' {
				hasSlash = true
				break
			}
		}
		if !hasSlash {
			return meshIP + "/32"
		}
	}
	return meshIP
}
