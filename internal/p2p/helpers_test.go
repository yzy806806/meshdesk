package p2p

// testEndpoint returns a deterministic endpoint string from a public key hex.
// Used in tests where a peer needs at least one endpoint.
func testEndpoint(pubKeyHex string) string {
	if len(pubKeyHex) < 4 {
		return "203.0.113.1:51820"
	}
	return "203.0.113." + pubKeyHex[:2] + "." + pubKeyHex[2:4] + ":51820"
}
