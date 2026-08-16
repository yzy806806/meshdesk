package app

// topology_paths.go — The P2P PeerLinkMap (global topology link state)
// has been removed along with the gossip layer. The topology path info
// is now nil — the web server falls back to its existing nil-safe
// behavior (no topology edges, or proxy path probe results if available).
