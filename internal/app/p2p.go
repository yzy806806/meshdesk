package app

import (
	"log"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// startP2P connects statically configured peers. The gossip layer has
// been removed; static peers are the only connection mechanism.
//
// Connections are maintained indefinitely: if a peer goes down (restart,
// network flap), this loop reconnects with exponential backoff capped
// at 60s. This is critical for resilience — without it, a shared node
// restart permanently partitions ordinary nodes that booted before it.
//
// Once a session is established, session_reconnect.go's watcher takes
// over monitoring and reconnecting. This loop does NOT poll the session
// state — that would race with the watcher (double-dial, conflicting
// reconnect attempts). Instead, after a successful AddPeer, we sleep
// 5 minutes and check: if the session is still alive, skip (the watcher
// owns it); if the session is gone AND no reconnect tracker exists
// (watcher died), re-run AddPeer as a safety net.
func (a *App) startP2P() {
	cfg, node := a.cfg, a.node

	for _, peerCfg := range cfg.Peers {
		if peerCfg.Endpoint == "" {
			continue
		}
		go func(pc config.PeerConfig) {
			backoff := 5 * time.Second
			maxBackoff := 60 * time.Second
			for attempt := 0; ; attempt++ {
				// Safety-net: skip AddPeer if a session to this peer
				// is already alive — calling AddPeer would close and
				// rebuild it unnecessarily. The session watcher in
				// session_reconnect.go owns live-session monitoring.
				if node.HasPeerSession(pc.PublicKey) {
					select {
					case <-a.node.Context().Done():
						return
					case <-time.After(5 * time.Minute):
						// Re-check after 5 minutes.
						continue
					}
				}

				if err := node.AddPeer(pc); err != nil {
					if attempt < 3 {
						log.Printf("Warning: peer %s connect attempt %d failed: %v",
							pc.Endpoint, attempt+1, err)
					} else if attempt%12 == 0 {
						// After initial 3 attempts, log every ~12 cycles
						// (at 60s backoff ≈ every 12 min) to avoid noise.
						log.Printf("[mesh] peer %s still unreachable (attempt %d), retrying",
							pc.Endpoint, attempt+1)
					}
					select {
					case <-a.node.Context().Done():
						return
					case <-time.After(backoff):
					}
					backoff = min(backoff*2, maxBackoff)
					continue
				}

				// Session established. Reset backoff and let the
				// loop continue — the next iteration's HasPeerSession
				// check will guard the live session.
				log.Printf("  Connected peer: %s", pc.Endpoint)
				backoff = 5 * time.Second
			}
		}(peerCfg)
	}
}

// stopGossip is a no-op (gossip layer removed).
func (a *App) stopGossip() {}
