package app

import (
	"log"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// startP2P connects statically configured peers. The gossip layer has
// been removed; static peers are the only connection mechanism.
// Connections are maintained indefinitely: if a peer goes down (restart,
// network flap), this loop reconnects with exponential backoff capped
// at 60s. This is critical for resilience — without it, a shared node
// restart permanently partitions ordinary nodes that booted before it.
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
				if err := node.AddPeer(pc); err != nil {
					if attempt < 3 {
						log.Printf("Warning: peer %s connect attempt %d failed: %v", pc.Endpoint, attempt+1, err)
					} else if attempt%12 == 0 {
						// After initial 3 attempts, log every ~12 cycles
						// (at 60s backoff = every ~12min) to avoid noise.
						log.Printf("[mesh] peer %s still unreachable (attempt %d), retrying", pc.Endpoint, attempt+1)
					}
					time.Sleep(backoff)
					backoff = min(backoff*2, maxBackoff)
					continue
				}
				log.Printf("  Connected peer: %s", pc.Endpoint)
				// AddPeer is non-blocking: it dials and returns once
				// the session is established. Monitor the session and
				// reconnect if it dies. The session watcher in
				// session_reconnect.go handles its own reconnection,
				// but if all attempts are exhausted (or the watcher
				// never started because the initial session died
				// before watchSession was set up), this loop is the
				// safety net.
				backoff = 5 * time.Second // reset backoff on success
				ticker := time.NewTicker(30 * time.Second)
				for {
					select {
					case <-a.node.Context().Done():
						ticker.Stop()
						return
					case <-ticker.C:
						// If the session to this peer is gone,
						// break out and reconnect.
						if !node.HasPeerSession(pc.PublicKey) {
							ticker.Stop()
							log.Printf("[mesh] peer %s session lost, reconnecting", pc.Endpoint)
							time.Sleep(backoff)
							backoff = min(backoff*2, maxBackoff)
							goto reconnect
						}
					}
				}
			reconnect:
			}
		}(peerCfg)
	}
}

// stopGossip is a no-op (gossip layer removed).
func (a *App) stopGossip() {}
