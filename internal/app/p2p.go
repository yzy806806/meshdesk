package app

import (
	"log"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// startP2P connects statically configured peers. The gossip layer has
// been removed; static peers are the only connection mechanism.
func (a *App) startP2P() {
	cfg, node := a.cfg, a.node

	// Connect statically configured peers.
	for _, peerCfg := range cfg.Peers {
		if peerCfg.Endpoint != "" {
			go func(pc config.PeerConfig) {
				backoff := 5 * time.Second
				for attempt := 0; attempt < 3; attempt++ {
					if err := node.AddPeer(pc); err != nil {
						log.Printf("Warning: peer %s connect attempt %d failed: %v", pc.Endpoint, attempt+1, err)
						time.Sleep(backoff)
						backoff *= 2
						continue
					}
					log.Printf("  Connected peer: %s", pc.Endpoint)
					return
				}
				log.Printf("  Peer %s: all connect attempts failed", pc.Endpoint)
			}(peerCfg)
		}
	}
}

// stopGossip is a no-op (gossip layer removed).
func (a *App) stopGossip() {}
