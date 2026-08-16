package app

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/identity"
	"github.com/yzy806806/meshdesk/internal/join"
)

// startJoinServer starts the auto-join server (shared nodes with
// Reality TLS). The join endpoint is served via the Dashboard mux on
// shared nodes, or on join.listen_addr otherwise.
func (a *App) startJoinServer() {
	if a.cfg.Join.Enabled && a.cfg.Reality.Enabled {
		// Derive the X25519 public key from the server's private key.
		// The joiner needs the PUBLIC key to connect via Reality TLS.
		realityPubHex := ""
		if privBytes, err := hex.DecodeString(a.cfg.Reality.PrivateKey); err == nil && len(privBytes) == 32 {
			if realityPriv, err := ecdh.X25519().NewPrivateKey(privBytes); err == nil {
				realityPubHex = hex.EncodeToString(realityPriv.PublicKey().Bytes())
			}
		}
		if realityPubHex == "" {
			log.Printf("Warning: invalid reality.private_key — join server disabled")
		} else {
			joinServerCfg := join.ServerConfig{
				Secret:            []byte(a.cfg.Join.Secret),
				ServerIdentity:    a.node.Identity(),
				BootstrapEndpoint: firstAdvertiseEndpointHost(a.cfg),
				GossipPort:        a.cfg.Mesh.Port,
				RealityPublicKey:  realityPubHex, // Derived X25519 public key
				RealityShortID:    firstShortID(a.cfg.Reality.ShortIDs),
				RealityServerName: firstServerName(a.cfg.Reality.ServerNames),
				Collectors:        a.cfg.Monitoring.Collectors,
				TokenLifetime:     time.Duration(a.cfg.Join.TokenLifetime) * time.Second,
			}

			// If the join secret is empty, generate a random one and log a warning.
			if a.cfg.Join.Secret == "" {
				randomSecret := make([]byte, 32)
				if _, err := rand.Read(randomSecret); err != nil {
					log.Printf("Warning: failed to generate random join secret: %v — join server disabled", err)
				} else {
					a.cfg.Join.Secret = hex.EncodeToString(randomSecret)
					// Do NOT log the secret itself (credential in logs).
					// Tell the operator where to set it instead.
					log.Printf("WARNING: join.secret not set — a random secret was generated for this session")
					log.Printf("  Persist it in the config (join.secret) to keep tokens valid across restarts")
				}
			}
			joinServerCfg.Secret = []byte(a.cfg.Join.Secret)

			a.joinServer = join.NewJoinServer(joinServerCfg)
			}
	}
}

func firstAdvertiseEndpointHost(cfg *config.Config) string {
	if len(cfg.P2P.AdvertiseEndpoints) > 0 {
		ep := cfg.P2P.AdvertiseEndpoints[0]
		if idx := strings.LastIndex(ep, ":"); idx > 0 {
			return ep[:idx]
		}
		return ep
	}
	host := cfg.Node.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	return host
}

func firstShortID(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func firstServerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

type nodeJoinTokenGenerator struct {
	cfg      *config.Config
	identity *identity.Identity
}

func (g *nodeJoinTokenGenerator) GenerateJoinToken(lifetime time.Duration) (string, error) {
	if g.cfg.Join.Secret == "" {
		return "", fmt.Errorf("join.secret not configured")
	}
	serverFP := ""
	if g.identity != nil {
		serverFP = g.identity.PublicKey
	}
	return join.GenerateToken([]byte(g.cfg.Join.Secret), serverFP, lifetime)
}
