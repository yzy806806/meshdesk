package join

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// ClientConfig holds the configuration for the join client.
type ClientConfig struct {
	// ServerURL is the base URL of the join server (e.g., "https://bootstrap:8443").
	ServerURL string

	// Token is the base64-encoded join token.
	Token string

	// JoinerPublicKey is this node's Ed25519 public key (hex).
	JoinerPublicKey string

	// JoinerHostname is this node's hostname.
	JoinerHostname string

	// JoinerEndpoint is this node's reachable endpoint (optional).
	JoinerEndpoint string

	// Timeout is the maximum time to wait for the join response.
	// Default: 30 seconds.
	Timeout time.Duration

	// TLSConfig is an optional TLS configuration for the HTTP client.
	// If InsecureSkipVerify is false and no custom RootCAs are set,
	// the client uses the system trust store. For self-signed certs,
	// set InsecureSkipVerify=true (not recommended for production).
	// For REALITY-pinned connections, set ServerName to the expected SNI.
	TLSConfig *tls.Config
}

// JoinClient is the HTTP client for the auto-join protocol.
type JoinClient struct {
	cfg ClientConfig
}

// NewJoinClient creates a new join client with the given config.
func NewJoinClient(cfg ClientConfig) *JoinClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &JoinClient{cfg: cfg}
}

// RequestJoin sends a join request to the server and returns the config bundle.
// The request is sent over HTTPS to ensure confidentiality of the distributed
// config (identity, REALITY keys, collector list).
func (c *JoinClient) RequestJoin(ctx context.Context) (*ConfigBundle, error) {
	reqBody := JoinRequest{
		Token:            c.cfg.Token,
		JoinerPublicKey:  c.cfg.JoinerPublicKey,
		JoinerHostname:   c.cfg.JoinerHostname,
		JoinerEndpoint:   c.cfg.JoinerEndpoint,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal join request: %w", err)
	}

	url := c.cfg.ServerURL + "/api/join"
	if !startsWithHTTPS(c.cfg.ServerURL) {
		log.Printf("[join] WARNING: server URL is not HTTPS — config bundle will be transmitted in plaintext")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Build the HTTP client with TLS config.
	httpClient := &http.Client{
		Timeout: c.cfg.Timeout,
	}
	if c.cfg.TLSConfig != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: c.cfg.TLSConfig,
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("join request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var joinResp JoinResponse
	if err := json.Unmarshal(respBody, &joinResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	if !joinResp.Success {
		return nil, fmt.Errorf("join rejected: %s", joinResp.Error)
	}

	if joinResp.Bundle == nil {
		return nil, fmt.Errorf("join response missing config bundle")
	}

	log.Printf("[join] received config bundle from server (pubkey=%s, endpoint=%s, collectors=%d, peers=%d)",
		shortHex(joinResp.Bundle.BootstrapPublicKey),
		joinResp.Bundle.BootstrapEndpoint,
		len(joinResp.Bundle.Collectors),
		len(joinResp.Bundle.KnownPeers))

	return joinResp.Bundle, nil
}

// startsWithHTTPS checks if a URL starts with "https://".
func startsWithHTTPS(url string) bool {
	return len(url) >= 8 && url[:8] == "https://"
}
