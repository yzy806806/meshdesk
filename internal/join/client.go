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

// JoinerSigner is the interface for signing challenges during the
// challenge-response step of the join protocol. The joiner must
// prove ownership of its claimed Ed25519 public key by signing
// the server-issued challenge.
//
// In production, this is implemented by *identity.Identity.
type JoinerSigner interface {
	// Sign signs data with the joiner's Ed25519 private key.
	// Returns a hex-encoded signature.
	Sign(data []byte) (string, error)
}

// ClientConfig holds the configuration for the join client.
type ClientConfig struct {
	// ServerURL is the base URL of the join server (e.g., "https://bootstrap:8443").
	// Must use https:// unless AllowPlainHTTP is true.
	ServerURL string

	// Token is the base64-encoded join token.
	Token string

	// JoinerPublicKey is this node's Ed25519 public key (hex).
	JoinerPublicKey string

	// JoinerHostname is this node's hostname.
	JoinerHostname string

	// JoinerEndpoint is this node's reachable endpoint (optional).
	JoinerEndpoint string

	// JoinerSigner is used to sign the challenge during step 2.
	// If nil, the challenge-response step cannot be completed and
	// RequestJoin will fail.
	JoinerSigner JoinerSigner

	// Timeout is the maximum time to wait for the join response.
	// Default: 30 seconds.
	Timeout time.Duration

	// TLSConfig is an optional TLS configuration for the HTTP client.
	// If InsecureSkipVerify is false and no custom RootCAs are set,
	// the client uses the system trust store. For self-signed certs,
	// set InsecureSkipVerify=true (not recommended for production).
	// For REALITY-pinned connections, set ServerName to the expected SNI.
	TLSConfig *tls.Config

	// AllowPlainHTTP permits connections to non-HTTPS join servers.
	// This is NOT recommended for production — the config bundle
	// (containing REALITY keys, identity material, and collector lists)
	// will be transmitted in plaintext over the network. Only enable
	// for testing on trusted networks.
	AllowPlainHTTP bool
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
//
// The protocol is a two-step challenge-response flow:
//  1. The client sends the token + joiner public key. The server
//     validates the token and returns a random challenge.
//  2. The client signs the challenge with its Ed25519 private key
//     and sends it back. The server verifies the signature and
//     returns the config bundle.
//
// This proves the client owns the private key for the claimed public
// key, preventing impersonation even if an attacker steals a token.
//
// The request must be over HTTPS unless AllowPlainHTTP is set.
func (c *JoinClient) RequestJoin(ctx context.Context) (*ConfigBundle, error) {
	// Enforce HTTPS by default.
	if !startsWithHTTPS(c.cfg.ServerURL) && !c.cfg.AllowPlainHTTP {
		return nil, fmt.Errorf("join: refusing to use non-HTTPS server URL %q — config bundle would be transmitted in plaintext; set AllowPlainHTTP=true to override (not recommended for production)", c.cfg.ServerURL)
	}
	if !startsWithHTTPS(c.cfg.ServerURL) && c.cfg.AllowPlainHTTP {
		log.Printf("[join] WARNING: AllowPlainHTTP is true — config bundle will be transmitted in plaintext to %s", c.cfg.ServerURL)
	}

	// Validate that we have a signer for the challenge-response step.
	if c.cfg.JoinerSigner == nil {
		return nil, fmt.Errorf("join: JoinerSigner is required for challenge-response verification")
	}

	httpClient := &http.Client{
		Timeout: c.cfg.Timeout,
	}
	if c.cfg.TLSConfig != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: c.cfg.TLSConfig,
		}
	}

	// Step 1: Request challenge.
	challenge, err := c.requestChallenge(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("challenge step: %w", err)
	}

	// Step 2: Sign challenge and request bundle.
	bundle, err := c.requestBundle(ctx, httpClient, challenge)
	if err != nil {
		return nil, fmt.Errorf("challenge-response step: %w", err)
	}

	log.Printf("[join] received config bundle from server (pubkey=%s, endpoint=%s, collectors=%d, peers=%d)",
		shortHex(bundle.BootstrapPublicKey),
		bundle.BootstrapEndpoint,
		len(bundle.Collectors),
		len(bundle.KnownPeers))

	return bundle, nil
}

// requestChallenge sends the initial join request (step 1) and
// returns the server-issued challenge.
func (c *JoinClient) requestChallenge(ctx context.Context, httpClient *http.Client) (string, error) {
	reqBody := JoinRequest{
		Token:           c.cfg.Token,
		JoinerPublicKey: c.cfg.JoinerPublicKey,
		JoinerHostname:  c.cfg.JoinerHostname,
		JoinerEndpoint:  c.cfg.JoinerEndpoint,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal join request: %w", err)
	}

	url := c.cfg.ServerURL + "/api/join"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("challenge request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	var joinResp JoinResponse
	if err := json.Unmarshal(respBody, &joinResp); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}

	if !joinResp.Success {
		return "", fmt.Errorf("join rejected: %s", joinResp.Error)
	}

	if joinResp.Challenge == "" {
		return "", fmt.Errorf("server did not return a challenge")
	}

	// Step 1 must NOT return a bundle — it should only return the challenge.
	// If a bundle is returned, the server has not implemented the
	// challenge-response enforcement.
	if joinResp.Bundle != nil {
		return "", fmt.Errorf("server returned bundle in step 1 — challenge-response not enforced")
	}

	log.Printf("[join] received challenge from server (len=%d)", len(joinResp.Challenge))
	return joinResp.Challenge, nil
}

// requestBundle signs the challenge and sends it back (step 2) to
// receive the config bundle.
func (c *JoinClient) requestBundle(ctx context.Context, httpClient *http.Client, challenge string) (*ConfigBundle, error) {
	// Sign the challenge with the joiner's private key.
	challengeBytes := []byte(challenge)
	sig, err := c.cfg.JoinerSigner.Sign(challengeBytes)
	if err != nil {
		return nil, fmt.Errorf("sign challenge: %w", err)
	}

	reqBody := JoinRequest{
		Token:             c.cfg.Token,
		JoinerPublicKey:   c.cfg.JoinerPublicKey,
		JoinerHostname:    c.cfg.JoinerHostname,
		JoinerEndpoint:    c.cfg.JoinerEndpoint,
		Challenge:         challenge,
		ChallengeResponse: sig,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal challenge response: %w", err)
	}

	url := c.cfg.ServerURL + "/api/join"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("challenge response request: %w", err)
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

	return joinResp.Bundle, nil
}

// startsWithHTTPS checks if a URL starts with "https://".
func startsWithHTTPS(url string) bool {
	return len(url) >= 8 && url[:8] == "https://"
}
