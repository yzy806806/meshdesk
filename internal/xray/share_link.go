package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// VLESSShareLink generates a VLESS share link for a given client
// connecting to a server. The link format is:
//
//	vless://<uuid>@<address>:<port>?encryption=none&security=<security>&type=<network>&flow=<flow>...
//
// For REALITY, additional parameters include:
//   - pbk (public key, base64url of X25519)
//   - sid (short ID)
//   - fp (fingerprint, e.g., chrome)
//   - sni (server name / SNI)
//   - spx (spider X, optional)
func VLESSShareLink(uuid, address string, port int, params VLESSShareParams) string {
	q := url.Values{}

	// Required params
	q.Set("encryption", "none")
	q.Set("security", params.Security)
	if params.Security == "" {
		q.Set("security", "reality")
	}
	q.Set("type", params.Network)
	if params.Network == "" {
		q.Set("type", "tcp")
	}

	if params.Flow != "" {
		q.Set("flow", params.Flow)
	}

	// REALITY params
	if params.Security == "reality" || params.Security == "" {
		if params.PublicKey != "" {
			q.Set("pbk", params.PublicKey)
		}
		if params.ShortID != "" {
			q.Set("sid", params.ShortID)
		}
		if params.Fingerprint != "" {
			q.Set("fp", params.Fingerprint)
		}
		if params.ServerName != "" {
			q.Set("sni", params.ServerName)
		}
		if params.SpiderX != "" {
			q.Set("spx", params.SpiderX)
		}
	}

	// TLS params
	if params.Security == "tls" && params.ServerName != "" {
		q.Set("sni", params.ServerName)
		if params.Fingerprint != "" {
			q.Set("fp", params.Fingerprint)
		}
	}

	// WebSocket params
	if params.Network == "ws" {
		if params.WSPath != "" {
			q.Set("path", params.WSPath)
		}
		if params.WSHost != "" {
			q.Set("host", params.WSHost)
		}
	}

	// Fragment / remark
	fragment := ""
	if params.Remark != "" {
		fragment = "#" + url.PathEscape(params.Remark)
	}

	return fmt.Sprintf("vless://%s@%s:%d?%s%s",
		uuid, address, port, q.Encode(), fragment)
}

// VLESSShareParams holds the parameters for generating a VLESS share link.
type VLESSShareParams struct {
	Security string // "reality", "tls", "none"
	Network  string // "tcp", "ws"
	Flow     string // "xtls-rprx-vision" or ""
	Remark   string // display name / remark

	// REALITY fields
	PublicKey   string // server's X25519 public key (base64url)
	ShortID     string // short ID (hex)
	Fingerprint string // uTLS fingerprint (chrome, firefox, safari, ...)
	ServerName  string // SNI
	SpiderX     string // spider crawl path (optional)

	// TLS fields
	// (ServerName + Fingerprint are shared with REALITY)

	// WebSocket fields
	WSPath string // WebSocket path
	WSHost string // WebSocket Host header
}

// GenerateShareLinkForInbound generates a VLESS share link for a specific
// client on an inbound, using the server's address and the inbound's
// REALITY/TLS parameters.
//
// serverAddress is the public IP or hostname clients connect to.
// For REALITY, the public key is derived from the inbound's private key
// via X25519.
func GenerateShareLinkForInbound(ic *InboundConfig, client VLESSClient, serverAddress string) (string, error) {
	params := VLESSShareParams{
		Security:    ic.Security,
		Network:     ic.Network,
		Flow:        client.Flow,
		Remark:      client.Email,
		Fingerprint: "chrome",
	}

	if ic.Security == "reality" || ic.Security == "" {
		params.Security = "reality"
		// Derive public key from private key
		pub, err := DerivePublicKey(ic.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("derive public key: %w", err)
		}
		params.PublicKey = pub
		if len(ic.ShortIds) > 0 {
			params.ShortID = ic.ShortIds[0]
		}
		if len(ic.ServerNames) > 0 {
			params.ServerName = ic.ServerNames[0]
		}
	} else if ic.Security == "tls" {
		if len(ic.ServerNames) > 0 {
			params.ServerName = ic.ServerNames[0]
		}
	}

	link := VLESSShareLink(client.ID, serverAddress, ic.Port, params)
	return link, nil
}

// DerivePublicKey derives the X25519 public key from a base64-standard
// encoded private key. xray-core uses base64 standard (not URL-safe)
// for X25519 keys in REALITY config.
func DerivePublicKey(privateKeyB64 string) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	pubBytes, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pubBytes), nil
}

// VLESSLinkInfo is the parsed representation of a VLESS share link,
// used for display in the UI.
type VLESSLinkInfo struct {
	UUID        string `json:"uuid"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Security    string `json:"security"`
	Network     string `json:"network"`
	Flow        string `json:"flow,omitempty"`
	Remark      string `json:"remark,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	ShortID     string `json:"short_id,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
}

// ParseVLESSLink parses a vless:// share link into structured info.
func ParseVLESSLink(link string) (*VLESSLinkInfo, error) {
	if !strings.HasPrefix(link, "vless://") {
		return nil, fmt.Errorf("not a vless link")
	}

	rest := strings.TrimPrefix(link, "vless://")

	// Extract fragment (remark)
	remark := ""
	if idx := strings.Index(rest, "#"); idx >= 0 {
		remark, _ = url.PathUnescape(rest[idx+1:])
		rest = rest[:idx]
	}

	// Split user@host:port?params
	atIdx := strings.Index(rest, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid vless link: missing @")
	}
	uuid := rest[:atIdx]
	rest = rest[atIdx+1:]

	// Split host:port and query
	queryStr := ""
	if qIdx := strings.Index(rest, "?"); qIdx >= 0 {
		queryStr = rest[qIdx+1:]
		rest = rest[:qIdx]
	}

	// Split host:port
	colonIdx := strings.LastIndex(rest, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("invalid vless link: missing port")
	}
	address := rest[:colonIdx]
	portStr := rest[colonIdx+1:]
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	params, err := url.ParseQuery(queryStr)
	if err != nil {
		return nil, fmt.Errorf("parse query: %w", err)
	}

	info := &VLESSLinkInfo{
		UUID:        uuid,
		Address:     address,
		Port:        port,
		Security:    params.Get("security"),
		Network:     params.Get("type"),
		Flow:        params.Get("flow"),
		Remark:      remark,
		PublicKey:   params.Get("pbk"),
		ShortID:     params.Get("sid"),
		Fingerprint: params.Get("fp"),
		ServerName:  params.Get("sni"),
	}

	return info, nil
}

// X25519PublicKeyJSON is a helper that returns the public key in a JSON
// structure suitable for API responses.
type X25519PublicKeyJSON struct {
	PublicKey string `json:"public_key"`
}

// MarshalPublicKeyJSON wraps DerivePublicKey for JSON output.
func MarshalPublicKeyJSON(privateKeyB64 string) ([]byte, error) {
	pub, err := DerivePublicKey(privateKeyB64)
	if err != nil {
		return nil, err
	}
	return json.Marshal(X25519PublicKeyJSON{PublicKey: pub})
}
