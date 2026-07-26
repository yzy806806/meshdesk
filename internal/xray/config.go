// Package xray implements the managed-subprocess config layer for xray-core.
//
// It provides:
//   - Go structs matching xray-core's JSON config schema (config.go)
//   - A config manager that generates JSON configs, manages the xray-core
//     subprocess (start/stop/reload), auto-restarts on crash with
//     exponential backoff, and captures stdout/stderr to a ring buffer
//     for the Dashboard log viewer (manager.go)
//   - REST API handlers for POST/GET/DELETE /api/xray/inbound (handlers in web pkg)
//
// Architecture (per motion-dfa7426d3d4b action item 3):
//
//	MeshDesk Node
//	├── meshdesk binary (Go)
//	│   ├── WireGuard + gVisor netstack
//	│   ├── REST API Server (Dashboard)
//	│   └── XrayConfigManager
//	│       ├── GenerateJSONConfig() → /var/lib/meshdesk/xray/config.json
//	│       ├── Start()              → exec xray run -config <path>
//	│       ├── Reload()             → SIGHUP to xray PID
//	│       └── log capture          → stdout/stderr → ring buffer
//	│
//	└── xray-core (external binary)
//	    └── VLESS + REALITY + XTLS Vision
//
// The xray-core binary is NOT embedded — it must be installed separately
// (e.g., via package manager or direct download). The manager auto-detects
// the binary path (checking "xray" in PATH, then common install locations).
package xray

import "encoding/json"

// XrayConfig is the top-level xray-core configuration object.
// This maps directly to the JSON that xray-core reads via -config.
type XrayConfig struct {
	Log       *LogConfig     `json:"log"`
	Inbounds  []Inbound      `json:"inbounds"`
	Outbounds []Outbound     `json:"outbounds"`
	Routing   *RoutingConfig `json:"routing,omitempty"`
}

// LogConfig controls xray-core's internal logging.
type LogConfig struct {
	LogLevel string `json:"loglevel"` // "debug" | "info" | "warning" | "error" | "none"
}

// Inbound describes a single xray inbound listener (server-side).
type Inbound struct {
	Tag            string          `json:"tag"`
	Port           int             `json:"port"`
	Listen         string          `json:"listen,omitempty"` // default "0.0.0.0"
	Protocol       string          `json:"protocol"`         // "vless", "vmess", "trojan", etc.
	Settings       json.RawMessage `json:"settings"`         // protocol-specific settings
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Sniffing       *SniffingConfig `json:"sniffing,omitempty"`
}

// StreamSettings holds transport-layer + security configuration.
type StreamSettings struct {
	Network         string           `json:"network"`  // "tcp" | "ws" | "grpc" | ...
	Security        string           `json:"security"` // "none" | "tls" | "reality" | "xtls"
	RealitySettings *RealitySettings `json:"realitySettings,omitempty"`
	TLSSettings     *TLSSettings     `json:"tlsSettings,omitempty"`
	WSSettings      *WSSettings      `json:"wsSettings,omitempty"`
}

// RealitySettings mirrors xray-core's RealityObject for both server-side
// (inbound) and client-side (outbound) REALITY TLS 1.3 configuration.
//
// Server-side fields are populated for inbounds; client-side fields for
// outbounds. The same struct is used for both — xray-core disambiguates
// by context (inbound vs outbound).
type RealitySettings struct {
	// --- Server-side (inbound) fields ---
	Show         bool     `json:"show"`                   // debug: print REALITY keys (default false)
	Dest         string   `json:"dest,omitempty"`         // camouflage target "host:port"
	Xver         int      `json:"xver,omitempty"`         // PROXY protocol version (0/1/2)
	ServerNames  []string `json:"serverNames,omitempty"`  // accepted SNI list
	PrivateKey   string   `json:"privateKey,omitempty"`   // X25519 private key (base64)
	ShortIds     []string `json:"shortIds,omitempty"`     // per-client hex IDs (even length, max 16 chars)
	MinClientVer string   `json:"minClientVer,omitempty"` // min xray version (e.g., "1.8.0")
	MaxClientVer string   `json:"maxClientVer,omitempty"` // max xray version
	MaxTimeDiff  int      `json:"maxTimeDiff,omitempty"`  // max clock skew tolerance (ms)

	// --- Client-side (outbound) fields ---
	Fingerprint string `json:"fingerprint,omitempty"` // uTLS fingerprint: chrome|firefox|safari|...
	ServerName  string `json:"serverName,omitempty"`  // SNI sent in ClientHello
	Password    string `json:"password,omitempty"`    // X25519 public key + auth tag (preferred over publicKey)
	ShortId     string `json:"shortId,omitempty"`     // one of server's shortIds
	SpiderX     string `json:"spiderX,omitempty"`     // spider crawl path hint
}

// TLSSettings holds standard TLS configuration (for non-Reality TLS).
type TLSSettings struct {
	ServerName   string   `json:"serverName,omitempty"`
	Certificates []Cert   `json:"certificates,omitempty"`
	ALPN         []string `json:"alpn,omitempty"`
}

// Cert represents a certificate/key pair for TLS.
type Cert struct {
	CertificateFile string `json:"certificateFile,omitempty"`
	KeyFile         string `json:"keyFile,omitempty"`
	Certificate     string `json:"certificate,omitempty"` // inline PEM
	Key             string `json:"key,omitempty"`         // inline PEM
}

// WSSettings holds WebSocket transport settings.
type WSSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

// SniffingConfig enables protocol detection for traffic routing.
type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride,omitempty"` // "http", "tls", "quic"
	RouteOnly    bool     `json:"routeOnly,omitempty"`
}

// RoutingConfig holds xray routing rules.
type RoutingConfig struct {
	DomainStrategy string        `json:"domainStrategy,omitempty"` // "AsIs" | "IPIfit" | ...
	Rules          []RoutingRule `json:"rules,omitempty"`
}

// RoutingRule is a single routing rule.
type RoutingRule struct {
	Type        string   `json:"type,omitempty"` // "field" (default)
	OutboundTag string   `json:"outboundTag"`    // target outbound tag
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
}

// Outbound describes a single xray outbound (client-side or direct).
type Outbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"` // "freedom" | "vless" | "vmess" | "blackhole" | ...
	Settings       json.RawMessage `json:"settings"` // protocol-specific
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
}

// VLESSInboundSettings holds the settings object for a VLESS inbound.
type VLESSInboundSettings struct {
	Clients    []VLESSClient `json:"clients"`
	Decryption string        `json:"decryption"` // must be "none"
}

// VLESSClient represents one authorized VLESS user on the server side.
type VLESSClient struct {
	ID    string `json:"id"`              // VLESS UUID
	Flow  string `json:"flow,omitempty"`  // "xtls-rprx-vision" | ""
	Email string `json:"email,omitempty"` // optional, for identification
}

// VLESSOutboundSettings holds the settings object for a VLESS outbound.
type VLESSOutboundSettings struct {
	VNext []VLESSOutboundServer `json:"vnext"`
}

// VLESSOutboundServer holds destination address + user credentials.
type VLESSOutboundServer struct {
	Address string      `json:"address"`
	Port    int         `json:"port"`
	Users   []VLESSUser `json:"users"`
}

// VLESSUser represents a user entry in the outbound config.
type VLESSUser struct {
	ID         string `json:"id"`
	Flow       string `json:"flow,omitempty"`
	Encryption string `json:"encryption"` // "none"
}

// FreedomOutboundSettings is the settings object for a "freedom" outbound.
type FreedomOutboundSettings struct {
	DomainStrategy string `json:"domainStrategy,omitempty"` // "AsIs" | "UseIP" | "UseIPv4v6"
}

// InboundConfig is the managed representation of a single inbound
// listener, stored by the XrayConfigManager. It contains all the
// information needed to generate the corresponding xray-core inbound
// JSON block, plus metadata for the Dashboard.
type InboundConfig struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"` // "vless-reality", "vless-tls", etc.
	Port     int    `json:"port"`
	Listen   string `json:"listen"`   // "0.0.0.0" or specific IP
	Network  string `json:"network"`  // "tcp" (default), "ws"
	Security string `json:"security"` // "reality", "tls", "none"

	// Reality fields (when Security == "reality")
	Dest        string   `json:"dest,omitempty"`         // camouflage target
	ServerNames []string `json:"server_names,omitempty"` // accepted SNI list
	PrivateKey  string   `json:"private_key,omitempty"`  // X25519 private key (server-side)
	ShortIds    []string `json:"short_ids,omitempty"`    // per-client hex IDs

	// TLS fields (when Security == "tls")
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`

	// VLESS clients (authorized users)
	VLESSClients []VLESSClient `json:"vless_clients,omitempty"`

	// Outbound peer info (for client-side configs)
	PeerAddress string `json:"peer_address,omitempty"`
	PeerPort    int    `json:"peer_port,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // uTLS fingerprint for client-side
	Password    string `json:"password,omitempty"`    // X25519 password (client-side)

	// Sniffing
	SniffEnabled      bool     `json:"sniff_enabled"`
	SniffDestOverride []string `json:"sniff_dest_override,omitempty"`
}

// OutboundConfig is the managed representation of a single outbound.
type OutboundConfig struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"` // "freedom", "vless", "blackhole"
	// For vless outbound:
	PeerAddress string      `json:"peer_address,omitempty"`
	PeerPort    int         `json:"peer_port,omitempty"`
	VLESSUsers  []VLESSUser `json:"vless_users,omitempty"`
	// For reality outbound:
	Fingerprint string `json:"fingerprint,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	Password    string `json:"password,omitempty"`
	ShortId     string `json:"short_id,omitempty"`
	// For freedom outbound:
	DomainStrategy string `json:"domain_strategy,omitempty"`
}
