package config

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ValidationError describes a single config validation problem.
type ValidationError struct {
	Section string // dotted path, e.g. "mesh", "proxy.ss"
	Field   string // field name, e.g. "port", "listen_addr"
	Message string // human-readable explanation
}

func (e ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("[%s.%s] %s", e.Section, e.Field, e.Message)
	}
	return fmt.Sprintf("[%s] %s", e.Section, e.Message)
}

// portEntry tracks a port usage for conflict detection.
type portEntry struct {
	Port    int
	Section string
	Field   string
}

// Validate checks a parsed Config for semantic errors: missing required
// fields, invalid enum values, range violations, and port conflicts across
// subsystems. It returns a slice of ValidationError (empty = valid).
//
// Validate does NOT check YAML syntax — that is caught by Load(). It
// operates on the already-parsed *Config returned by Load() or Default().
func Validate(cfg *Config) []ValidationError {
	var errs []ValidationError

	// --- mesh section ---
	if cfg.Mesh.Port <= 0 || cfg.Mesh.Port > 65535 {
		errs = append(errs, ValidationError{
			Section: "mesh", Field: "port",
			Message: fmt.Sprintf("port must be 1-65535, got %d", cfg.Mesh.Port),
		})
	}
	if cfg.Mesh.TunEnabled {
		if cfg.Mesh.MeshCIDR == "" {
			errs = append(errs, ValidationError{
				Section: "mesh", Field: "mesh_cidr",
				Message: "mesh_cidr is required when tun_enabled is true",
			})
		} else if _, err := parseCIDR(cfg.Mesh.MeshCIDR); err != nil {
			errs = append(errs, ValidationError{
				Section: "mesh", Field: "mesh_cidr",
				Message: fmt.Sprintf("invalid CIDR %q: %v", cfg.Mesh.MeshCIDR, err),
			})
		}
		for _, sp := range cfg.Mesh.SubnetProxy {
			if _, err := parseCIDR(sp); err != nil {
				errs = append(errs, ValidationError{
					Section: "mesh", Field: "subnet_proxy",
					Message: fmt.Sprintf("invalid CIDR %q: %v", sp, err),
				})
			}
		}
	}
	if cfg.Mesh.TunMTU < 0 || cfg.Mesh.TunMTU > 9000 {
		errs = append(errs, ValidationError{
			Section: "mesh", Field: "tun_mtu",
			Message: fmt.Sprintf("tun_mtu must be 0 (default) or 1-9000, got %d", cfg.Mesh.TunMTU),
		})
	}
	if cfg.Mesh.StaticVirtualIP != "" {
		if net.ParseIP(cfg.Mesh.StaticVirtualIP) == nil {
			errs = append(errs, ValidationError{
				Section: "mesh", Field: "static_virtual_ip",
				Message: fmt.Sprintf("invalid IP %q", cfg.Mesh.StaticVirtualIP),
			})
		}
	}
	// DNS port validation.
	if cfg.Mesh.DNSEnabled {
		if cfg.Mesh.DNSPort < 0 || cfg.Mesh.DNSPort > 65535 {
			errs = append(errs, ValidationError{
				Section: "mesh", Field: "dns_port",
				Message: fmt.Sprintf("dns_port must be 0-65535, got %d", cfg.Mesh.DNSPort),
			})
		}
	}

	// --- peers section ---
	seenKeys := make(map[string]bool)
	for i, p := range cfg.Peers {
		prefix := fmt.Sprintf("peers[%d]", i)
		if p.PublicKey == "" {
			errs = append(errs, ValidationError{
				Section: prefix, Field: "public_key",
				Message: "public_key is required",
			})
		} else {
			if seenKeys[p.PublicKey] {
				errs = append(errs, ValidationError{
					Section: prefix, Field: "public_key",
					Message: fmt.Sprintf("duplicate peer public_key %q", p.PublicKey),
				})
			}
			seenKeys[p.PublicKey] = true
		}
		if p.Endpoint != "" {
			if _, _, err := net.SplitHostPort(p.Endpoint); err != nil {
				errs = append(errs, ValidationError{
					Section: prefix, Field: "endpoint",
					Message: fmt.Sprintf("invalid endpoint %q: %v", p.Endpoint, err),
				})
			}
		}
		if p.Reality != nil {
			if p.Reality.ServerName == "" {
				errs = append(errs, ValidationError{
					Section: prefix + ".reality", Field: "server_name",
					Message: "server_name is required when reality is configured",
				})
			}
			if p.Reality.PublicKey == "" {
				errs = append(errs, ValidationError{
					Section: prefix + ".reality", Field: "public_key",
					Message: "public_key is required when reality is configured",
				})
			}
		}
	}

	// --- monitoring section ---
	if cfg.Monitoring.Interval < 0 {
		errs = append(errs, ValidationError{
			Section: "monitoring", Field: "interval",
			Message: fmt.Sprintf("interval must be >= 0, got %d", cfg.Monitoring.Interval),
		})
	}
	if cfg.Monitoring.Port < 0 || cfg.Monitoring.Port > 65535 {
		errs = append(errs, ValidationError{
			Section: "monitoring", Field: "port",
			Message: fmt.Sprintf("port must be 0-65535, got %d", cfg.Monitoring.Port),
		})
	}

	// --- webssh section ---
	if cfg.WebSSH.Port < 0 || cfg.WebSSH.Port > 65535 {
		errs = append(errs, ValidationError{
			Section: "webssh", Field: "port",
			Message: fmt.Sprintf("port must be 0-65535, got %d", cfg.WebSSH.Port),
		})
	}
	if cfg.WebSSH.DialTimeout < 0 {
		errs = append(errs, ValidationError{
			Section: "webssh", Field: "dial_timeout",
			Message: fmt.Sprintf("dial_timeout must be >= 0, got %d", cfg.WebSSH.DialTimeout),
		})
	}
	if cfg.WebSSH.MaxSessions < 0 {
		errs = append(errs, ValidationError{
			Section: "webssh", Field: "max_sessions",
			Message: fmt.Sprintf("max_sessions must be >= 0, got %d", cfg.WebSSH.MaxSessions),
		})
	}

	// --- auth section ---
	for i, u := range cfg.Auth.WebUsers {
		prefix := fmt.Sprintf("auth.web_users[%d]", i)
		if u.Username == "" {
			errs = append(errs, ValidationError{
				Section: prefix, Field: "username",
				Message: "username is required",
			})
		}
		if u.PasswordHash == "" {
			errs = append(errs, ValidationError{
				Section: prefix, Field: "password_hash",
				Message: "password_hash is required",
			})
		}
	}
	if cfg.Auth.TOTPWindow < 0 {
		errs = append(errs, ValidationError{
			Section: "auth", Field: "totp_window",
			Message: fmt.Sprintf("totp_window must be >= 0, got %d", cfg.Auth.TOTPWindow),
		})
	}

	// --- transfer section ---
	if cfg.Transfer.MaxFileSize < 0 {
		errs = append(errs, ValidationError{
			Section: "transfer", Field: "max_file_size",
			Message: fmt.Sprintf("max_file_size must be >= 0, got %d", cfg.Transfer.MaxFileSize),
		})
	}

	// --- reality server section ---
	if cfg.Reality.Enabled {
		if cfg.Reality.Dest == "" {
			errs = append(errs, ValidationError{
				Section: "reality", Field: "dest",
				Message: "dest is required when reality is enabled",
			})
		}
		if cfg.Reality.PrivateKey == "" {
			errs = append(errs, ValidationError{
				Section: "reality", Field: "private_key",
				Message: "private_key is required when reality is enabled",
			})
		}
		if len(cfg.Reality.ServerNames) == 0 {
			errs = append(errs, ValidationError{
				Section: "reality", Field: "server_names",
				Message: "at least one server_name is required when reality is enabled",
			})
		}
		if cfg.Reality.ListenPort < 0 || cfg.Reality.ListenPort > 65535 {
			errs = append(errs, ValidationError{
				Section: "reality", Field: "listen_port",
				Message: fmt.Sprintf("listen_port must be 0-65535, got %d", cfg.Reality.ListenPort),
			})
		}
	}

	// --- join section ---
	if cfg.Join.Enabled {
		if cfg.Join.Secret == "" {
			errs = append(errs, ValidationError{
				Section: "join", Field: "secret",
				Message: "secret is required when join server is enabled",
			})
		}
		if cfg.Join.TokenLifetime < 0 {
			errs = append(errs, ValidationError{
				Section: "join", Field: "token_lifetime",
				Message: fmt.Sprintf("token_lifetime must be >= 0, got %d", cfg.Join.TokenLifetime),
			})
		}
	}
	// Join client validation: if token is set, server_url must also be set.
	if cfg.Join.Token != "" && cfg.Join.ServerURL == "" {
		errs = append(errs, ValidationError{
			Section: "join", Field: "server_url",
			Message: "server_url is required when a join token is specified",
		})
	}

	// --- proxy section ---
	if cfg.Proxy.SS.Enabled {
		if cfg.Proxy.SS.Password == "" {
			errs = append(errs, ValidationError{
				Section: "proxy.ss", Field: "password",
				Message: "password is required when SS listener is enabled",
			})
		}
		if cfg.Proxy.SS.Port < 0 || cfg.Proxy.SS.Port > 65535 {
			errs = append(errs, ValidationError{
				Section: "proxy.ss", Field: "port",
				Message: fmt.Sprintf("port must be 0-65535, got %d", cfg.Proxy.SS.Port),
			})
		}
	}

	// ChunkerStrategy enum.
	switch cfg.Proxy.ChunkerStrategy {
	case "", "fixed-16k", "bounded-4k-64k":
		// valid
	default:
		errs = append(errs, ValidationError{
			Section: "proxy", Field: "chunker_strategy",
			Message: fmt.Sprintf("must be 'fixed-16k' or 'bounded-4k-64k', got %q", cfg.Proxy.ChunkerStrategy),
		})
	}

	// PathSelection mode enum.
	switch cfg.Proxy.PathSelection.Mode {
	case "", "manual", "auto":
		// valid
	default:
		errs = append(errs, ValidationError{
			Section: "proxy.path_selection", Field: "mode",
			Message: fmt.Sprintf("must be 'manual' or 'auto', got %q", cfg.Proxy.PathSelection.Mode),
		})
	}

	// PathSelection strategy enum.
	switch cfg.Proxy.PathSelection.Strategy {
	case "", "latency", "random", "round-robin":
		// valid
	default:
		errs = append(errs, ValidationError{
			Section: "proxy.path_selection", Field: "strategy",
			Message: fmt.Sprintf("must be 'latency', 'random', or 'round-robin', got %q", cfg.Proxy.PathSelection.Strategy),
		})
	}

	// Relay jitter sanity.
	if cfg.Proxy.Relay.JitterMinMs > cfg.Proxy.Relay.JitterMaxMs && cfg.Proxy.Relay.JitterMaxMs > 0 {
		errs = append(errs, ValidationError{
			Section: "proxy.relay", Field: "jitter_min_ms",
			Message: fmt.Sprintf("jitter_min_ms (%d) must be <= jitter_max_ms (%d)",
				cfg.Proxy.Relay.JitterMinMs, cfg.Proxy.Relay.JitterMaxMs),
		})
	}

	// --- ACL section ---
	switch cfg.ACL.DefaultPolicy {
	case "", ACLActionAllow, ACLActionDeny:
		// valid
	default:
		errs = append(errs, ValidationError{
			Section: "acl", Field: "default_policy",
			Message: fmt.Sprintf("must be 'allow' or 'deny', got %q", cfg.ACL.DefaultPolicy),
		})
	}
	for i, rule := range cfg.ACL.Rules {
		prefix := fmt.Sprintf("acl.rules[%d]", i)
		switch rule.Action {
		case ACLActionAllow, ACLActionDeny:
			// valid
		default:
			errs = append(errs, ValidationError{
				Section: prefix, Field: "action",
				Message: fmt.Sprintf("must be 'allow' or 'deny', got %q", rule.Action),
			})
		}
		if rule.SourceCIDR != "" && rule.SourceCIDR != "*" {
			if _, err := parseCIDR(rule.SourceCIDR); err != nil {
				errs = append(errs, ValidationError{
					Section: prefix, Field: "src_cidr",
					Message: fmt.Sprintf("invalid CIDR %q: %v", rule.SourceCIDR, err),
				})
			}
		}
		if rule.DestCIDR != "" && rule.DestCIDR != "*" {
			if _, err := parseCIDR(rule.DestCIDR); err != nil {
				errs = append(errs, ValidationError{
					Section: prefix, Field: "dst_cidr",
					Message: fmt.Sprintf("invalid CIDR %q: %v", rule.DestCIDR, err),
				})
			}
		}
		switch rule.Protocol {
		case "", "*", "tcp", "udp", "icmp":
			// valid
		default:
			errs = append(errs, ValidationError{
				Section: prefix, Field: "protocol",
				Message: fmt.Sprintf("must be 'tcp', 'udp', 'icmp', or '*', got %q", rule.Protocol),
			})
		}
		if rule.SrcPort < 0 || rule.SrcPort > 65535 {
			errs = append(errs, ValidationError{
				Section: prefix, Field: "src_port",
				Message: fmt.Sprintf("src_port must be 0-65535, got %d", rule.SrcPort),
			})
		}
		if rule.DstPort < 0 || rule.DstPort > 65535 {
			errs = append(errs, ValidationError{
				Section: prefix, Field: "dst_port",
				Message: fmt.Sprintf("dst_port must be 0-65535, got %d", rule.DstPort),
			})
		}
	}

	// --- P2P section ---
	switch cfg.P2P.RelayMode {
	case "", "auto", "manual", "disabled":
		// valid
	default:
		errs = append(errs, ValidationError{
			Section: "p2p", Field: "relay_mode",
			Message: fmt.Sprintf("must be 'auto', 'manual', or 'disabled', got %q", cfg.P2P.RelayMode),
		})
	}
	switch cfg.P2P.JoinApproval {
	case "", "auto", "manual":
		// valid
	default:
		errs = append(errs, ValidationError{
			Section: "p2p", Field: "join_approval",
			Message: fmt.Sprintf("must be 'auto' or 'manual', got %q", cfg.P2P.JoinApproval),
		})
	}

	// --- Port conflict detection ---
	errs = append(errs, checkPortConflicts(cfg)...)

	return errs
}

// ValidateFile reads, parses, and validates a config file. It returns
// syntax errors (YAML parse failures) and semantic errors (Validate).
func ValidateFile(path string) []ValidationError {
	// Syntax check: try to unmarshal into a generic map first to catch
	// raw YAML syntax errors before the typed parse.
	data, err := readFile(path)
	if err != nil {
		return []ValidationError{{
			Section: "",
			Message: fmt.Sprintf("cannot read file: %v", err),
		}}
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return []ValidationError{{
			Section: "",
			Message: fmt.Sprintf("YAML syntax error: %v", err),
		}}
	}

	cfg, err := Load(path)
	if err != nil {
		return []ValidationError{{
			Section: "",
			Message: fmt.Sprintf("config parse error: %v", err),
		}}
	}
	return Validate(cfg)
}

// checkPortConflicts collects all port assignments across subsystems
// and reports any port used by more than one subsystem.
func checkPortConflicts(cfg *Config) []ValidationError {
	var entries []portEntry

	// Mesh WireGuard port.
	if cfg.Mesh.Port > 0 {
		entries = append(entries, portEntry{cfg.Mesh.Port, "mesh", "port"})
	}
	// Gossip port.
	if cfg.Mesh.GossipPort > 0 {
		entries = append(entries, portEntry{cfg.Mesh.GossipPort, "mesh", "gossip_port"})
	}
	// DNS port.
	if cfg.Mesh.DNSEnabled && cfg.Mesh.DNSPort > 0 {
		entries = append(entries, portEntry{cfg.Mesh.DNSPort, "mesh", "dns_port"})
	}
	// Monitoring push port.
	if cfg.Monitoring.Port > 0 {
		entries = append(entries, portEntry{cfg.Monitoring.Port, "monitoring", "port"})
	}
	// WebSSH port.
	if cfg.WebSSH.Port > 0 {
		entries = append(entries, portEntry{cfg.WebSSH.Port, "webssh", "port"})
	}
	// Reality listen port.
	rPort := cfg.Reality.ListenPort
	if rPort == 0 && cfg.Reality.Enabled {
		rPort = 443 // default
	}
	if rPort > 0 {
		entries = append(entries, portEntry{rPort, "reality", "listen_port"})
	}
	// Join server listen port.
	jPort := 0
	if cfg.Join.Enabled {
		if cfg.Join.ListenAddr != "" {
			if _, portStr, err := net.SplitHostPort(cfg.Join.ListenAddr); err == nil {
				fmt.Sscanf(portStr, "%d", &jPort)
			}
		}
		if jPort == 0 {
			jPort = 8443 // default
		}
	}
	if jPort > 0 {
		entries = append(entries, portEntry{jPort, "join", "listen_addr"})
	}
	// SS listener port.
	if cfg.Proxy.SS.Enabled && cfg.Proxy.SS.Port > 0 {
		entries = append(entries, portEntry{cfg.Proxy.SS.Port, "proxy.ss", "port"})
	}
	// CF Tunnel metrics port.
	if cfg.Proxy.CFTunnel.Enabled && cfg.Proxy.CFTunnel.MetricsAddr != "" {
		if _, portStr, err := net.SplitHostPort(cfg.Proxy.CFTunnel.MetricsAddr); err == nil {
			var mPort int
			fmt.Sscanf(portStr, "%d", &mPort)
			if mPort > 0 {
				entries = append(entries, portEntry{mPort, "proxy.cf_tunnel", "metrics_addr"})
			}
		}
	}
	// Node web address port.
	if cfg.Node.WebAddr != "" {
		if _, portStr, err := net.SplitHostPort(cfg.Node.WebAddr); err == nil {
			var wPort int
			fmt.Sscanf(portStr, "%d", &wPort)
			if wPort > 0 {
				entries = append(entries, portEntry{wPort, "node", "web"})
			}
		}
	}

	// Group by port and report conflicts.
	portMap := make(map[int][]portEntry)
	for _, e := range entries {
		portMap[e.Port] = append(portMap[e.Port], e)
	}

	var conflictPorts []int
	for port, group := range portMap {
		if len(group) > 1 {
			conflictPorts = append(conflictPorts, port)
		}
	}
	sort.Ints(conflictPorts)

	var errs []ValidationError
	for _, port := range conflictPorts {
		group := portMap[port]
		parts := make([]string, len(group))
		for i, e := range group {
			parts[i] = fmt.Sprintf("%s.%s", e.Section, e.Field)
		}
		errs = append(errs, ValidationError{
			Section: "",
			Message: fmt.Sprintf("port %d conflict: used by %s", port, strings.Join(parts, ", ")),
		})
	}
	return errs
}

// parseCIDR wraps net.ParseCIDR with a clearer error message.
func parseCIDR(s string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %w", err)
	}
	return ipNet, nil
}

// readFile is a thin wrapper around os.ReadFile for testability.
var readFile = os.ReadFile
