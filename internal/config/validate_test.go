package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validateTestCase is a table-driven test case for Validate and ValidateFile.
type validateTestCase struct {
	name        string
	yaml        string
	wantErrs    []string // substrings that must appear in the error output
	wantNoErrs  []string // substrings that must NOT appear (for negative checks)
	expectValid bool
}

func TestValidate(t *testing.T) {
	cases := []validateTestCase{
		// --- Valid configs ---
		{
			name:        "empty config (defaults) is valid",
			yaml:        "",
			expectValid: true,
		},
		{
			name: "minimal valid config",
			yaml: `
mesh:
  port: 51820
`,
			expectValid: true,
		},
		{
			name: "full valid config with peers and reality",
			yaml: `
node:
  hostname: node1
  web: ":8080"
mesh:
  port: 51820
  tun_enabled: true
  mesh_cidr: 10.100.0.0/24
peers:
  - public_key: abc123
    endpoint: 192.168.1.1:51820
    reality:
      server_name: www.example.com
      public_key: def456
monitoring:
  port: 4191
  interval: 15
webssh:
  port: 2222
reality:
  enabled: true
  dest: www.example.com:443
  private_key: aabbcc
  server_names:
    - www.example.com
  listen_port: 443
auth:
  web_users:
    - username: admin
      password_hash: "$2a$10$somehash"
`,
			expectValid: true,
		},

		// --- YAML syntax errors (caught by ValidateFile) ---
		{
			name: "YAML syntax error: bad indentation",
			yaml: `
mesh:
  port: 51820
   bad_indent: true
`,
			wantErrs: []string{"YAML syntax error"},
		},
		{
			name:     "YAML syntax error: tab character",
			yaml:     "mesh:\n\tport: 51820\n",
			wantErrs: []string{"YAML syntax error"},
		},

		// --- Mesh section ---
		{
			name: "mesh port out of range (negative)",
			yaml: `
mesh:
  port: -1
`,
			wantErrs: []string{"mesh.port", "must be 1-65535"},
		},
		{
			name: "mesh port out of range (too high)",
			yaml: `
mesh:
  port: 70000
`,
			wantErrs: []string{"mesh.port", "must be 1-65535"},
		},
		{
			name: "tun_enabled with invalid CIDR",
			yaml: `
mesh:
  port: 51820
  tun_enabled: true
  mesh_cidr: not-a-cidr
`,
			wantErrs: []string{"mesh.mesh_cidr", "invalid CIDR"},
		},
		{
			name: "tun_enabled with invalid subnet_proxy",
			yaml: `
mesh:
  port: 51820
  tun_enabled: true
  mesh_cidr: 10.100.0.0/24
  subnet_proxy:
    - not-a-cidr
`,
			wantErrs: []string{"mesh.subnet_proxy", "invalid CIDR"},
		},
		{
			name: "invalid static_virtual_ip",
			yaml: `
mesh:
  port: 51820
  static_virtual_ip: not-an-ip
`,
			wantErrs: []string{"mesh.static_virtual_ip", "invalid IP"},
		},

		// --- Peers section ---
		{
			name: "peer missing public_key",
			yaml: `
peers:
  - endpoint: 1.2.3.4:51820
`,
			wantErrs: []string{"peers[0].public_key", "required"},
		},
		{
			name: "duplicate peer public_key",
			yaml: `
peers:
  - public_key: samekey
    endpoint: 1.2.3.4:51820
  - public_key: samekey
    endpoint: 5.6.7.8:51820
`,
			wantErrs: []string{"peers[1].public_key", "duplicate"},
		},
		{
			name: "peer invalid endpoint",
			yaml: `
peers:
  - public_key: abc123
    endpoint: no-port-here
`,
			wantErrs: []string{"peers[0].endpoint", "invalid endpoint"},
		},
		{
			name: "peer reality missing public_key",
			yaml: `
peers:
  - public_key: abc123
    reality:
      server_name: www.example.com
`,
			wantErrs: []string{"peers[0].reality.public_key", "required"},
		},

		// --- Monitoring section ---
		{
			name: "monitoring negative interval",
			yaml: `
monitoring:
  interval: -5
`,
			wantErrs: []string{"monitoring.interval", "must be >= 0"},
		},
		{
			name: "monitoring port out of range",
			yaml: `
monitoring:
  port: 99999
`,
			wantErrs: []string{"monitoring.port", "must be 0-65535"},
		},

		// --- WebSSH section ---
		{
			name: "webssh negative max_sessions",
			yaml: `
webssh:
  max_sessions: -1
`,
			wantErrs: []string{"webssh.max_sessions", "must be >= 0"},
		},

		// --- Auth section ---
		{
			name: "auth web_user missing username",
			yaml: `
auth:
  web_users:
    - password_hash: somehash
`,
			wantErrs: []string{"auth.web_users[0].username", "required"},
		},
		{
			name: "auth web_user missing password_hash",
			yaml: `
auth:
  web_users:
    - username: admin
`,
			wantErrs: []string{"auth.web_users[0].password_hash", "required"},
		},

		// --- Transfer section ---
		{
			name: "negative max_file_size",
			yaml: `
transfer:
  max_file_size: -100
`,
			wantErrs: []string{"transfer.max_file_size", "must be >= 0"},
		},

		// --- Reality server section ---
		{
			name: "reality enabled without private_key",
			yaml: `
reality:
  enabled: true
  dest: www.example.com:443
  server_names:
    - www.example.com
`,
			wantErrs: []string{"reality.private_key", "required"},
		},

		// --- Join section ---
		{
			name: "join enabled without secret",
			yaml: `
join:
  enabled: true
`,
			wantErrs: []string{"join.secret", "required"},
		},
		{
			name: "join token without server_url",
			yaml: `
join:
  token: sometoken
`,
			wantErrs: []string{"join.server_url", "required"},
		},

		// --- Proxy section ---
		{
			name: "invalid chunker_strategy",
			yaml: `
proxy:
  chunker_strategy: invalid-strategy
`,
			wantErrs: []string{"proxy.chunker_strategy", "must be"},
		},
		{
			name: "invalid path_selection mode",
			yaml: `
proxy:
  path_selection:
    mode: invalid-mode
`,
			wantErrs: []string{"proxy.path_selection.mode", "must be"},
		},
		{
			name: "invalid path_selection strategy",
			yaml: `
proxy:
  path_selection:
    strategy: invalid-strategy
`,
			wantErrs: []string{"proxy.path_selection.strategy", "must be"},
		},
		{
			name: "relay jitter_min > jitter_max",
			yaml: `
proxy:
  relay:
    enabled: true
    jitter_min_ms: 100
    jitter_max_ms: 50
`,
			wantErrs: []string{"proxy.relay.jitter_min_ms", "must be <="},
		},

		// --- ACL section ---
		{
			name: "invalid acl default_policy",
			yaml: `
acl:
  default_policy: invalid
`,
			wantErrs: []string{"acl.default_policy", "must be"},
		},
		{
			name: "acl rule invalid action",
			yaml: `
acl:
  rules:
    - action: block
`,
			wantErrs: []string{"acl.rules[0].action", "must be"},
		},
		{
			name: "acl rule invalid protocol",
			yaml: `
acl:
  rules:
    - action: allow
      protocol: gre
`,
			wantErrs: []string{"acl.rules[0].protocol", "must be"},
		},
		{
			name: "acl rule invalid src_cidr",
			yaml: `
acl:
  rules:
    - action: allow
      src_cidr: not-a-cidr
`,
			wantErrs: []string{"acl.rules[0].src_cidr", "invalid CIDR"},
		},
		{
			name: "acl rule invalid dst_port",
			yaml: `
acl:
  rules:
    - action: allow
      dst_port: 99999
`,
			wantErrs: []string{"acl.rules[0].dst_port", "must be 0-65535"},
		},

		// --- P2P section ---
		{
			name: "invalid p2p relay_mode",
			yaml: `
p2p:
  enabled: true
  relay_mode: invalid
`,
			wantErrs: []string{"p2p.relay_mode", "must be"},
		},

		// --- Port conflicts ---
		{
			name: "port conflict: mesh port == monitoring port",
			yaml: `
mesh:
  port: 4191
monitoring:
  port: 4191
`,
			wantErrs: []string{"port 4191 conflict"},
		},
		{
			name: "port conflict: webssh == reality listen_port",
			yaml: `
webssh:
  port: 443
reality:
  enabled: true
  listen_port: 443
  dest: www.example.com:443
  private_key: aabbcc
  server_names:
    - www.example.com
`,
			wantErrs: []string{"port 443 conflict", "webssh.port", "reality.listen_port"},
		},
		{
			name: "no port conflict when ports are different",
			yaml: `
mesh:
  port: 51820
monitoring:
  port: 4191
webssh:
  port: 2222
`,
			expectValid: true,
		},

		// --- Unknown top-level keys (warning only, not error) ---
		{
			name: "unknown top-level key does not cause validation error",
			yaml: `
mesh:
  port: 51820
unknown_section:
  foo: bar
`,
			expectValid: true, // Load() warns but doesn't fail; Validate passes
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Write the YAML to a temp file.
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configPath, []byte(tc.yaml), 0644); err != nil {
				t.Fatalf("failed to write temp config: %v", err)
			}

			errs := ValidateFile(configPath)

			if tc.expectValid {
				if len(errs) > 0 {
					t.Errorf("expected valid config, got %d errors:", len(errs))
					for _, e := range errs {
						t.Errorf("  %s", e.Error())
					}
				}
				return
			}

			// Check that all expected error substrings are present.
			errStrs := make([]string, len(errs))
			for i, e := range errs {
				errStrs[i] = e.Error()
			}
			combinedErr := strings.Join(errStrs, "\n")

			for _, want := range tc.wantErrs {
				if !strings.Contains(combinedErr, want) {
					t.Errorf("expected error containing %q\nerrors:\n%s", want, combinedErr)
				}
			}
			for _, wantNot := range tc.wantNoErrs {
				if strings.Contains(combinedErr, wantNot) {
					t.Errorf("unexpected error containing %q\nerrors:\n%s", wantNot, combinedErr)
				}
			}
		})
	}
}

func TestValidateStruct(t *testing.T) {
	// Test Validate directly on Config structs (no file I/O).

	t.Run("default config is valid", func(t *testing.T) {
		cfg := Default()
		errs := Validate(cfg)
		if len(errs) > 0 {
			t.Errorf("Default() config should be valid, got %d errors:", len(errs))
			for _, e := range errs {
				t.Errorf("  %s", e.Error())
			}
		}
	})

	t.Run("port conflict between mesh port and monitoring port", func(t *testing.T) {
		cfg := Default()
		cfg.Mesh.Port = 4191
		cfg.Monitoring.Port = 4191
		errs := Validate(cfg)
		found := false
		for _, e := range errs {
			if strings.Contains(e.Error(), "port 4191 conflict") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected port conflict error for port 4191, got: %v", errs)
		}
	})

	t.Run("three-way port conflict", func(t *testing.T) {
		cfg := Default()
		cfg.Mesh.Port = 2222
		cfg.WebSSH.Port = 2222
		cfg.Monitoring.Port = 2222
		errs := Validate(cfg)
		found := false
		for _, e := range errs {
			if strings.Contains(e.Error(), "port 2222 conflict") {
				found = true
				// Should mention all three subsystems.
				for _, sub := range []string{"mesh.port", "webssh.port", "monitoring.port"} {
					if !strings.Contains(e.Error(), sub) {
						t.Errorf("conflict error should mention %s: %s", sub, e.Error())
					}
				}
				break
			}
		}
		if !found {
			t.Errorf("expected three-way port conflict, got: %v", errs)
		}
	})

	t.Run("no conflict when ports differ", func(t *testing.T) {
		cfg := Default()
		cfg.Mesh.Port = 51820
		cfg.Monitoring.Port = 4191
		cfg.WebSSH.Port = 2222
		errs := Validate(cfg)
		for _, e := range errs {
			if strings.Contains(e.Error(), "conflict") {
				t.Errorf("unexpected port conflict: %s", e.Error())
			}
		}
	})

	t.Run("peer with valid reality config passes", func(t *testing.T) {
		cfg := Default()
		cfg.Peers = []PeerConfig{
			{
				PublicKey: "abc123",
				Endpoint:  "1.2.3.4:51820",
				Reality: &RealityPeerConfig{
					ServerName: "www.example.com",
					PublicKey:  "def456",
					ShortID:    "aabb",
				},
			},
		}
		errs := Validate(cfg)
		for _, e := range errs {
			if strings.Contains(e.Section, "peers") {
				t.Errorf("unexpected peer error: %s", e.Error())
			}
		}
	})
}

func TestValidateFileMissing(t *testing.T) {
	errs := ValidateFile("/nonexistent/path/config.yaml")
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Message, "cannot read file") {
		t.Errorf("expected 'cannot read file' error, got: %s", errs[0].Message)
	}
}

func TestValidationErrorFormat(t *testing.T) {
	e := ValidationError{Section: "mesh", Field: "port", Message: "invalid"}
	got := e.Error()
	want := "[mesh.port] invalid"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}

	e2 := ValidationError{Section: "reality", Field: "", Message: "something wrong"}
	got2 := e2.Error()
	want2 := "[reality] something wrong"
	if got2 != want2 {
		t.Errorf("Error() = %q, want %q", got2, want2)
	}
}

func TestValidateACLWildcards(t *testing.T) {
	cfg := Default()
	cfg.ACL.Enabled = true
	cfg.ACL.Rules = []ACLRule{
		{Action: ACLActionAllow, SourceCIDR: "*", DestCIDR: "*", Protocol: "*"},
		{Action: ACLActionDeny, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.10.0.0/24", Protocol: "tcp", DstPort: 22},
	}
	errs := Validate(cfg)
	for _, e := range errs {
		if strings.Contains(e.Section, "acl") {
			t.Errorf("unexpected ACL error: %s", e.Error())
		}
	}
}
