package topology

// DeriveRole computes a node's role string from its configuration flags.
// The role is a +-delimited list: "entry", "relay", "exit", "dashboard".
//
// This function takes primitive boolean parameters rather than importing
// internal/config, keeping the topology package dependency-free.
//
// Role derivation rules (TOPOLOGY_API_SPEC.md §4):
//   - entry:     SS password is set (node is a proxy entry point)
//   - relay:     relay is explicitly enabled
//   - exit:      exit has allowed ports or allow-all is set
//   - dashboard: WebAddr is non-empty (node runs a web dashboard)
//
// A node with no proxy config and no web UI returns "dashboard" as a
// sensible default (localhost is dashboard). If none of the flags are
// set, returns "dashboard" so the node always appears in the topology
// with at least one role.
func DeriveRole(ssPasswordSet, relayEnabled bool, exitHasPorts, exitAllowAll, webAddrSet bool) string {
	var roles []string

	if ssPasswordSet {
		roles = append(roles, "entry")
	}
	if relayEnabled {
		roles = append(roles, "relay")
	}
	if exitHasPorts || exitAllowAll {
		roles = append(roles, "exit")
	}
	if webAddrSet {
		roles = append(roles, "dashboard")
	}

	// A node always has at least the "dashboard" role.
	// This handles the localhost case and nodes with no proxy config.
	if len(roles) == 0 {
		return "dashboard"
	}

	return joinRoles(roles)
}

// joinRoles joins role strings with "+".
func joinRoles(roles []string) string {
	if len(roles) == 0 {
		return ""
	}
	result := roles[0]
	for _, r := range roles[1:] {
		result += "+" + r
	}
	return result
}
