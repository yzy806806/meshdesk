package web

// FieldTier classifies a config field's access level for the
// tiered config access model (CONFIG_API_DESIGN.md §1).
type FieldTier int

const (
	// TierReadOnly (T0): returned in GET responses, rejected on write.
	TierReadOnly FieldTier = 0
	// TierMasked (T1): returned as "***" in GET, accepted on write (no-op if "***" sent).
	TierMasked FieldTier = 1
	// TierStepUp (T2): returned in GET, requires step-up token to write.
	TierStepUp FieldTier = 2
	// TierNormal (T3): returned in GET, writable with standard session auth.
	TierNormal FieldTier = 3
)

// String returns the human-readable tier name used in _meta.tier_map.
func (t FieldTier) String() string {
	switch t {
	case TierReadOnly:
		return "read-only"
	case TierMasked:
		return "masked"
	case TierStepUp:
		return "step-up"
	case TierNormal:
		return "normal"
	default:
		return "unknown"
	}
}

// ReloadClass classifies how a field's change is applied.
type ReloadClass int

const (
	ReloadHot     ReloadClass = iota // applied via reloader, no restart
	ReloadRestart                    // requires process restart
)

// String returns the human-readable reload classification.
func (r ReloadClass) String() string {
	switch r {
	case ReloadHot:
		return "hot-reload"
	case ReloadRestart:
		return "restart"
	default:
		return "unknown"
	}
}

// fieldMeta holds tier and reload classification for a single config field.
type fieldMeta struct {
	Tier   FieldTier
	Reload ReloadClass
}

// tierMap is the flat path → classification lookup table.
// Array indices use [N] as a placeholder: "peers[N].capabilities".
//
// A field can appear in both a read-only and masked set (e.g. node.identity).
// We model this by having the field appear once with the highest-restriction
// tier for reads (masked takes priority over read-only for GET masking)
// and the most restrictive for writes (read-only blocks writes).
// For dual-tier fields, we store a composite: TierReadOnly for write-blocking
// and a separate masked set.
var tierMap = map[string]fieldMeta{
	// --- Node (§3.1) ---
	"node.identity":      {Tier: TierMasked, Reload: ReloadRestart},   // DEPRECATED: hex private key; masked + read-only. Migrated to PEM file.
	"node.identity_file": {Tier: TierReadOnly, Reload: ReloadRestart}, // Path to PEM identity file; read-only.
	"node.fingerprint":   {Tier: TierReadOnly, Reload: ReloadRestart}, // Public key hex; read-only reference.
	"node.hostname":      {Tier: TierReadOnly, Reload: ReloadRestart},
	"node.web":           {Tier: TierNormal, Reload: ReloadRestart},
	"node.position.x":    {Tier: TierNormal, Reload: ReloadHot},
	"node.position.y":    {Tier: TierNormal, Reload: ReloadHot},
	"node.position.z":    {Tier: TierNormal, Reload: ReloadHot},

	// --- Mesh (§3.2) ---
	"mesh.port":        {Tier: TierNormal, Reload: ReloadRestart},
	"mesh.gossip_port": {Tier: TierNormal, Reload: ReloadRestart},

	// --- Peers (§3.3) — array fields use [N] placeholder ---
	"peers[N].public_key":              {Tier: TierReadOnly, Reload: ReloadHot},
	"peers[N].endpoint":                {Tier: TierNormal, Reload: ReloadHot},
	"peers[N].allowed_ips":             {Tier: TierNormal, Reload: ReloadHot},
	"peers[N].capabilities":            {Tier: TierStepUp, Reload: ReloadHot},
	"peers[N].reality.server_name":     {Tier: TierNormal, Reload: ReloadHot},
	"peers[N].reality.public_key":      {Tier: TierMasked, Reload: ReloadHot},
	"peers[N].reality.short_id":        {Tier: TierMasked, Reload: ReloadHot},
	"peers[N].reality.tls_fingerprint": {Tier: TierNormal, Reload: ReloadHot},
	"peers[N].service_manage":          {Tier: TierStepUp, Reload: ReloadHot},
	"peers[N].file_transfer_paths":     {Tier: TierStepUp, Reload: ReloadHot},
	"peers[N].monitor_scopes":          {Tier: TierNormal, Reload: ReloadHot},

	// --- P2P (§3.4) ---
	"p2p.enabled":                 {Tier: TierNormal, Reload: ReloadRestart},
	"p2p.seeds":                   {Tier: TierNormal, Reload: ReloadRestart},
	"p2p.nat_traversal":           {Tier: TierNormal, Reload: ReloadRestart},
	"p2p.stun_servers":            {Tier: TierNormal, Reload: ReloadRestart},
	"p2p.relay_mode":              {Tier: TierNormal, Reload: ReloadHot},
	"p2p.max_relay_hops":          {Tier: TierNormal, Reload: ReloadHot},
	"p2p.join_approval":           {Tier: TierStepUp, Reload: ReloadHot},
	"p2p.authorized_keys":         {Tier: TierStepUp, Reload: ReloadHot},
	"p2p.gossip_interval":         {Tier: TierNormal, Reload: ReloadHot},
	"p2p.gossip_probe_interval":   {Tier: TierNormal, Reload: ReloadHot},
	"p2p.direct_reprobe_interval": {Tier: TierNormal, Reload: ReloadHot},
	"p2p.max_peers":               {Tier: TierNormal, Reload: ReloadHot},

	// --- Monitoring (§3.5) ---
	"monitoring.collectors": {Tier: TierNormal, Reload: ReloadHot},
	"monitoring.interval":   {Tier: TierNormal, Reload: ReloadHot},
	"monitoring.port":       {Tier: TierNormal, Reload: ReloadHot},

	// --- WebSSH (§3.6) ---
	"webssh.port":           {Tier: TierNormal, Reload: ReloadHot},
	"webssh.host_key":       {Tier: TierMasked, Reload: ReloadHot},
	"webssh.shell":          {Tier: TierNormal, Reload: ReloadHot},
	"webssh.dial_timeout":   {Tier: TierNormal, Reload: ReloadHot},
	"webssh.read_deadline":  {Tier: TierNormal, Reload: ReloadHot},
	"webssh.write_deadline": {Tier: TierNormal, Reload: ReloadHot},
	"webssh.max_sessions":   {Tier: TierNormal, Reload: ReloadHot},

	// --- Auth (§3.7) ---
	"auth.web_users":                  {Tier: TierStepUp, Reload: ReloadHot},
	"auth.web_users[N].username":      {Tier: TierNormal, Reload: ReloadHot},
	"auth.web_users[N].password_hash": {Tier: TierMasked, Reload: ReloadHot},
	"auth.totp_issuer":                {Tier: TierNormal, Reload: ReloadHot},
	"auth.require_2fa":                {Tier: TierStepUp, Reload: ReloadHot},
	"auth.totp_window":                {Tier: TierNormal, Reload: ReloadHot},
	"auth.totp_store_dir":             {Tier: TierReadOnly, Reload: ReloadRestart},
	"auth.step_up_timeout":            {Tier: TierStepUp, Reload: ReloadHot},
	"auth.alert_webhook_url":          {Tier: TierStepUp, Reload: ReloadHot},

	// --- Transfer (§3.8) ---
	"transfer.max_file_size": {Tier: TierNormal, Reload: ReloadHot},
	"transfer.upload_dir":    {Tier: TierNormal, Reload: ReloadHot},

	// --- Proxy: SS (§3.9) ---
	"proxy.ss.password":    {Tier: TierMasked, Reload: ReloadHot},
	"proxy.ss.cipher":      {Tier: TierNormal, Reload: ReloadHot},
	"proxy.ss.listen_addr": {Tier: TierNormal, Reload: ReloadHot},
	"proxy.ss.port":        {Tier: TierNormal, Reload: ReloadHot},

	// --- Proxy: Circuit ---
	"proxy.circuit.idle_timeout":          {Tier: TierNormal, Reload: ReloadHot},
	"proxy.circuit.keepalive_interval":    {Tier: TierNormal, Reload: ReloadHot},
	"proxy.circuit.nack_timeout":          {Tier: TierNormal, Reload: ReloadHot},
	"proxy.circuit.orphan_timeout":        {Tier: TierNormal, Reload: ReloadHot},
	"proxy.circuit.max_reassembly_window": {Tier: TierNormal, Reload: ReloadHot},

	// --- Proxy: Chunking ---
	"proxy.chunker_strategy":   {Tier: TierNormal, Reload: ReloadHot},
	"proxy.debug_fixed_chunks": {Tier: TierNormal, Reload: ReloadHot},
	"proxy.paths":              {Tier: TierStepUp, Reload: ReloadHot},
	"proxy.exit_addr":          {Tier: TierStepUp, Reload: ReloadHot},

	// --- Proxy: Path Selection ---
	"proxy.path_selection.mode":                {Tier: TierNormal, Reload: ReloadHot},
	"proxy.path_selection.strategy":            {Tier: TierNormal, Reload: ReloadHot},
	"proxy.path_selection.max_relays_per_path": {Tier: TierNormal, Reload: ReloadHot},
	"proxy.path_selection.probe_timeout_sec":   {Tier: TierNormal, Reload: ReloadHot},
	"proxy.path_selection.probe_concurrency":   {Tier: TierNormal, Reload: ReloadHot},
	"proxy.path_selection.max_candidates":      {Tier: TierNormal, Reload: ReloadHot},
	"proxy.path_selection.probe_cache_ttl_sec": {Tier: TierNormal, Reload: ReloadHot},
	"proxy.path_selection.exit_latency_matrix": {Tier: TierReadOnly, Reload: ReloadRestart},

	// --- Proxy: CF Tunnel ---
	"proxy.cf_tunnel.enabled":           {Tier: TierNormal, Reload: ReloadRestart},
	"proxy.cf_tunnel.tunnel_id":         {Tier: TierMasked, Reload: ReloadHot},
	"proxy.cf_tunnel.credentials_file":  {Tier: TierMasked, Reload: ReloadHot},
	"proxy.cf_tunnel.hostname":          {Tier: TierNormal, Reload: ReloadHot},
	"proxy.cf_tunnel.origin_server":     {Tier: TierNormal, Reload: ReloadHot},
	"proxy.cf_tunnel.region":            {Tier: TierNormal, Reload: ReloadHot},
	"proxy.cf_tunnel.log_level":         {Tier: TierNormal, Reload: ReloadHot},
	"proxy.cf_tunnel.metrics_addr":      {Tier: TierNormal, Reload: ReloadHot},
	"proxy.cf_tunnel.binary_path":       {Tier: TierNormal, Reload: ReloadHot},
	"proxy.cf_tunnel.reconnect_retries": {Tier: TierNormal, Reload: ReloadHot},
	"proxy.cf_tunnel.grace_period_sec":  {Tier: TierNormal, Reload: ReloadHot},

	// --- Proxy: Relay ---
	"proxy.relay.enabled":         {Tier: TierNormal, Reload: ReloadRestart},
	"proxy.relay.jitter_min_ms":   {Tier: TierNormal, Reload: ReloadHot},
	"proxy.relay.jitter_max_ms":   {Tier: TierNormal, Reload: ReloadHot},
	"proxy.relay.disable_jitter":  {Tier: TierNormal, Reload: ReloadHot},
	"proxy.relay.max_circuits":    {Tier: TierNormal, Reload: ReloadHot},
	"proxy.relay.max_queue_depth": {Tier: TierNormal, Reload: ReloadHot},

	// --- Proxy: Exit ---
	"proxy.exit.allowed_ports":        {Tier: TierStepUp, Reload: ReloadHot},
	"proxy.exit.allow_all_ports":      {Tier: TierStepUp, Reload: ReloadHot},
	"proxy.exit.destination_filter":   {Tier: TierStepUp, Reload: ReloadHot},
	"proxy.exit.audit_log_dir":        {Tier: TierNormal, Reload: ReloadHot},
	"proxy.exit.audit_retention_days": {Tier: TierNormal, Reload: ReloadHot},

	// --- Reality (§3.11) ---
	"reality.enabled":      {Tier: TierNormal, Reload: ReloadRestart},
	"reality.listen_addr":  {Tier: TierNormal, Reload: ReloadRestart},
	"reality.listen_port":  {Tier: TierNormal, Reload: ReloadRestart},
	"reality.dest":         {Tier: TierNormal, Reload: ReloadHot},
	"reality.server_names": {Tier: TierNormal, Reload: ReloadHot},
	"reality.private_key":  {Tier: TierMasked, Reload: ReloadRestart},
	"reality.short_ids":    {Tier: TierNormal, Reload: ReloadHot},
}

// readOnlyFields is the set of fields that are read-only on write.
// node.identity is dual-tier: masked on read + read-only on write.
var readOnlyFields = []string{
	"node.identity",
	"node.identity_file",
	"node.fingerprint",
	"node.hostname",
	"peers[N].public_key",
	"auth.totp_store_dir",
	"proxy.path_selection.exit_latency_matrix",
}

// maskedFields is the set of fields serialized as "***" in GET responses.
var maskedFields = []string{
	"node.identity",
	"peers[N].reality.public_key",
	"peers[N].reality.short_id",
	"webssh.host_key",
	"auth.web_users[N].password_hash",
	"proxy.ss.password",
	"proxy.cf_tunnel.tunnel_id",
	"proxy.cf_tunnel.credentials_file",
	"reality.private_key",
}

// stepUpFields is the set of fields that require step-up auth to write.
var stepUpFields = []string{
	"peers[N].capabilities",
	"peers[N].service_manage",
	"peers[N].file_transfer_paths",
	"p2p.join_approval",
	"p2p.authorized_keys",
	"auth.web_users",
	"auth.require_2fa",
	"auth.step_up_timeout",
	"auth.alert_webhook_url",
	"proxy.paths",
	"proxy.exit_addr",
	"proxy.exit.allowed_ports",
	"proxy.exit.allow_all_ports",
	"proxy.exit.destination_filter",
}

// isReadOnly checks if a field path is in the read-only set.
func isReadOnly(path string) bool {
	for _, f := range readOnlyFields {
		if matchFieldPath(f, path) {
			return true
		}
	}
	// Also check parent path for array elements (e.g. "peers[0].public_key"
	// has parent "peers" which isn't read-only, but "peers[N].public_key"
	// template matches).
	return false
}

// isMasked checks if a field path should be masked in GET responses.
func isMasked(path string) bool {
	for _, f := range maskedFields {
		if matchFieldPath(f, path) {
			return true
		}
	}
	return false
}

// isStepUp checks if a field path requires step-up auth to write.
func isStepUp(path string) bool {
	for _, f := range stepUpFields {
		if matchFieldPath(f, path) {
			return true
		}
	}
	// Also check parent path for array elements: if "p2p.authorized_keys"
	// is a T2 field, then "p2p.authorized_keys[0]" should also require step-up.
	if idx := indexOf(path, "["); idx >= 0 {
		parent := path[:idx]
		for _, f := range stepUpFields {
			if f == parent {
				return true
			}
		}
	}
	return false
}

// matchFieldPath checks if an actual field path matches a template path
// that may contain [N] placeholders. For example:
//
//	template "peers[N].preshared_key" matches "peers[0].preshared_key"
//	template "auth.web_users" matches "auth.web_users" (exact for container fields)
//	template "auth.web_users[N].password_hash" matches "auth.web_users[0].password_hash"
func matchFieldPath(template, actual string) bool {
	// Exact match (for non-array fields and container-level fields).
	if template == actual {
		return true
	}
	// Check if template contains [N] placeholder.
	if !containsSubstr(template, "[N]") {
		return false
	}
	// Replace [N] with a regex-like match: split on [N] and check parts.
	return matchWithNPlaceholders(template, actual)
}

// matchWithNPlaceholders matches a template path with [N] placeholders
// against an actual path with numeric indices.
func matchWithNPlaceholders(template, actual string) bool {
	// Split both on "." to compare segment by segment.
	tParts := splitPath(template)
	aParts := splitPath(actual)
	if len(tParts) != len(aParts) {
		return false
	}
	for i, tp := range tParts {
		ap := aParts[i]
		if tp == ap {
			continue
		}
		// Check if template segment is "prefix[N]" form.
		if !containsSubstr(tp, "[N]") {
			return false
		}
		// Replace [N] with any number of digits and check.
		if !matchSegmentWithN(tp, ap) {
			return false
		}
	}
	return true
}

// matchSegmentWithN matches a single path segment containing [N] against
// an actual segment with a numeric index.
func matchSegmentWithN(template, actual string) bool {
	// Find "[N]" in template.
	nIdx := indexOf(template, "[N]")
	if nIdx < 0 {
		return template == actual
	}
	prefix := template[:nIdx]
	suffix := template[nIdx+3:] // skip "[N]"

	// Check prefix.
	if len(actual) < len(prefix)+len(suffix) {
		return false
	}
	if actual[:len(prefix)] != prefix {
		return false
	}
	if actual[len(actual)-len(suffix):] != suffix {
		return false
	}
	// The part between prefix and suffix should be [digits].
	mid := actual[len(prefix) : len(actual)-len(suffix)]
	if len(mid) < 2 { // at least "[" and "]"
		return false
	}
	if mid[0] != '[' || mid[len(mid)-1] != ']' {
		return false
	}
	for _, c := range mid[1 : len(mid)-1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// splitPath splits a dot-separated path, respecting that array index
// notation [N] is part of the current segment (not a separate segment).
func splitPath(path string) []string {
	return splitOn(path, '.')
}

// containsStr checks if s contains substr.
func containsSubstr(s, substr string) bool {
	return len(substr) == 0 || indexOf(s, substr) >= 0
}

// indexOf returns the index of the first occurrence of substr in s, or -1.
func indexOf(s, substr string) int {
	if len(substr) == 0 {
		return 0
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// splitOn splits s on the given delimiter, but does NOT split inside
// square brackets (so "peers[0].field" splits into ["peers[0]", "field"]).
func splitOn(s string, delim byte) []string {
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '[' {
			depth++
		} else if c == ']' {
			depth--
		} else if c == delim && depth == 0 {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// fieldPathToTemplate converts an actual field path (e.g. "peers[0].preshared_key")
// to its template form (e.g. "peers[N].preshared_key") by replacing numeric
// indices with [N].
func fieldPathToTemplate(path string) string {
	parts := splitPath(path)
	for i, p := range parts {
		parts[i] = segmentToTemplate(p)
	}
	return joinPath(parts)
}

// segmentToTemplate replaces [digits] with [N] in a path segment.
func segmentToTemplate(seg string) string {
	bracketStart := indexOf(seg, "[")
	if bracketStart < 0 {
		return seg
	}
	bracketEnd := indexOf(seg[bracketStart:], "]")
	if bracketEnd < 0 {
		return seg
	}
	// Check that the content between brackets is all digits.
	inner := seg[bracketStart+1 : bracketStart+bracketEnd]
	allDigits := len(inner) > 0
	for _, c := range inner {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if !allDigits {
		return seg
	}
	return seg[:bracketStart+1] + "N" + seg[bracketStart+bracketEnd:]
}

// joinPath joins path parts with ".".
func joinPath(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "."
		}
		result += p
	}
	return result
}

// validSections is the set of recognized top-level config section names.
var validSections = map[string]bool{
	"node": true, "mesh": true, "peers": true, "p2p": true,
	"monitoring": true, "webssh": true, "auth": true, "transfer": true,
	"proxy": true, "reality": true,
}

// maskSentinel is the placeholder string for masked fields.
const maskSentinel = "***"
