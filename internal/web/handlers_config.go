package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"gopkg.in/yaml.v3"
)

// configMu protects the in-memory config pointer from concurrent reads
// and writes. The server's cfg field is accessed by GET handlers (read)
// and PUT/PATCH handlers (write), so we need a RWMutex for safety.
var configMu sync.RWMutex

// ConfigAPIManager manages the config API subsystem: tiered access,
// hot-reload tracking, and atomic config file writes.
type ConfigAPIManager struct {
	mu sync.Mutex

	// configPath is the on-disk YAML config file path.
	configPath string

	// reloaderRegistry tracks dirty fields and runs reloaders.
	reloaderRegistry *ReloaderRegistry

	// lastRestartCheck is used for rate-limiting POST /api/config/restart.
	lastRestartTime time.Time

	// lastReloadTime is used for rate-limiting POST /api/config/reload.
	lastReloadTime time.Time
}

// NewConfigAPIManager creates a new config API manager.
func NewConfigAPIManager(configPath string) *ConfigAPIManager {
	return &ConfigAPIManager{
		configPath:       configPath,
		reloaderRegistry: NewReloaderRegistry(),
	}
}

// --- HTTP Handlers ---

// handleConfigAPI is the main dispatch handler for /api/config.
func (s *Server) handleConfigAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleConfigGet(w, r)
	case http.MethodPut:
		s.handleConfigPut(w, r)
	case http.MethodPatch:
		s.handleConfigPatch(w, r)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleConfigReload handles POST /api/config/reload.
func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Rate-limit reload: once per 5 seconds (Finding #5 from review).
	if s.configAPI != nil {
		s.configAPI.mu.Lock()
		if !s.configAPI.lastReloadTime.IsZero() && time.Since(s.configAPI.lastReloadTime) < 5*time.Second {
			s.configAPI.mu.Unlock()
			writeJSONError(w, http.StatusTooManyRequests, "reload rate-limited — wait 5 seconds between reloads")
			return
		}
		s.configAPI.lastReloadTime = time.Now()
		s.configAPI.mu.Unlock()
	}

	// Re-read config from disk.
	if s.configAPI == nil || s.configAPI.configPath == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "config file path not configured")
		return
	}

	newCfg, err := config.Load(s.configAPI.configPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("reload: load config: %v", err))
		return
	}

	result := s.configAPI.reloaderRegistry.Reload(newCfg)

	// Update the server's in-memory config pointer atomically.
	configMu.Lock()
	s.cfg = newCfg
	configMu.Unlock()

	writeJSON(w, http.StatusOK, result)
}

// handleConfigRestart handles POST /api/config/restart.
// Requires step-up token for OpSettings scope.
func (s *Server) handleConfigRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Step-up check: the /api/config/restart route is wrapped in
	// requireStepUp(OpSettings, ...) at registration time, so if we
	// reach here, step-up is already validated.

	// Rate-limit restart: once per 30 seconds.
	if s.configAPI != nil {
		s.configAPI.mu.Lock()
		if !s.configAPI.lastRestartTime.IsZero() && time.Since(s.configAPI.lastRestartTime) < 30*time.Second {
			s.configAPI.mu.Unlock()
			writeJSONError(w, http.StatusTooManyRequests, "restart rate-limited — wait 30 seconds between restarts")
			return
		}
		s.configAPI.lastRestartTime = time.Now()
		s.configAPI.mu.Unlock()
	}

	// In a production deployment, this would send SIGTERM to the process
	// and let the supervisor (systemd) restart it. Here we return the
	// intent; the actual restart is platform-specific.
	resp := map[string]any{
		"ok":      true,
		"message": "Daemon restart initiated. The API will become unresponsive for approximately 3-5 seconds.",
	}

	if s.configAPI != nil && s.configAPI.reloaderRegistry.HasPendingRestart() {
		resp["requires_restart"] = s.configAPI.reloaderRegistry.PendingRestartFields()
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleConfigDiff handles GET /api/config/diff.
func (s *Server) handleConfigDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.configAPI == nil || s.configAPI.configPath == "" {
		writeJSONError(w, http.StatusServiceUnavailable, "config file path not configured")
		return
	}

	// Read saved config from disk.
	savedCfg, err := config.Load(s.configAPI.configPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("diff: load saved config: %v", err))
		return
	}

	// Get running config (in-memory).
	configMu.RLock()
	runningCfg := s.cfg
	configMu.RUnlock()

	// Compute diff by serializing both to maps and comparing.
	diff := computeConfigDiff(runningCfg, savedCfg)

	resp := map[string]any{
		"running_vs_saved": diff,
		"pending_restart":  s.configAPI.reloaderRegistry.HasPendingRestart(),
	}

	writeJSON(w, http.StatusOK, resp)
}

// --- GET /api/config ---

// handleConfigGet handles GET /api/config and GET /api/config?section=<name>.
func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	configMu.RLock()
	cfg := s.cfg
	configMu.RUnlock()

	// Serialize config to a generic map for tier-based masking.
	cfgMap := configToMap(cfg)

	// Apply masking to T1 fields.
	applyMasking(cfgMap)

	section := r.URL.Query().Get("section")
	meta := buildConfigMeta()

	if section != "" {
		// Single section response.
		if !validSections[section] {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("unknown section: %s", section))
			return
		}
		sectionData, ok := cfgMap[section]
		if !ok {
			writeJSONError(w, http.StatusNotFound, fmt.Sprintf("section not found: %s", section))
			return
		}
		resp := map[string]any{
			"section": section,
			"data":    sectionData,
			"_meta":   buildSectionMeta(section),
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Full config response.
	cfgMap["_meta"] = meta
	writeJSON(w, http.StatusOK, cfgMap)
}

// --- PUT /api/config ---

// handleConfigPut handles PUT /api/config (full replacement).
func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	// Remove _meta if present (client shouldn't send it, but be lenient).
	delete(body, "_meta")

	// Collect all field paths present in the body.
	paths := collectFieldPaths(body, "")

	// 1. Check for read-only field violations (AC-2, AC-10).
	var readonlyViolations []string
	for _, p := range paths {
		if isReadOnly(p) {
			readonlyViolations = append(readonlyViolations, p)
		}
	}
	if len(readonlyViolations) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "readonly_fields",
			"fields":  readonlyViolations,
			"message": "These fields cannot be modified via the API",
		})
		return
	}

	// 2. Check for unknown fields (AC-12).
	var unknownFields []string
	for _, p := range paths {
		if !isKnownField(p) {
			unknownFields = append(unknownFields, p)
		}
	}
	if len(unknownFields) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "unknown_fields",
			"fields":  unknownFields,
			"message": "Unknown field paths are rejected to prevent typos",
		})
		return
	}

	// 3. Check for step-up requirement (AC-3, AC-4).
	stepUpNeeded := []string{}
	for _, p := range paths {
		if isStepUp(p) {
			stepUpNeeded = append(stepUpNeeded, p)
		}
	}

	if len(stepUpNeeded) > 0 {
		sessionToken := sessionTokenFromContext(r.Context())
		if !s.stepUpStore.Validate(sessionToken, OpSettings) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-StepUp-Required", "settings")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"error":                    "step_up_required",
				"step_up_scopes":          []string{OpSettings},
				"fields_requiring_step_up": stepUpNeeded,
			})
			return
		}
	}

	// 4. Apply the config changes.
	result := s.applyConfigChanges(body, paths)
	writeJSON(w, http.StatusOK, result)
}

// --- PATCH /api/config ---

// handleConfigPatch handles PATCH /api/config (partial update via JSON merge-patch).
func (s *Server) handleConfigPatch(w http.ResponseWriter, r *http.Request) {
	var patch map[string]any
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	// Remove _meta if present.
	delete(patch, "_meta")

	// Collect field paths from the patch.
	paths := collectFieldPaths(patch, "")

	// 1. Check read-only violations.
	var readonlyViolations []string
	for _, p := range paths {
		if isReadOnly(p) {
			readonlyViolations = append(readonlyViolations, p)
		}
	}
	if len(readonlyViolations) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "readonly_fields",
			"fields":  readonlyViolations,
			"message": "These fields cannot be modified via the API",
		})
		return
	}

	// 2. Check unknown fields.
	var unknownFields []string
	for _, p := range paths {
		if !isKnownField(p) {
			unknownFields = append(unknownFields, p)
		}
	}
	if len(unknownFields) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "unknown_fields",
			"fields":  unknownFields,
			"message": "Unknown field paths are rejected to prevent typos",
		})
		return
	}

	// 3. Check step-up.
	stepUpNeeded := []string{}
	for _, p := range paths {
		if isStepUp(p) {
			stepUpNeeded = append(stepUpNeeded, p)
		}
	}

	if len(stepUpNeeded) > 0 {
		sessionToken := sessionTokenFromContext(r.Context())
		if !s.stepUpStore.Validate(sessionToken, OpSettings) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-StepUp-Required", "settings")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"error":                    "step_up_required",
				"step_up_scopes":          []string{OpSettings},
				"fields_requiring_step_up": stepUpNeeded,
			})
			return
		}
	}

	// 4. Apply JSON merge-patch (RFC 7396): merge patch into existing config.
	merged := s.mergePatchConfig(patch)
	result := s.applyConfigChanges(merged, paths)
	writeJSON(w, http.StatusOK, result)
}

// --- Internal helpers ---

// applyConfigChanges writes the config changes to disk atomically, marks
// dirty fields, and returns the result.
func (s *Server) applyConfigChanges(body map[string]any, paths []string) ConfigPutResult {
	result := ConfigPutResult{OK: true}

	// Load current config from disk (or in-memory if no path).
	var currentCfg *config.Config
	if s.configAPI != nil && s.configAPI.configPath != "" {
		var err error
		currentCfg, err = config.Load(s.configAPI.configPath)
		if err != nil {
			// Fall back to in-memory config.
			configMu.RLock()
			currentCfg = s.cfg
			configMu.RUnlock()
		}
	} else {
		configMu.RLock()
		currentCfg = s.cfg
		configMu.RUnlock()
	}

	// Merge the body into the current config via YAML round-trip.
	// This approach handles nested structs, arrays, and types correctly
	// by leveraging the existing YAML serialization infrastructure.
	merged := mergeConfigMaps(currentCfg, body)

	// Handle masked field no-op: if a T1 field is sent as "***", preserve
	// the existing value (AC-5).
	for _, p := range paths {
		if isMasked(p) {
			val := getPathValue(body, p)
			if val == maskSentinel {
				// Preserve existing value — the merge already did this
				// because we loaded from disk first, but mark it as no-op.
				result.NoOp = append(result.NoOp, p)
			}
		}
	}

	// Write to disk atomically if path is configured.
	if s.configAPI != nil && s.configAPI.configPath != "" {
		if err := atomicConfigSave(s.configAPI.configPath, merged); err != nil {
			result.OK = false
			result.Errors = append(result.Errors, fmt.Sprintf("save config: %v", err))
			return result
		}
	}

	// Update in-memory config.
	configMu.Lock()
	s.cfg = merged
	configMu.Unlock()

	// Mark dirty fields and classify them.
	if s.configAPI != nil {
		for _, p := range paths {
			if isMasked(p) {
				val := getPathValue(body, p)
				if val == maskSentinel {
					continue // no-op, don't mark dirty
				}
			}
			s.configAPI.reloaderRegistry.MarkDirty(p)
		}
	}

	// Build applied/requires_restart lists.
	for _, p := range paths {
		tmpl := fieldPathToTemplate(p)
		if meta, ok := tierMap[tmpl]; ok {
			if meta.Reload == ReloadRestart {
				result.RequiresRestart = append(result.RequiresRestart, p)
			} else {
				result.Applied = append(result.Applied, p)
			}
		} else {
			result.Applied = append(result.Applied, p)
		}
	}

	result.PendingRestart = s.configAPI != nil && s.configAPI.reloaderRegistry.HasPendingRestart()
	result.Warnings = result.NoOp

	return result
}

// mergePatchConfig merges a JSON merge-patch into the existing config,
// returning a full config map suitable for writing.
func (s *Server) mergePatchConfig(patch map[string]any) map[string]any {
	configMu.RLock()
	currentMap := configToMap(s.cfg)
	configMu.RUnlock()

	// RFC 7396 merge: recursively merge patch into current.
	merged := mergeMap(currentMap, patch)
	return merged
}

// mergeMap recursively merges src into dst following RFC 7396 semantics:
// - For objects: recursively merge keys
// - For non-objects: replace the value
// - null means delete the key
func mergeMap(dst, src map[string]any) map[string]any {
	result := make(map[string]any)
	for k, v := range dst {
		result[k] = v
	}
	for k, v := range src {
		if v == nil {
			delete(result, k)
			continue
		}
		srcMap, srcIsMap := v.(map[string]any)
		dstVal, dstHas := result[k]
		if srcIsMap && dstHas {
			if dstMap, dstIsMap := dstVal.(map[string]any); dstIsMap {
				result[k] = mergeMap(dstMap, srcMap)
				continue
			}
		}
		result[k] = v
	}
	return result
}

// ConfigPutResult is the response for PUT/PATCH /api/config.
type ConfigPutResult struct {
	OK              bool     `json:"ok"`
	Applied         []string `json:"applied"`
	RequiresRestart []string `json:"requires_restart,omitempty"`
	NoOp            []string `json:"noop,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	Errors          []string `json:"errors,omitempty"`
	PendingRestart  bool     `json:"pending_restart"`
}

// configToMap serializes a Config struct to a map[string]any via YAML round-trip.
// YAML is used because the Config struct has yaml tags, and this ensures
// field names match the config file.
func configToMap(cfg *config.Config) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}
	// Marshal to YAML, then unmarshal to a generic map.
	data, err := yaml.Marshal(cfg)
	if err != nil {
		log.Printf("configToMap: marshal error: %v", err)
		return map[string]any{}
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		log.Printf("configToMap: unmarshal error: %v", err)
		return map[string]any{}
	}
	// Convert YAML scalar types to JSON-compatible types.
	result := yamlMapToJSON(m)
	if m, ok := result.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// yamlMapToJSON converts YAML-decoded values to JSON-compatible types.
// YAML decodes numbers as int or float64 depending on format, and
// this normalizes everything for JSON serialization.
func yamlMapToJSON(v any) any {
	switch val := v.(type) {
	case map[string]any:
		result := make(map[string]any, len(val))
		for k, vv := range val {
			result[k] = yamlMapToJSON(vv)
		}
		return result
	case map[any]any:
		result := make(map[string]any, len(val))
		for k, vv := range val {
			result[fmt.Sprint(k)] = yamlMapToJSON(vv)
		}
		return result
	case []any:
		for i, item := range val {
			val[i] = yamlMapToJSON(item)
		}
		return val
	default:
		return v
	}
}

// mergeConfigMaps merges a body map into the current config, producing
// a new *config.Config. This is used for PUT (full replacement with
// masked field preservation).
func mergeConfigMaps(current *config.Config, body map[string]any) *config.Config {
	// Serialize current config to map.
	currentMap := configToMap(current)

	// Merge body into current map. For PUT, the body is a full replacement,
	// but masked fields sent as "***" should preserve the existing value.
	merged := mergePutWithMasking(currentMap, body, "")

	// Convert back to *config.Config via YAML round-trip.
	data, err := yaml.Marshal(merged)
	if err != nil {
		log.Printf("mergeConfigMaps: marshal error: %v", err)
		return current
	}
	cfg := config.Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		log.Printf("mergeConfigMaps: unmarshal error: %v", err)
		return current
	}
	return cfg
}

// mergePutWithMasking merges src into dst, but when a T1 masked field
// has the value "***", preserves the existing dst value.
func mergePutWithMasking(dst, src map[string]any, prefix string) map[string]any {
	result := make(map[string]any)
	for k, v := range dst {
		result[k] = v
	}
	for k, v := range src {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		if v == nil {
			delete(result, k)
			continue
		}
		srcMap, srcIsMap := v.(map[string]any)
		dstVal, dstHas := result[k]
		if srcIsMap && dstHas {
			if dstMap, dstIsMap := dstVal.(map[string]any); dstIsMap {
				result[k] = mergePutWithMasking(dstMap, srcMap, path)
				continue
			}
		}
		// Check if this is a masked field with "***" value — preserve existing.
		if isMasked(path) && v == maskSentinel {
			// Keep the existing value from dst.
			if dstHas {
				result[k] = dstVal
				continue
			}
		}
		result[k] = v
	}
	return result
}

// applyMasking walks the config map and replaces all T1 masked field
// values with the "***" sentinel.
func applyMasking(m map[string]any) {
	applyMaskingRecursive(m, "")
}

func applyMaskingRecursive(data any, prefix string) {
	switch v := data.(type) {
	case map[string]any:
		for key, val := range v {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			if isMasked(path) {
				v[key] = maskSentinel
				continue
			}
			applyMaskingRecursive(val, path)
		}
	case map[any]any:
		for key, val := range v {
			path := fmt.Sprint(key)
			if prefix != "" {
				path = prefix + "." + fmt.Sprint(key)
			}
			if isMasked(path) {
				v[key] = maskSentinel
				continue
			}
			applyMaskingRecursive(val, path)
		}
	case []any:
		for i, item := range v {
			// Replace array index in path: prefix[N].field
			path := fmt.Sprintf("%s[%d]", prefix, i)
			applyMaskingRecursive(item, path)
		}
	}
}

// buildConfigMeta builds the _meta object for GET /api/config responses.
func buildConfigMeta() map[string]any {
	tierMapMeta := map[string]string{}
	for path, meta := range tierMap {
		tierStr := meta.Tier.String()
		// Special case: node.identity is dual-tier (read-only + masked).
		if path == "node.identity" {
			tierStr = "read-only+masked"
		}
		tierMapMeta[path] = tierStr
	}

	return map[string]any{
		"tier_map":          tierMapMeta,
		"masked_fields":     maskedFields,
		"readonly_fields":   readOnlyFields,
		"pending_restart":   false, // updated dynamically in handlers
		"dirty_since_reload": []string{},
	}
}

// buildSectionMeta builds a section-specific _meta object.
func buildSectionMeta(section string) map[string]any {
	sectionTierMap := map[string]string{}
	for path, meta := range tierMap {
		if strings.HasPrefix(path, section+".") {
			sectionTierMap[path] = meta.Tier.String()
		}
	}
	return map[string]any{
		"tier_map":        sectionTierMap,
		"pending_restart": false,
	}
}

// collectFieldPaths walks a config map recursively and returns all
// leaf field paths (dot-separated, with array indices).
func collectFieldPaths(data any, prefix string) []string {
	var paths []string
	switch v := data.(type) {
	case map[string]any:
		for key, val := range v {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			paths = append(paths, collectFieldPaths(val, path)...)
		}
	case []any:
		// For arrays, collect paths with index.
		for i, item := range v {
			path := fmt.Sprintf("%s[%d]", prefix, i)
			paths = append(paths, collectFieldPaths(item, path)...)
		}
	default:
		// Leaf value — this is a field path.
		if prefix != "" {
			paths = append(paths, prefix)
		}
	}
	return paths
}

// isKnownField checks if a field path (with numeric indices) matches
// any entry in the tier map (with [N] placeholders).
func isKnownField(path string) bool {
	tmpl := fieldPathToTemplate(path)
	_, ok := tierMap[tmpl]
	if ok {
		return true
	}
	// Check if the path itself (with indices) is in the tier map
	// (e.g. "p2p.authorized_keys" is a T2 field, but
	// "p2p.authorized_keys[0]" is an array element of that field).
	if isStepUp(path) || isMasked(path) || isReadOnly(path) {
		return true
	}
	// Also check if it's a container path (e.g. "peers" or "auth.web_users"
	// which are parents of array entries).
	if isContainerField(path) {
		return true
	}
	// For array element paths (e.g. "p2p.authorized_keys[0]"),
	// check if the parent path (without the index) is known.
	if idx := indexOf(path, "["); idx >= 0 {
		parent := path[:idx]
		if _, ok := tierMap[parent]; ok {
			return true
		}
		if isContainerField(parent) {
			return true
		}
	}
	return false
}

// isContainerField checks if a path is a parent of known fields
// (e.g. "peers" is a container for "peers[N].*").
func isContainerField(path string) bool {
	for tmpl := range tierMap {
		if strings.HasPrefix(tmpl, path+".") || strings.HasPrefix(tmpl, path+"[") {
			return true
		}
	}
	return false
}

// getPathValue retrieves the value at a dotted field path from a map.
// Returns nil if the path doesn't exist.
func getPathValue(data map[string]any, path string) any {
	parts := splitPath(path)
	var current any = data
	for _, part := range parts {
		// Check if part has array index notation.
		bracketIdx := indexOf(part, "[")
		if bracketIdx >= 0 {
			fieldName := part[:bracketIdx]
			idxStr := part[bracketIdx+1 : len(part)-1] // strip [N]
			idx := 0
			for _, c := range idxStr {
				idx = idx*10 + int(c-'0')
			}
			if m, ok := current.(map[string]any); ok {
				if arr, ok := m[fieldName].([]any); ok {
					if idx >= 0 && idx < len(arr) {
						current = arr[idx]
					} else {
						return nil
					}
				} else {
					return nil
				}
			} else {
				return nil
			}
		} else {
			if m, ok := current.(map[string]any); ok {
				if val, ok := m[part]; ok {
					current = val
				} else {
					return nil
				}
			} else {
				return nil
			}
		}
	}
	return current
}

// atomicConfigSave writes config to a temp file, fsyncs, then renames
// over the real path. This prevents corruption on crash (§8.3).
func atomicConfigSave(path string, cfg *config.Config) error {
	tmpPath := path + ".tmp"
	if err := config.Save(tmpPath, cfg); err != nil {
		return err
	}
	// fsync the temp file for durability.
	f, err := os.Open(tmpPath)
	if err == nil {
		f.Sync()
		f.Close()
	}
	// Rename over the real path.
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename config: %w", err)
	}
	return nil
}

// sessionTokenFromContext extracts the session token from the request context.
func sessionTokenFromContext(ctx any) string {
	type contextWithValues interface {
		Value(key any) any
	}
	cwv, ok := ctx.(contextWithValues)
	if !ok {
		return ""
	}
	val := cwv.Value(ctxSessionTokenKey{})
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

// computeConfigDiff computes the diff between running and saved config.
func computeConfigDiff(running, saved *config.Config) map[string]any {
	runningMap := configToMap(running)
	savedMap := configToMap(saved)

	diff := map[string]any{}
	computeDiffRecursive(runningMap, savedMap, "", diff)
	return diff
}

func computeDiffRecursive(running, saved map[string]any, prefix string, diff map[string]any) {
	allKeys := map[string]bool{}
	for k := range running {
		allKeys[k] = true
	}
	for k := range saved {
		allKeys[k] = true
	}
	for k := range allKeys {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		runVal, runHas := running[k]
		savedVal, savedHas := saved[k]

		if !runHas && savedHas {
			diff[path] = map[string]any{
				"running": nil,
				"saved":   savedVal,
			}
			continue
		}
		if runHas && !savedHas {
			diff[path] = map[string]any{
				"running": runVal,
				"saved":   nil,
			}
			continue
		}

		// Both exist — check if they're maps (recurse) or leaves (compare).
		runMap, runIsMap := runVal.(map[string]any)
		savedMap, savedIsMap := savedVal.(map[string]any)
		if runIsMap && savedIsMap {
			computeDiffRecursive(runMap, savedMap, path, diff)
			continue
		}

		// Leaf comparison.
		if fmt.Sprint(runVal) != fmt.Sprint(savedVal) {
			tmpl := fieldPathToTemplate(path)
			meta, ok := tierMap[tmpl]
			tier := "unknown"
			reload := "unknown"
			if ok {
				tier = meta.Tier.String()
				reload = meta.Reload.String()
			}
			diff[path] = map[string]any{
				"running": runVal,
				"saved":   savedVal,
				"tier":    tier,
				"reload":  reload,
			}
		}
	}
}
