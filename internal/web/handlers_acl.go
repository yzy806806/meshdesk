package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

// ACLProvider abstracts the ACL engine for the web layer.
// In production this is satisfied by *mesh.MeshNode.
type ACLProvider interface {
	ACL() *mesh.ACLEngine
	BroadcastACLRules(rules []string)
}

// aclRuleJSON is the JSON representation of an ACL rule for the API.
type aclRuleJSON struct {
	Action      string `json:"action"`
	SourceCIDR  string `json:"src_cidr"`
	DestCIDR    string `json:"dst_cidr"`
	Protocol    string `json:"protocol"`
	SrcPort     int    `json:"src_port"`
	DstPort     int    `json:"dst_port"`
	PeerID      string `json:"peer_id"`
	Description string `json:"description"`
}

// aclStatusResponse is the JSON response for GET /api/acl/status.
type aclStatusResponse struct {
	Enabled       bool                   `json:"enabled"`
	DefaultPolicy string                 `json:"default_policy"`
	AllowCount    uint64                 `json:"allow_count"`
	DenyCount     uint64                 `json:"deny_count"`
	Rules         []aclRuleJSON          `json:"rules"`
	RuleHits      []mesh.ACLRuleHitStats `json:"rule_hits"`
}

// handleACLPage renders the ACL management Dashboard page.
func (s *Server) handleACLPage(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:      "Access Control (ACL)",
		ActivePage: "acl",
	}
	s.renderPage(w, "acl.html", data)
}

// handleACLStatus handles GET /api/acl/status.
// Returns the current ACL engine state, rules, and hit statistics.
func (s *Server) handleACLStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	provider := s.getACLProvider()
	if provider == nil {
		writeJSON(w, http.StatusOK, aclStatusResponse{
			Enabled:       false,
			DefaultPolicy: "allow",
			Rules:         []aclRuleJSON{},
			RuleHits:      []mesh.ACLRuleHitStats{},
		})
		return
	}

	engine := provider.ACL()
	if engine == nil {
		writeJSON(w, http.StatusOK, aclStatusResponse{
			Enabled:       false,
			DefaultPolicy: "allow",
			Rules:         []aclRuleJSON{},
			RuleHits:      []mesh.ACLRuleHitStats{},
		})
		return
	}

	stats := engine.Stats()

	// Build rules JSON from the engine's current rules (full detail fields).
	rules := rulesToJSON(engine.CurrentRules())

	writeJSON(w, http.StatusOK, aclStatusResponse{
		Enabled:       stats.Enabled,
		DefaultPolicy: string(stats.DefaultPolicy),
		AllowCount:    stats.AllowCount,
		DenyCount:     stats.DenyCount,
		Rules:         rules,
		RuleHits:      stats.RuleHits,
	})
}

// handleACLRules handles POST/PUT/DELETE /api/acl/rules.
//
//	POST   — add a single rule to the current set.
//	PUT    — replace the entire rule set.
//	DELETE — delete a rule by index (?index=N).
func (s *Server) handleACLRules(w http.ResponseWriter, r *http.Request) {
	provider := s.getACLProvider()
	if provider == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "ACL not available")
		return
	}

	engine := provider.ACL()
	if engine == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "ACL engine not initialized")
		return
	}

	switch r.Method {
	case http.MethodPost:
		// Add a single rule.
		var rule aclRuleJSON
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}

		cfgRule := jsonToConfigRule(rule)
		if err := validateRule(cfgRule); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Get current config rules, append, and update.
		currentRules := engine.CurrentRules()
		currentRules = append(currentRules, cfgRule)

		if err := engine.UpdateRules(config.ACLConfig{
			Enabled:       engine.IsEnabled(),
			DefaultPolicy: engine.DefaultPolicy(),
			Rules:         currentRules,
		}); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Broadcast updated rules via gossip.
		provider.BroadcastACLRules(mesh.EncodeACLRulesForGossip(currentRules))

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": "rule added",
			"rules":   rulesToJSON(currentRules),
		})

	case http.MethodPut:
		// Replace all rules.
		var rules []aclRuleJSON
		if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}

		cfgRules := make([]config.ACLRule, 0, len(rules))
		for i, r := range rules {
			cr := jsonToConfigRule(r)
			if err := validateRule(cr); err != nil {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("rule %d: %s", i, err.Error()))
				return
			}
			cfgRules = append(cfgRules, cr)
		}

		if err := engine.UpdateRules(config.ACLConfig{
			Enabled:       engine.IsEnabled(),
			DefaultPolicy: engine.DefaultPolicy(),
			Rules:         cfgRules,
		}); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		provider.BroadcastACLRules(mesh.EncodeACLRulesForGossip(cfgRules))

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": "rules replaced",
			"rules":   rulesToJSON(cfgRules),
		})

	case http.MethodDelete:
		// Delete a rule by index.
		indexStr := r.URL.Query().Get("index")
		index, err := strconv.Atoi(indexStr)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid index parameter")
			return
		}

		currentRules := engine.CurrentRules()
		if index < 0 || index >= len(currentRules) {
			writeJSONError(w, http.StatusBadRequest, "index out of range")
			return
		}

		// Remove the rule at index.
		newRules := append(currentRules[:index], currentRules[index+1:]...)

		if err := engine.UpdateRules(config.ACLConfig{
			Enabled:       engine.IsEnabled(),
			DefaultPolicy: engine.DefaultPolicy(),
			Rules:         newRules,
		}); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		provider.BroadcastACLRules(mesh.EncodeACLRulesForGossip(newRules))

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"message": "rule deleted",
			"rules":   rulesToJSON(newRules),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleACLEngine handles PUT /api/acl/engine.
// Updates the ACL engine settings (enabled, default_policy).
func (s *Server) handleACLEngine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	provider := s.getACLProvider()
	if provider == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "ACL not available")
		return
	}

	engine := provider.ACL()
	if engine == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "ACL engine not initialized")
		return
	}

	var req struct {
		Enabled       *bool  `json:"enabled"`
		DefaultPolicy string `json:"default_policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	enabled := engine.IsEnabled()
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	defaultPolicy := config.ACLAction(req.DefaultPolicy)
	if defaultPolicy == "" {
		defaultPolicy = engine.DefaultPolicy()
	}
	if defaultPolicy != config.ACLActionAllow && defaultPolicy != config.ACLActionDeny {
		writeJSONError(w, http.StatusBadRequest, "default_policy must be allow or deny")
		return
	}

	currentRules := engine.CurrentRules()
	if err := engine.UpdateRules(config.ACLConfig{
		Enabled:       enabled,
		DefaultPolicy: defaultPolicy,
		Rules:         currentRules,
	}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"enabled":        enabled,
		"default_policy": string(defaultPolicy),
	})
}

// getACLProvider returns the ACL provider from the mesh node, or nil.
func (s *Server) getACLProvider() ACLProvider {
	if s.node == nil {
		return nil
	}
	return s.node
}

// jsonToConfigRule converts a JSON rule to a config.ACLRule.
func jsonToConfigRule(j aclRuleJSON) config.ACLRule {
	return config.ACLRule{
		Action:      config.ACLAction(j.Action),
		SourceCIDR:  j.SourceCIDR,
		DestCIDR:    j.DestCIDR,
		Protocol:    j.Protocol,
		SrcPort:     j.SrcPort,
		DstPort:     j.DstPort,
		PeerID:      j.PeerID,
		Description: j.Description,
	}
}

// validateRule checks that a rule has a valid action.
func validateRule(r config.ACLRule) error {
	if r.Action != config.ACLActionAllow && r.Action != config.ACLActionDeny {
		return fmt.Errorf("action must be 'allow' or 'deny'")
	}
	return nil
}

// rulesToJSON converts config rules to JSON rules.
func rulesToJSON(rules []config.ACLRule) []aclRuleJSON {
	result := make([]aclRuleJSON, 0, len(rules))
	for _, r := range rules {
		srcCIDR := r.SourceCIDR
		if srcCIDR == "" {
			srcCIDR = "*"
		}
		dstCIDR := r.DestCIDR
		if dstCIDR == "" {
			dstCIDR = "*"
		}
		proto := r.Protocol
		if proto == "" {
			proto = "*"
		}
		peerID := r.PeerID
		if peerID == "" {
			peerID = "*"
		}
		result = append(result, aclRuleJSON{
			Action:      string(r.Action),
			SourceCIDR:  srcCIDR,
			DestCIDR:    dstCIDR,
			Protocol:    proto,
			SrcPort:     r.SrcPort,
			DstPort:     r.DstPort,
			PeerID:      peerID,
			Description: r.Description,
		})
	}
	return result
}
