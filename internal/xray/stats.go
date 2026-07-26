package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// StatsQueryResult holds the parsed output of `xray api statsquery`.
// xray-core's StatsService returns stat entries like:
//
//	inbound>>>[tag]>>>traffic>>>uplink   → 12345
//	inbound>>>[tag]>>>traffic>>>downlink → 67890
//	user>>>[email]>>>traffic>>>uplink    → 100
//	user>>>[email]>>>traffic>>>downlink  → 200
type StatsQueryResult struct {
	Stat []StatEntry `json:"stat"`
}

// StatEntry is a single stat counter from xray-core's StatsService.
type StatEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"` // xray returns value as string
}

// TrafficStats holds aggregated traffic for a single inbound or user.
type TrafficStats struct {
	Tag      string `json:"tag"`
	Uplink   int64  `json:"uplink"`
	Downlink int64  `json:"downlink"`
	Total    int64  `json:"total"`
}

// ClientTrafficStats holds per-client (per-user) traffic stats.
type ClientTrafficStats struct {
	Email    string `json:"email"`
	Uplink   int64  `json:"uplink"`
	Downlink int64 `json:"downlink"`
	Total    int64  `json:"total"`
}

// AllStats is the combined result returned by QueryAllStats.
type AllStats struct {
	Inbounds []TrafficStats       `json:"inbounds"`
	Clients  []ClientTrafficStats `json:"clients"`
}

// QueryStats queries xray-core's StatsService via the `xray api statsquery` CLI.
// It shells out to the xray binary with the configured API address.
//
// The pattern is an optional filter pattern (empty string = all stats).
// Returns the raw parsed result or an error.
//
// This uses the CLI approach (rather than gRPC directly) to avoid adding
// google.golang.org/grpc and protobuf as dependencies — consistent with
// the HealthChecker's design philosophy.
func QueryStats(ctx context.Context, binaryPath, apiAddr string, pattern string) (*StatsQueryResult, error) {
	if binaryPath == "" {
		return nil, fmt.Errorf("xray binary path is empty")
	}

	args := []string{"api", "statsquery", "-s", apiAddr}
	if pattern != "" {
		args = append(args, "-pattern", pattern)
	}

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Stdout = nil // we capture via Output
	cmd.Stderr = nil

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("xray api statsquery failed: %w", err)
	}

	output = trimXrayOutput(output)
	if len(output) == 0 {
		// xray returns empty when no stats are collected yet
		return &StatsQueryResult{Stat: []StatEntry{}}, nil
	}

	var result StatsQueryResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("parse statsquery output: %w (output: %s)", err, string(output))
	}

	return &result, nil
}

// QueryAllStats queries all traffic stats from xray-core and aggregates
// them into per-inbound and per-client summaries.
func QueryAllStats(ctx context.Context, binaryPath, apiAddr string) (*AllStats, error) {
	result, err := QueryStats(ctx, binaryPath, apiAddr, "")
	if err != nil {
		return nil, err
	}

	inboundMap := make(map[string]*TrafficStats)
	clientMap := make(map[string]*ClientTrafficStats)

	for _, entry := range result.Stat {
		parts := strings.Split(entry.Name, ">>>")
		if len(parts) < 4 {
			continue
		}

		entityType := parts[0] // "inbound" or "user"
		entityName := parts[1] // tag or email
		// parts[2] == "traffic"
		direction := parts[3] // "uplink" or "downlink"

		value, err := strconv.ParseInt(entry.Value, 10, 64)
		if err != nil {
			continue
		}

		switch entityType {
		case "inbound":
			s, ok := inboundMap[entityName]
			if !ok {
				s = &TrafficStats{Tag: entityName}
				inboundMap[entityName] = s
			}
			if direction == "uplink" {
				s.Uplink += value
			} else if direction == "downlink" {
				s.Downlink += value
			}
			s.Total = s.Uplink + s.Downlink

		case "user":
			s, ok := clientMap[entityName]
			if !ok {
				s = &ClientTrafficStats{Email: entityName}
				clientMap[entityName] = s
			}
			if direction == "uplink" {
				s.Uplink += value
			} else if direction == "downlink" {
				s.Downlink += value
			}
			s.Total = s.Uplink + s.Downlink
		}
	}

	inbounds := make([]TrafficStats, 0, len(inboundMap))
	for _, s := range inboundMap {
		inbounds = append(inbounds, *s)
	}
	clients := make([]ClientTrafficStats, 0, len(clientMap))
	for _, s := range clientMap {
		clients = append(clients, *s)
	}

	return &AllStats{
		Inbounds: inbounds,
		Clients:  clients,
	}, nil
}

// QueryInboundStats queries traffic stats for a single inbound tag.
func QueryInboundStats(ctx context.Context, binaryPath, apiAddr, tag string) (*TrafficStats, error) {
	pattern := fmt.Sprintf("inbound>>>%s>>>traffic", tag)
	result, err := QueryStats(ctx, binaryPath, apiAddr, pattern)
	if err != nil {
		return nil, err
	}

	stats := &TrafficStats{Tag: tag}
	for _, entry := range result.Stat {
		parts := strings.Split(entry.Name, ">>>")
		if len(parts) < 4 {
			continue
		}
		direction := parts[3]
		value, err := strconv.ParseInt(entry.Value, 10, 64)
		if err != nil {
			continue
		}
		if direction == "uplink" {
			stats.Uplink += value
		} else if direction == "downlink" {
			stats.Downlink += value
		}
	}
	stats.Total = stats.Uplink + stats.Downlink
	return stats, nil
}

// trimXrayOutput removes leading/trailing whitespace and any non-JSON
// prefixes that xray-core may print (e.g., log lines before the JSON).
func trimXrayOutput(output []byte) []byte {
	s := strings.TrimSpace(string(output))
	if s == "" {
		return nil
	}

	// Find the first '{' — xray may print log lines before the JSON
	idx := strings.Index(s, "{")
	if idx < 0 {
		return nil
	}

	// Find the matching last '}'
	lastIdx := strings.LastIndex(s, "}")
	if lastIdx < idx {
		return nil
	}

	return []byte(s[idx : lastIdx+1])
}

// StatsQueryTimeout is the default timeout for stats queries.
const StatsQueryTimeout = 5 * time.Second
