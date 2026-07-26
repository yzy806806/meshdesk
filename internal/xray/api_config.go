package xray

// ApiConfig is the top-level xray-core API configuration.
// When present, xray-core exposes a gRPC API on the inbound
// tagged with the same name (typically "api"), allowing remote
// management and health checking.
type ApiConfig struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services,omitempty"` // e.g. "HandlerService", "LoggerService", "StatsService"
}

// DokodemoDoorSettings are the settings for a dokodemo-door inbound.
// The dokodemo-door protocol accepts connections on any port and
// forwards them to a configured destination. When used for the API,
// it routes to the API handler via routing rules.
type DokodemoDoorSettings struct {
	Address        string `json:"address"`           // destination address
	Port           int    `json:"port,omitempty"`    // destination port
	Network        string `json:"network,omitempty"` // "tcp" (default) or "udp"
	FollowRedirect bool   `json:"followRedirect,omitempty"`
	UserLevel      int    `json:"userLevel,omitempty"`
}
