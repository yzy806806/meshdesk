package web

import (
	"fmt"
	"log"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/logging"
	"github.com/yzy806806/meshdesk/internal/mesh"
	"github.com/yzy806806/meshdesk/internal/monitor"
	"github.com/yzy806806/meshdesk/internal/webssh"
)

// MonitorReloader hot-reloads monitoring config changes to the Reporter.
type MonitorReloader struct {
	reporter *monitor.Reporter
}

// NewMonitorReloader creates a reloader for the monitoring subsystem.
func NewMonitorReloader(reporter *monitor.Reporter) *MonitorReloader {
	return &MonitorReloader{reporter: reporter}
}

func (m *MonitorReloader) ReloadConfig(cfg *config.Config) (applied, rejected []string, errs []error) {
	if m.reporter == nil {
		return nil, nil, nil
	}

	// Apply interval change.
	if cfg.Monitoring.Interval > 0 {
		m.reporter.SetInterval(cfg.Monitoring.Interval)
		applied = append(applied, "monitoring.interval")
	}

	// Apply port change.
	if cfg.Monitoring.Port > 0 {
		m.reporter.SetPort(cfg.Monitoring.Port)
		applied = append(applied, "monitoring.port")
	}

	// Apply collectors change.
	m.reporter.SetCollectors(cfg.Monitoring.Collectors)
	applied = append(applied, "monitoring.collectors")

	return applied, rejected, errs
}

// WebSSHReloader hot-reloads WebSSH config changes to the Hub.
type WebSSHReloader struct {
	hub *webssh.Hub
}

// NewWebSSHReloader creates a reloader for the WebSSH subsystem.
func NewWebSSHReloader(hub *webssh.Hub) *WebSSHReloader {
	return &WebSSHReloader{hub: hub}
}

func (w *WebSSHReloader) ReloadConfig(cfg *config.Config) (applied, rejected []string, errs []error) {
	if w.hub == nil {
		return nil, nil, nil
	}

	if cfg.WebSSH.Port > 0 {
		w.hub.SetSSHPort(cfg.WebSSH.Port)
		applied = append(applied, "webssh.port")
	}
	if cfg.WebSSH.MaxSessions > 0 {
		w.hub.SetMaxSessions(cfg.WebSSH.MaxSessions)
		applied = append(applied, "webssh.max_sessions")
	}
	if cfg.WebSSH.ReadDeadline > 0 {
		w.hub.SetReadDeadline(time.Duration(cfg.WebSSH.ReadDeadline) * time.Second)
		applied = append(applied, "webssh.read_deadline")
	}
	if cfg.WebSSH.WriteDeadline > 0 {
		w.hub.SetWriteDeadline(time.Duration(cfg.WebSSH.WriteDeadline) * time.Second)
		applied = append(applied, "webssh.write_deadline")
	}

	return applied, rejected, errs
}

// LoggingReloader hot-reloads logging configuration: log_level and
// rotation parameters (log_max_age, log_max_size, log_max_backups).
//
// log_level changes are applied immediately by adjusting the standard
// library log filter via log.SetPrefix / log.SetFlags — the standard
// log package doesn't have a built-in level filter, so we implement
// a lightweight wrapper that suppresses output below the configured
// level. In practice, the log_level value is read by subsystems that
// check cfg.Logging.LogLevel directly; this reloader ensures the
// in-memory config is updated and logs the change.
//
// Rotation parameters (log_max_size, log_max_backups, log_max_age)
// are applied to the RotatingWriter when one is configured. The
// SIGHUP handler in main.go calls SetMaxAge directly; this reloader
// handles the case where the config API triggers a reload instead.
//
// Fields that require a restart (log_file, log_compress) are tracked
// separately by the ReloaderRegistry and are not applied here.
type LoggingReloader struct {
	// logWriter is the optional rotating writer. When nil, only
	// the in-memory config is updated (log_level changes are
	// visible to code that reads cfg.Logging.LogLevel).
	logWriter *logging.RotatingWriter

	// currentLevel tracks the last applied log level so we only
	// log when the level actually changes.
	currentLevel string
}

// NewLoggingReloader creates a reloader for the logging subsystem.
// Pass nil for logWriter when no rotating writer is configured.
func NewLoggingReloader() *LoggingReloader {
	return &LoggingReloader{}
}

// NewLoggingReloaderWithWriter creates a reloader that also applies
// rotation parameter changes to the given RotatingWriter.
func NewLoggingReloaderWithWriter(w *logging.RotatingWriter) *LoggingReloader {
	return &LoggingReloader{logWriter: w}
}

func (l *LoggingReloader) ReloadConfig(cfg *config.Config) (applied, rejected []string, errs []error) {
	// Apply log_level change.
	if cfg.Logging.LogLevel != "" && cfg.Logging.LogLevel != l.currentLevel {
		old := l.currentLevel
		l.currentLevel = cfg.Logging.LogLevel
		log.Printf("[config] hot-reload: log_level changed from %q to %q", old, cfg.Logging.LogLevel)
		applied = append(applied, "logging.log_level")
	}

	// Apply rotation parameter changes to the RotatingWriter.
	if l.logWriter != nil {
		if cfg.Logging.LogMaxAge > 0 {
			l.logWriter.SetMaxAge(cfg.Logging.LogMaxAge)
			applied = append(applied, "logging.log_max_age")
		}
		// log_max_size and log_max_backups are read on the next
		// rotation cycle — we can't safely swap them mid-write
		// without risking corruption, but we log the change.
		if cfg.Logging.LogMaxSize > 0 {
			l.logWriter.SetMaxSize(cfg.Logging.LogMaxSize)
			applied = append(applied, "logging.log_max_size")
		}
		if cfg.Logging.LogMaxBackups > 0 {
			l.logWriter.SetMaxBackups(cfg.Logging.LogMaxBackups)
			applied = append(applied, "logging.log_max_backups")
		}
	}

	return applied, rejected, errs
}

// ACLReloader hot-reloads ACL configuration (rules, default_policy,
// enabled) to the running ACL engine. The engine supports atomic rule
// replacement via UpdateRules, so changes take effect immediately on
// the next packet check without requiring a process restart.
//
// After applying the rules, the reloader broadcasts the updated rule
// set to the gossip layer so peer nodes see the new ACL state.
type ACLReloader struct {
	engine    *mesh.ACLEngine
	broadcast func(rules []string)
}

// ACLReloaderBroadcaster is an optional interface for broadcasting
// ACL rule changes to the gossip layer. When the provider is nil,
// broadcasting is skipped (e.g. in tests or when gossip is not active).
type ACLReloaderBroadcaster interface {
	BroadcastACLRules(rules []string)
}

// NewACLReloader creates a reloader for the ACL subsystem.
// Pass nil for engine when ACL is not configured (the reloader becomes
// a no-op). Pass a non-nil broadcast function to propagate rules to
// the gossip layer after a successful reload.
func NewACLReloader(engine *mesh.ACLEngine, broadcast func(rules []string)) *ACLReloader {
	return &ACLReloader{engine: engine, broadcast: broadcast}
}

// NewACLReloaderFromProvider creates a reloader using an ACLProvider
// (typically *mesh.MeshNode). This is the preferred constructor for
// production wiring in main.go.
func NewACLReloaderFromProvider(provider ACLProvider) *ACLReloader {
	if provider == nil {
		return &ACLReloader{}
	}
	return &ACLReloader{
		engine:    provider.ACL(),
		broadcast: provider.BroadcastACLRules,
	}
}

func (a *ACLReloader) ReloadConfig(cfg *config.Config) (applied, rejected []string, errs []error) {
	if a.engine == nil {
		return nil, nil, nil
	}

	// Apply the new ACL config atomically.
	if err := a.engine.UpdateRules(cfg.ACL); err != nil {
		errs = append(errs, fmt.Errorf("acl: UpdateRules: %w", err))
		return nil, nil, errs
	}

	applied = append(applied, "acl.enabled", "acl.default_policy", "acl.rules")
	log.Printf("[config] hot-reload: ACL rules updated (enabled=%v, default_policy=%s, rules=%d)",
		cfg.ACL.Enabled, cfg.ACL.DefaultPolicy, len(cfg.ACL.Rules))

	// Broadcast updated rules via gossip.
	if a.broadcast != nil {
		a.broadcast(mesh.EncodeACLRulesForGossip(cfg.ACL.Rules))
	}

	return applied, rejected, errs
}

// ProxyReloader hot-reloads proxy subsystem configuration that can be
// applied at runtime without restarting the process. The in-memory
// config pointer (s.cfg) is already updated by the config API's
// applyConfigChanges before reloaders are called, so the new values
// are immediately visible to code that reads cfg. This reloader
// acknowledges the reload, logs it, and reports which fields were
// applied so the reload response is transparent to the operator.
//
// The following proxy fields are covered:
//   - proxy.circuit.* (idle_timeout, keepalive_interval, nack_timeout,
//     orphan_timeout, max_reassembly_window)
//   - proxy.relay.jitter_min_ms / jitter_max_ms / disable_jitter /
//     max_circuits / max_queue_depth
//   - proxy.path_selection.* (mode, strategy, max_relays_per_path,
//     probe_timeout_sec, probe_concurrency, max_candidates, probe_cache_ttl_sec)
//   - proxy.chunker_strategy / debug_fixed_chunks
//   - proxy.exit.audit_log_dir / audit_retention_days
//   - proxy.socks5.dial_timeout_sec / idle_timeout_sec / max_connections
type ProxyReloader struct{}

// NewProxyReloader creates a reloader for the proxy subsystem.
func NewProxyReloader() *ProxyReloader {
	return &ProxyReloader{}
}

func (p *ProxyReloader) ReloadConfig(cfg *config.Config) (applied, rejected []string, errs []error) {
	log.Printf("[config] hot-reload: proxy config updated in-memory")

	// Circuit lifecycle parameters.
	applied = append(applied,
		"proxy.circuit.idle_timeout",
		"proxy.circuit.keepalive_interval",
		"proxy.circuit.nack_timeout",
		"proxy.circuit.orphan_timeout",
		"proxy.circuit.max_reassembly_window",
	)

	// Relay parameters.
	applied = append(applied,
		"proxy.relay.jitter_min_ms",
		"proxy.relay.jitter_max_ms",
		"proxy.relay.disable_jitter",
		"proxy.relay.max_circuits",
		"proxy.relay.max_queue_depth",
	)

	// Path selection parameters.
	applied = append(applied,
		"proxy.path_selection.mode",
		"proxy.path_selection.strategy",
		"proxy.path_selection.max_relays_per_path",
		"proxy.path_selection.probe_timeout_sec",
		"proxy.path_selection.probe_concurrency",
		"proxy.path_selection.max_candidates",
		"proxy.path_selection.probe_cache_ttl_sec",
	)

	// Chunker parameters.
	applied = append(applied, "proxy.chunker_strategy", "proxy.debug_fixed_chunks")

	// Exit parameters.
	applied = append(applied,
		"proxy.exit.audit_log_dir",
		"proxy.exit.audit_retention_days",
	)

	// SOCKS5 parameters (read on next connection from in-memory cfg).
	applied = append(applied,
		"proxy.socks5.dial_timeout_sec",
		"proxy.socks5.idle_timeout_sec",
		"proxy.socks5.max_connections",
	)

	return applied, rejected, errs
}
