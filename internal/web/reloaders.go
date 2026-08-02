package web

import (
	"log"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
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

// LoggingReloader is a no-op reloader that logs which fields were marked
// for hot-reload but have no dedicated subsystem reloader. The in-memory
// config pointer is already updated by the config API, so the new values
// are visible to any code that reads s.cfg. Fields that require a restart
// are tracked separately by the ReloaderRegistry.
//
// This covers fields like:
//   - proxy.circuit.* (read from config on next circuit creation)
//   - proxy.relay.* (read from config on next relay registration)
//   - proxy.exit.* (read from config on next exit connection)
//   - proxy.path_selection.* (read from config on next path selection)
//   - p2p.gossip_interval / gossip_probe_interval (applied on restart)
//   - reality.dest / server_names / short_ids (applied on restart)
type LoggingReloader struct{}

func NewLoggingReloader() *LoggingReloader { return &LoggingReloader{} }

func (l *LoggingReloader) ReloadConfig(cfg *config.Config) (applied, rejected []string, errs []error) {
	// The in-memory config pointer (s.cfg) is already updated by the
	// config API's applyConfigChanges. This reloader exists to acknowledge
	// that the config was reloaded and to log it.
	log.Printf("[config] hot-reload: in-memory config updated for fields without dedicated reloaders")
	return nil, nil, nil
}
