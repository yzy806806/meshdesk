package app

import (
	"log"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

// Reload applies a hot-reload of config (SIGHUP / Dashboard hot
// reload): monitoring collectors/interval, web reloaders, logging,
// ACL rules. Cross-subsystem wiring lives here — the SIGHUP handler in
// Run() only calls this.
func (a *App) Reload(newCfg *config.Config) error {
	// Apply hot-reloadable fields to the running config.
	a.cfg.Monitoring.Collectors = newCfg.Monitoring.Collectors
	a.cfg.Monitoring.Interval = newCfg.Monitoring.Interval

	if a.webServer != nil {
		if err := a.webServer.ReloadConfig(newCfg); err != nil {
			log.Printf("SIGHUP: web reload error: %v", err)
		}
	}
	if a.reporter != nil {
		a.reporter.SetCollectors(newCfg.Monitoring.Collectors)
		a.reporter.SetInterval(newCfg.Monitoring.Interval)
	}
	// Re-apply logging config if changed.
	if a.logWriter != nil {
		a.logWriter.SetMaxAge(newCfg.Logging.LogMaxAge)
		if newCfg.Logging.LogMaxSize > 0 {
			a.logWriter.SetMaxSize(newCfg.Logging.LogMaxSize)
		}
		if newCfg.Logging.LogMaxBackups > 0 {
			a.logWriter.SetMaxBackups(newCfg.Logging.LogMaxBackups)
		}
	}
	if newCfg.Logging.LogLevel != "" {
		log.Printf("SIGHUP: log_level set to %s", newCfg.Logging.LogLevel)
	}
	// Apply ACL rules if the engine is configured.
	if aclEngine := a.node.ACL(); aclEngine != nil {
		if err := aclEngine.UpdateRules(newCfg.ACL); err != nil {
			log.Printf("SIGHUP: ACL reload error: %v", err)
		} else {
			log.Printf("SIGHUP: ACL rules reloaded (%d rules, enabled=%v, default_policy=%s)",
				len(newCfg.ACL.Rules), newCfg.ACL.Enabled, newCfg.ACL.DefaultPolicy)
			a.node.BroadcastACLRules(mesh.EncodeACLRulesForGossip(newCfg.ACL.Rules))
		}
	}
	return nil
}
