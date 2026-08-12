package app

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
)

// Run blocks until a shutdown signal (SIGINT/SIGTERM), handling
// SIGHUP (config reload) and SIGUSR1 (state dump) in the loop, then
// performs an orderly shutdown via Stop().
func (a *App) Run() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGUSR1:
			// Dump peers/sessions/routes to the log for diagnostics.
			log.Printf("=== SIGUSR1: state dump ===")
			a.node.DumpState(log.Writer())
			log.Printf("=== end state dump ===")

		case syscall.SIGHUP:
			log.Printf("SIGHUP: reloading config from %s", a.configPath)
			newCfg, err := config.Load(a.configPath)
			if err != nil {
				log.Printf("SIGHUP: config reload failed: %v", err)
				continue
			}
			if err := a.Reload(newCfg); err != nil {
				log.Printf("SIGHUP: reload error: %v", err)
			} else {
				log.Printf("SIGHUP: config reloaded successfully")
				if a.sdNotifier != nil {
					if s, ok := a.sdNotifier.(interface{ Status(string) }); ok {
						s.Status("config reloaded")
					}
				}
			}

		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("Received %s, shutting down...", sig)
			a.Stop()
			return
		}
	}
}

// sdNotifierStatus abstracts the systemd notifier Status call.
type sdNotifierStatus interface {
	Status(string)
	Stopping()
	Enabled() bool
}

// notifyStopping tells systemd we're beginning an orderly shutdown.
func (a *App) notifyStopping() {
	if a.sdNotifier != nil {
		if s, ok := a.sdNotifier.(sdNotifierStatus); ok && s.Enabled() {
			s.Stopping()
		}
	}
}

// sendLeaveNotice sends a graceful gossip leave notice before teardown.
func (a *App) sendLeaveNotice() {
	if a.gossipLayer != nil && a.gossipLayer.IsStarted() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := a.gossipLayer.SendLeaveNotice(ctx); err != nil {
			log.Printf("Warning: leave notice: %v", err)
		}
	}
}
