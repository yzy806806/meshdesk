package mesh

import (
	"context"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/yzy806806/meshdesk/internal/smux"
)

// reconnectConfig holds the parameters for the auto-reconnect logic.
type reconnectConfig struct {
	initialDelay time.Duration
	maxDelay     time.Duration
	maxAttempts  int
}

func defaultReconnectConfig() reconnectConfig {
	return reconnectConfig{
		initialDelay: 2 * time.Second,
		maxDelay:     60 * time.Second,
		maxAttempts:  0,
	}
}

type reconnectTracker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (n *MeshNode) startSessionWatcher(peerIdentityHex, endpoint string, isClientSession bool) {
	cfg := defaultReconnectConfig()

	n.reconnectStateMu.Lock()
	defer n.reconnectStateMu.Unlock()

	if _, exists := n.reconnectState[peerIdentityHex]; exists {
		return
	}

	ctx, cancel := context.WithCancel(n.ctx)
	tracker := &reconnectTracker{
		cancel: cancel,
		done:   make(chan struct{}),
	}
	n.reconnectState[peerIdentityHex] = tracker

	go n.watchSession(ctx, tracker, peerIdentityHex, endpoint, isClientSession, cfg)
}

func (n *MeshNode) watchSession(
	ctx context.Context,
	tracker *reconnectTracker,
	peerIdentityHex, endpoint string,
	isClientSession bool,
	cfg reconnectConfig,
) {
	defer close(tracker.done)

	sess := n.getWatchableSession(peerIdentityHex)
	if sess == nil {
		n.removeReconnectTracker(peerIdentityHex)
		return
	}

	select {
	case <-sess.Done():
	case <-ctx.Done():
		n.removeReconnectTracker(peerIdentityHex)
		return
	}

	log.Printf("[mesh] session lost for peer %s, starting auto-reconnect",
		shortPeerID(peerIdentityHex))

	if n.isShuttingDown() {
		log.Printf("[mesh] node shutting down, skipping reconnect for peer %s",
			shortPeerID(peerIdentityHex))
		n.removeReconnectTracker(peerIdentityHex)
		return
	}

	n.cleanupDeadSession(peerIdentityHex, sess)
	n.reconnectLoop(ctx, tracker, peerIdentityHex, endpoint, isClientSession, cfg)
}

func (n *MeshNode) reconnectLoop(
	ctx context.Context,
	tracker *reconnectTracker,
	peerIdentityHex, endpoint string,
	isClientSession bool,
	cfg reconnectConfig,
) {
	delay := cfg.initialDelay
	attempt := 0

	for {
		attempt++
		if cfg.maxAttempts > 0 && attempt > cfg.maxAttempts {
			log.Printf("[mesh] reconnect exhausted %d attempts for peer %s, giving up",
				cfg.maxAttempts, shortPeerID(peerIdentityHex))
			n.removeReconnectTracker(peerIdentityHex)
			return
		}

		select {
		case <-time.After(delay):
		case <-ctx.Done():
			n.removeReconnectTracker(peerIdentityHex)
			return
		}

		if n.hasActiveSession(peerIdentityHex) {
			log.Printf("[mesh] peer %s already reconnected via another path, cancelling reconnect",
				shortPeerID(peerIdentityHex))
			n.removeReconnectTracker(peerIdentityHex)
			return
		}

		log.Printf("[mesh] reconnect attempt %d for peer %s at %s",
			attempt, shortPeerID(peerIdentityHex), endpoint)

		err := n.tryReconnect(ctx, peerIdentityHex, endpoint, isClientSession)
		if err == nil {
			log.Printf("[mesh] reconnect succeeded for peer %s after %d attempts",
				shortPeerID(peerIdentityHex), attempt)
			n.removeReconnectTracker(peerIdentityHex)
			return
		}

		log.Printf("[mesh] reconnect attempt %d failed for peer %s: %v",
			attempt, shortPeerID(peerIdentityHex), err)

		delay = time.Duration(float64(delay) * 1.5)
		if delay > cfg.maxDelay {
			delay = cfg.maxDelay
		}
	}
}

func (n *MeshNode) tryReconnect(ctx context.Context, peerIdentityHex, endpoint string, isClientSession bool) error {
	if endpoint == "" {
		endpoint = n.resolvePeerEndpoint(peerIdentityHex)
	}
	if endpoint == "" {
		return fmt.Errorf("no known endpoint for peer %s", shortPeerID(peerIdentityHex))
	}

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	stream, err := n.DialPeerByEndpoint(dialCtx, endpoint)
	if err != nil {
		if n.hasPeerConfigByAddress(endpoint) {
			stream2, err2 := n.Dial(dialCtx, "tcp", endpoint)
			if err2 != nil {
				return fmt.Errorf("mesh-internal dial: %w; reality dial: %v", err, err2)
			}
			stream2.Close()
			return nil
		}
		return fmt.Errorf("mesh-internal dial: %w", err)
	}
	stream.Close()
	return nil
}

func (n *MeshNode) getWatchableSession(peerIdentityHex string) *smux.Session {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()

	if sess, ok := n.clientSessions[peerIdentityHex]; ok && sess != nil {
		return sess
	}
	if sess, ok := n.sessions[peerIdentityHex]; ok && sess != nil {
		return sess
	}
	return nil
}

func (n *MeshNode) hasActiveSession(peerIdentityHex string) bool {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()

	if sess, ok := n.clientSessions[peerIdentityHex]; ok && sess != nil && !sess.IsClosed() {
		return true
	}
	if sess, ok := n.sessions[peerIdentityHex]; ok && sess != nil && !sess.IsClosed() {
		return true
	}
	return false
}

func (n *MeshNode) cleanupDeadSession(peerIdentityHex string, deadSess *smux.Session) {
	n.sessionsMu.Lock()
	defer n.sessionsMu.Unlock()

	if sess, ok := n.sessions[peerIdentityHex]; ok && sess == deadSess {
		delete(n.sessions, peerIdentityHex)
	}
	if sess, ok := n.clientSessions[peerIdentityHex]; ok && sess == deadSess {
		delete(n.clientSessions, peerIdentityHex)
	}
}

func (n *MeshNode) resolvePeerEndpoint(peerIdentityHex string) string {
	for i := range n.cfg.Peers {
		if n.cfg.Peers[i].PublicKey == peerIdentityHex {
			return n.cfg.Peers[i].Endpoint
		}
	}
	if entry, ok := n.routes.GetPeer(peerIdentityHex); ok && entry.Endpoint != "" {
		return entry.Endpoint
	}
	return ""
}

func (n *MeshNode) removeReconnectTracker(peerIdentityHex string) {
	n.reconnectStateMu.Lock()
	defer n.reconnectStateMu.Unlock()
	delete(n.reconnectState, peerIdentityHex)
}

func (n *MeshNode) stopReconnectWatcher(peerIdentityHex string) {
	n.reconnectStateMu.Lock()
	tracker, ok := n.reconnectState[peerIdentityHex]
	if ok {
		delete(n.reconnectState, peerIdentityHex)
	}
	n.reconnectStateMu.Unlock()

	if ok {
		tracker.cancel()
		select {
		case <-tracker.done:
		case <-time.After(5 * time.Second):
			log.Printf("[mesh] reconnect watcher for peer %s did not exit within 5s",
				shortPeerID(peerIdentityHex))
		}
	}
}

func (n *MeshNode) isShuttingDown() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.closed
}

func shortPeerID(id string) string {
	if len(id) <= 16 {
		return id
	}
	return id[:16] + "..."
}

func (n *MeshNode) stopAllReconnectWatchers() {
	n.reconnectStateMu.Lock()
	trackers := make([]*reconnectTracker, 0, len(n.reconnectState))
	for id, tracker := range n.reconnectState {
		trackers = append(trackers, tracker)
		delete(n.reconnectState, id)
	}
	n.reconnectStateMu.Unlock()

	var wg sync.WaitGroup
	for _, tracker := range trackers {
		wg.Add(1)
		go func(t *reconnectTracker) {
			defer wg.Done()
			t.cancel()
			select {
			case <-t.done:
			case <-time.After(5 * time.Second):
			}
		}(tracker)
	}
	wg.Wait()
}

func backoffDelay(attempt int, initial, max time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	mult := math.Pow(1.5, float64(attempt-1))
	delayFloat := float64(initial) * mult
	if delayFloat > float64(max) || delayFloat < 0 {
		return max
	}
	return time.Duration(delayFloat)
}
