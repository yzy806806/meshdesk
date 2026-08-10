package mesh

import (
	"context"
	"fmt"
	"log"
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

	// Fire the session death handler to clean up TUN routes and other
	// session-dependent state. This is the correct place to clean up:
	// the smux session is truly dead, as opposed to a memberlist UDP flap
	// where the session may still be alive.
	n.mu.RLock()
	deathHdl := n.sessionDeathHandler
	n.mu.RUnlock()
	if deathHdl != nil {
		deathHdl(peerIdentityHex)
	}

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
			// The session was restored by another path (auto-connect
			// from NotifyJoin, or an inbound session). Fire the
			// reconnect handler so TUN routes removed by the session
			// death handler are restored — no new NotifyJoin fires for
			// a peer that stayed in memberlist, so the join handler
			// never re-runs.
			n.mu.RLock()
			reconnectHdl := n.sessionReconnectHandler
			n.mu.RUnlock()
			if reconnectHdl != nil {
				reconnectHdl(peerIdentityHex)
			}
			n.removeReconnectTracker(peerIdentityHex)
			return
		}

		log.Printf("[mesh] reconnect attempt %d for peer %s at %s",
			attempt, shortPeerID(peerIdentityHex), endpoint)

		err := n.tryReconnect(ctx, peerIdentityHex, endpoint, isClientSession)
		if err == nil {
			log.Printf("[mesh] reconnect succeeded for peer %s after %d attempts",
				shortPeerID(peerIdentityHex), attempt)

			// Fire the session reconnect handler to re-add TUN routes that
			// were removed by the sessionDeathHandler. Since the peer stays
			// in memberlist (only the smux session died), no new NotifyJoin
			// fires, so the normal join handler in main.go never re-runs.
			n.mu.RLock()
			reconnectHdl := n.sessionReconnectHandler
			n.mu.RUnlock()
			if reconnectHdl != nil {
				reconnectHdl(peerIdentityHex)
			}

			// Re-arm the watcher for the NEW session: the old tracker is
			// removed here, and DialPeerByEndpoint inside tryReconnect
			// skipped startSessionWatcher (tracker still existed), so
			// without this the new session would have NO monitor and a
			// future drop would never auto-reconnect.
			n.removeReconnectTracker(peerIdentityHex)
			n.startSessionWatcher(peerIdentityHex, endpoint, isClientSession)
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
	// Prefer the peer's STABLE endpoint (config peers or routing table)
	// over the passed-in address. The passed-in endpoint may be the
	// remote source address of an inbound session — an ephemeral NAT
	// port that is invalid once the connection drops (reconnect loop
	// against a dead NAT mapping). resolvePeerEndpoint returns the
	// advertised endpoint which stays valid across reconnects.
	if stable := n.resolvePeerEndpoint(peerIdentityHex); stable != "" && stable != endpoint {
		log.Printf("[mesh] reconnect: using stable endpoint %s for peer %s (was %s)",
			stable, shortPeerID(peerIdentityHex), endpoint)
		endpoint = stable
	}
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

// HasPeerSession reports whether an active smux session exists to the
// given peer (client or server side, not closed). Used by NAT probing
// to judge real connectivity.
func (n *MeshNode) HasPeerSession(peerIdentityHex string) bool {
	return n.hasActiveSession(peerIdentityHex)
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
	// Prefer the gossip-advertised endpoint (stable, survives NAT
	// remapping). The routing table may hold the ephemeral source
	// address of an inbound session, which is invalid after the
	// connection drops.
	n.mu.RLock()
	resolver := n.peerEndpointResolver
	n.mu.RUnlock()
	if resolver != nil {
		if ep := resolver(peerIdentityHex); ep != "" {
			return ep
		}
	}
	n.peersMu.RLock()
	defer n.peersMu.RUnlock()
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
